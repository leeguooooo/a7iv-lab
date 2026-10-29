"""Build a fixed-receipt current-RAM reader offline; no SDK or device entry."""
import argparse
import io
import json
import os
from pathlib import Path
import secrets
import struct
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from elftools.elf.elffile import ELFFile
from install_patch_read_profile import (ROOT, APP, COMPILER, COMPILER_SHA, SCHEMA, PROFILE,
    contract, input_evidence, derive, header, require, sha)


def build(output, *, pending_receipt, body_sha256, plan_sha256):
    sources, libraries = input_evidence()
    original, spec = derive(pending_receipt, body_sha256, plan_sha256)
    output = Path(output).absolute()
    require('..' not in output.parts and output.is_relative_to(ROOT / 'output') and not output.exists()
            and all(not p.is_symlink() for p in output.parents), 'Fresh nonsymlink workspace output required')
    output.mkdir(mode=0o700, parents=True)
    nonce = secrets.token_bytes(16)
    old_nonces = {spec['original_patch_nonce'], *(spec['original_asset_reference']['captures'][name]['nonce']
                                                for name in ('pre_app', 'pre_ufp'))}
    while not any(nonce) or nonce.hex() in old_nonces:
        nonce = secrets.token_bytes(16)
    (output / 'prior-pending.json').write_bytes(original)
    (output / 'target-spec.json').write_text(json.dumps(spec, indent=2) + '\n')
    (output / 'job.h').write_bytes(header(nonce, spec))
    flags = ['-target', 'aarch64-linux-gnu', '-mcpu=generic', '-Os', '-g', '-ffreestanding', '-fno-builtin',
        '-fno-stack-protector', '-fno-unwind-tables', '-fno-asynchronous-unwind-tables', '-nostdlib',
        '-ffunction-sections', '-fdata-sections', '-Wl,--gc-sections', '-Wl,--no-undefined',
        '-Wl,--build-id=none', '-Wl,-z,noexecstack', '-Wl,-z,max-page-size=4096', '-Wl,-z,common-page-size=4096',
        '-I', str(output), '-I', str(APP / 'native')]
    env = dict(os.environ, ZIG_GLOBAL_CACHE_DIR=str(output / 'zig-global-cache'),
               ZIG_LOCAL_CACHE_DIR=str(output / 'zig-local-cache'))
    commands = []
    def compile(source, destination, extra):
        command = [str(COMPILER), 'cc', *flags, *extra, str(source), '-o', str(output / destination)]
        commands.append(command)
        done = subprocess.run(command, capture_output=True, text=True, timeout=120, env=env)
        (output / (destination + '.compile.log')).write_text(done.stdout + done.stderr)
        require(done.returncode == 0, 'Compilation failed: ' + done.stderr[-3000:])
    compile(ROOT / 'native/install_patch_read.c', 'worker.debug.elf', ['-static', '-fno-pic', '-Wl,-e,_start'])
    debug = (output / 'worker.debug.elf').read_bytes()
    elf = ELFFile(io.BytesIO(debug))
    limit = max(s['p_offset'] + s['p_filesz'] for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD')
    compact = bytearray(debug[:limit])
    struct.pack_into('<Q', compact, 40, 0)
    struct.pack_into('<3H', compact, 58, 0, 0, 0)
    (output / 'worker.elf').write_bytes(compact)
    (output / 'worker_blob.h').write_text('static const unsigned char worker_blob[]={'+','.join(map(str, compact))+'};\n')
    symbols = {s.name: s['st_value'] for s in elf.get_section_by_name('.symtab').iter_symbols() if s.name}
    (output / 'symbols.json').write_text(json.dumps(symbols, indent=2) + '\n')
    compile(APP / 'native/bootstrap.c', 'libJit.so', ['-shared', '-fPIC', '-Wl,-Bsymbolic', '-s'])
    require(input_evidence() == (sources, libraries), 'Source inputs changed during build')
    require(derive(pending_receipt, body_sha256, plan_sha256) == (original, spec), 'Prior pending receipt changed')
    module = (output / 'libJit.so').read_bytes()
    require(len(module) <= 65520 and module.count(compact) == 1, 'Bootstrap single-worker/upload bound failed')
    names = ('prior-pending.json', 'target-spec.json', 'job.h', 'worker.debug.elf', 'worker.elf',
             'worker_blob.h', 'symbols.json', 'libJit.so', 'worker.debug.elf.compile.log', 'libJit.so.compile.log')
    m = dict(schema=SCHEMA, profile=PROFILE, admission='OFFLINE_NOT_BODY_BOUND',
        nonce=nonce.hex(), job_dir='/tmp_wbshd/m4ipr_' + nonce.hex(),
        original_pending=dict(path=str(Path(pending_receipt).absolute()), sha256=spec['pending_receipt_sha256'],
                              body_sha256=body_sha256, plan_sha256=plan_sha256),
        original_patch_nonce=spec['original_patch_nonce'], target_spec_sha256=contract.spec_sha256(spec),
        original_source_is_hardware=spec['original_source_is_hardware'], original_hardware_origin_proven=False,
        body_binding=None, target_package_sha256=None, live_controller_sealed=False,
        hardware_operations=0, hardware_acceptance=False, native_fault_model_executed=False,
        worker_executed=False, bootstrap_executed=False, automatic_retry=False,
        process_memory_writes=0, readonly_process_memory=True, original_mm_continuity_proven=False,
        restoration_proven=False, installation_authorized=False, firmware_readiness_proven=False,
        sources=sources, libraries=libraries, compile_commands=commands,
        compiler=dict(path=str(COMPILER.relative_to(ROOT)), sha256=COMPILER_SHA,
                      version='0.15.2', host='aarch64-macos', target='aarch64-linux-gnu'),
        artifacts={name:dict(bytes=(output/name).stat().st_size,sha256=sha(output/name)) for name in names},
        result=dict(magic=contract.MAGIC.decode(), version=1, start_magic=contract.START_MAGIC.decode(),
                    start_format='<8s16s16sQ', format=contract.FRAME.format, bytes=contract.FRAME.size,
                    fields=list(contract.FIELDS)),
        terminal_publication=dict(pending='result.pending',published='result',syscall='renameat2',flags=1),
        limitations=['Current bounded observation only; no continuity with the original closed mm',
            'A matching PID, current mappings and within-probe start ticks do not authenticate historical process identity',
            'No real /proc, cache coherence, kernel, renameat2, bootstrap or device execution validated',
            'No SDK executor, cancellation, restoration, READY or firmware authorization exists'])
    (output / 'manifest.json').write_text(json.dumps(m, indent=2) + '\n')
    return output


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--pending-receipt', type=Path, required=True)
    p.add_argument('--body-sha256', required=True)
    p.add_argument('--plan-sha256', required=True)
    a = p.parse_args()
    path = build(a.output, pending_receipt=a.pending_receipt, body_sha256=a.body_sha256, plan_sha256=a.plan_sha256)
    print(json.dumps(dict(output=str(path),manifest_sha256=sha(path/'manifest.json'),hardware_operations=0)))


if __name__ == '__main__':
    main()
