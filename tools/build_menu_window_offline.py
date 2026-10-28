"""Cross-compile exact reviewed stock M4 menu C offline; never execute emitted ARM."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import secrets
import struct
import subprocess

from elftools.elf.elffile import ELFFile
from menu_window_profile import (ROOT, APP, COMPILER, COMPILER_SHA, DEFS, MODULES,
    OBSERVATION_OFFSETS, OBSERVATION_SIZES, FIELDS, input_evidence, require, sha)


def array(name, values, ctype='unsigned char'):
    return 'static const ' + ctype + ' ' + name + '[]={' + ','.join(map(str, values)) + '};\n'


def build(output):
    sources, libraries = input_evidence()
    output = Path(output).absolute()
    require(output.is_relative_to(ROOT / 'output') and not output.exists(), 'Fresh output under workspace/output required')
    require(not any(p.is_symlink() for p in output.parents), 'Symlink output forbidden')
    output.mkdir(mode=0o700, parents=True)
    nonce = secrets.token_bytes(16)
    job_dir = '/tmp_wbshd/m4dual_' + nonce.hex()
    header = '#define JOB_DIR "' + job_dir + '"\n'
    header += ''.join(f'#define {key} {value}\n' for key, value in DEFS.items())
    header += array('job_nonce', nonce)
    for module, prefix in (('libupdaterufp.so', ''), ('appFw.so', 'app_')):
        p = MODULES[module]
        for key, suffix in (('anchor_hex', 'anchor'), ('original_hex', 'original4'), ('patch_hex', 'patch4')):
            header += array(prefix + suffix, bytes.fromhex(p[key]))
    header += array('observation_offsets', OBSERVATION_OFFSETS, 'unsigned long')
    header += array('observation_sizes', OBSERVATION_SIZES, 'unsigned long')
    (output / 'job.h').write_text(header)
    common = ['-target', 'aarch64-linux-gnu', '-mcpu=generic', '-Os', '-g',
        '-ffreestanding', '-fno-builtin', '-fno-stack-protector', '-fno-unwind-tables',
        '-fno-asynchronous-unwind-tables', '-nostdlib', '-ffunction-sections', '-fdata-sections',
        '-Wl,--gc-sections', '-Wl,--no-undefined', '-Wl,--build-id=none', '-Wl,-z,noexecstack',
        '-Wl,-z,max-page-size=4096', '-Wl,-z,common-page-size=4096',
        '-I', str(output), '-I', str(APP / 'native')]
    commands = []

    def compile(source, destination, extra):
        command = [str(COMPILER), 'cc', *common, *extra, str(source), '-o', str(output / destination)]
        commands.append(command)
        result = subprocess.run(command, capture_output=True, text=True, timeout=120)
        (output / (destination + '.compile.log')).write_text(result.stdout + result.stderr)
        require(result.returncode == 0, 'Cross-compilation failed: ' + result.stderr[-3000:])

    compile(APP / 'menu_stock/dual_worker.c', 'worker.debug.elf', ['-static', '-fno-pic', '-Wl,-e,_start'])
    debug = (output / 'worker.debug.elf').read_bytes()
    elf = ELFFile(io.BytesIO(debug))
    limit = max(s['p_offset'] + s['p_filesz'] for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD')
    compact = bytearray(debug[:limit])
    struct.pack_into('<Q', compact, 40, 0)
    struct.pack_into('<3H', compact, 58, 0, 0, 0)
    (output / 'worker.elf').write_bytes(compact)
    (output / 'worker_blob.h').write_text(array('worker_blob', compact))
    symbols = {s.name: s['st_value'] for s in elf.get_section_by_name('.symtab').iter_symbols() if s.name}
    (output / 'symbols.json').write_text(json.dumps(symbols, indent=2) + '\n')
    compile(APP / 'native/bootstrap.c', 'libJit.so', ['-shared', '-fPIC', '-Wl,-Bsymbolic', '-s'])
    # The independent verifier checks load bytes, relocations, ABI and embedded count.
    require((output / 'libJit.so').stat().st_size <= 65520, 'Bootstrap exceeds single-upload bound')
    require((output / 'libJit.so').read_bytes().count(bytes(compact)) == 1, 'Worker embedding count differs')
    require(input_evidence() == (sources, libraries), 'Sources/ELFs changed during build')
    source_paths = [Path(__file__), ROOT / 'tools/menu_window_profile.py', ROOT / 'tools/verify_menu_window_offline.py']
    sources.update({str(p.relative_to(ROOT)): sha(p) for p in source_paths})
    names = ('job.h', 'worker.debug.elf', 'worker.elf', 'worker_blob.h', 'symbols.json', 'libJit.so',
             'worker.debug.elf.compile.log', 'libJit.so.compile.log')
    artifacts = {name: {'bytes': (output / name).stat().st_size, 'sha256': sha(output / name)} for name in names}
    manifest = {'schema': 'camera-menu-stock-window-offline/1', 'profile': 'menu_stock_6.02_saved_ELFs',
        'admission': 'OFFLINE_NOT_BODY_BOUND', 'live_controller_sealed': False,
        'target_package_sha256': None, 'body_binding': None, 'hardware_operations': 0,
        'hardware_acceptance': False, 'native_fault_model_executed': False,
        'worker_executed': False, 'bootstrap_executed': False,
        'nonce': nonce.hex(), 'job_dir': job_dir, 'sources': sources, 'libraries': libraries,
        'compiler': {'path': str(COMPILER.relative_to(ROOT)), 'sha256': COMPILER_SHA,
                     'version': '0.15.2', 'host': 'aarch64-macos', 'target': 'aarch64-linux-gnu'},
        'compile_commands': commands, 'artifacts': artifacts,
        'result': {'magic': 'M4DWL002', 'start_magic': 'M4DSTART', 'format': '<8s16s51q',
                   'bytes': 432, 'fields': list(FIELDS)},
        'timeouts': {'start': 120, 'maps_wait': 300, 'hold': 600},
        'patch_order': ['app', 'lib'], 'restore_order': ['lib', 'app'], 'automatic_retry': False,
        'limitations': ['No live identity or process/mapping validation performed',
            'No watchdog guarantee after worker crash, kill or suspend',
            'No native fault-model or emitted ARM execution performed',
            'No device/session adapter or install authorization supplied']}
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'output/menu-stock-window-offline-01')
    args = parser.parse_args()
    out = build(args.output)
    print(json.dumps({'output': str(out), 'manifest_sha256': sha(out / 'manifest.json'),
                      'module_bytes': (out / 'libJit.so').stat().st_size,
                      'admission': 'OFFLINE_NOT_BODY_BOUND', 'hardware_operations': 0}))


if __name__ == '__main__':
    main()
