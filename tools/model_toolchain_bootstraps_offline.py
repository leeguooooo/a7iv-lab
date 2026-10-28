"""Apply the pinned 16-case bootstrap CPU model to six exact offline artifacts.

Temporary bootstrap.json files are model adapters only. They carry no release,
body binding, deployment permission or hardware proof. Worker exec is observed
by the existing model and stopped; the embedded workers are never executed.
"""
import argparse
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import sys
from tempfile import TemporaryDirectory

from elftools.elf.elffile import ELFFile
import unicorn

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / 'ref/sony-a7m4-custom-firmware/no-fastboot-install/software/app'
MODEL = ROOT / 'tools/emulate_stream_bootstrap.py'
PINS = {
    'tools/emulate_stream_bootstrap.py': '3fd5f308db5286f0bf5b7d110f147b41cb5c62eaeee6c4002f1c64c910b6afc1',
    'camera_inventory.py': '7c42cae5e744c4018739f1f5e3f1af3ff53f8e5ff4b21b97486f40e496182d5b',
    'ref/sony-a7m4-custom-firmware/no-fastboot-install/software/app/native/bootstrap.c':
        '4e4dcb37eceab654a25b4a7f0d16626d1764f2a9708a48b3275da10c173b19a1',
    'ref/sony-a7m4-custom-firmware/no-fastboot-install/software/app/native/linux_a64.h':
        '827bfa50c9d5e2a1ee8eacc032303844cd3c0a8a9b4f5ea1bfa640a987eedd88',
}
CASES = ('success', 'wait_eintr', 'not_root', 'unlink_error', 'wrong_fs', 'low_tmpfs',
         'existing_job', 'existing_worker', 'write_error', 'short_write', 'fork_error',
         'wait_status_error', 'intermediate', 'grandchild_exec', 'exec_error', 'setsid_error')
CAPTURE_JOBS = ('pre_app', 'pre_ufp', 'post_app', 'post_cp', 'post_p1')


def require(value, message):
    if not value:
        raise ValueError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def read(path):
    path = Path(path).absolute()
    require(path.is_file() and not any(p.is_symlink() for p in (path, *path.parents)),
            'Regular non-symlink artifact required: ' + str(path))
    return path.read_bytes()


def module_info(raw):
    elf = ELFFile(io.BytesIO(raw))
    require(elf.elfclass == 64 and elf.little_endian and elf['e_machine'] == 'EM_AARCH64'
            and elf['e_type'] == 'ET_DYN', 'Bootstrap ELF identity differs')
    require(not any(s['p_type'] == 'PT_INTERP' for s in elf.iter_segments()), 'Unexpected interpreter')
    loads = [s for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD']
    require(loads and all(s['p_flags'] & 3 != 3 and s['p_filesz'] <= s['p_memsz'] and
            s['p_offset'] + s['p_filesz'] <= len(raw) for s in loads), 'Invalid bootstrap load mapping')
    init, relocations = None, []
    for section in elf.iter_sections():
        if section['sh_type'] == 'SHT_DYNAMIC':
            for tag in section.iter_tags():
                require(tag.entry.d_tag not in ('DT_NEEDED', 'DT_TEXTREL'), 'Bootstrap dependency/text relocation')
                if tag.entry.d_tag == 'DT_INIT':
                    require(init is None, 'Duplicate initializer')
                    init = tag.entry.d_val
        if section['sh_type'] == 'SHT_DYNSYM':
            require(not any(s.name and s['st_shndx'] == 'SHN_UNDEF' for s in section.iter_symbols()),
                    'Bootstrap undefined import')
        if section['sh_type'] in ('SHT_RELA', 'SHT_REL'):
            relocations.extend(r.entry.r_info_type for r in section.iter_relocations())
    require(init is not None and all(r == 1027 for r in relocations), 'Initializer/relative relocation changed')
    require(sum(1 for s in loads if s['p_flags'] & 1 and
                s['p_vaddr'] <= init < s['p_vaddr'] + s['p_filesz']) == 1, 'Initializer not mapped executable')
    require(len(raw) <= 65520, 'Bootstrap exceeds one-upload bound')
    return {'sha256': digest(raw), 'size': len(raw), 'init': init, 'entry': elf['e_entry'],
            'relative_relocations': len(relocations)}


def asset(name, job, metadata_path, menu=False):
    raw_meta = read(metadata_path)
    meta = json.loads(raw_meta)
    module_raw, worker_raw = read(job / 'libJit.so'), read(job / 'worker.elf')
    module = module_info(module_raw)
    nonce, directory = meta['nonce'], meta['job_dir']
    require(re.fullmatch('[0-9a-f]{32}', nonce) and any(bytes.fromhex(nonce)), 'Invalid actual manifest nonce')
    prefix = '/tmp_wbshd/m4dual_' if menu else '/tmp_wbshd/m4stream_'
    require(directory == prefix + nonce, 'Actual job directory/nonce mismatch')
    dependencies = {metadata_path: digest(raw_meta), job / 'libJit.so': digest(module_raw),
                    job / 'worker.elf': digest(worker_raw)}
    if menu:
        require(meta['schema'] == 'camera-menu-stock-window-offline/1' and
                meta['admission'] == 'OFFLINE_NOT_BODY_BOUND' and meta['body_binding'] is None and
                meta['target_package_sha256'] is None, 'Menu offline scope changed')
        require(meta['artifacts']['libJit.so'] == {'bytes': len(module_raw), 'sha256': digest(module_raw)}
                and meta['artifacts']['worker.elf'] == {'bytes': len(worker_raw), 'sha256': digest(worker_raw)},
                'Menu exact artifact binding changed')
        source = str((APP / 'native/bootstrap.c').relative_to(ROOT))
        require(meta['sources'][source] == PINS[source], 'Menu generic bootstrap source binding changed')
        header = read(job / 'job.h')
        require(digest(header) == meta['artifacts']['job.h']['sha256'], 'Menu nonce header differs')
        header_provenance = job / 'job.h'
    else:
        require(meta['schema'] == 'camera-firmware-file-bootstrap-offline/1' and meta['profile'] == name
                and meta['hardware_acceptance'] is False and meta['uploads'] == 0, 'Capture bootstrap scope differs')
        require(meta['module']['sha256'] == digest(module_raw) and meta['module']['size'] == len(module_raw)
                and meta['module']['init'] == module['init']
                and meta['compact_worker_sha256'] == digest(worker_raw), 'Capture artifact binding changed')
        require(meta['bootstrap_source_sha256'] == PINS[str((APP / 'native/bootstrap.c').relative_to(ROOT))]
                and meta['linux_helpers_sha256'] == PINS[str((APP / 'native/linux_a64.h').relative_to(ROOT))],
                'Capture generic bootstrap source binding changed')
        production = ROOT / meta['production_worker_job']
        require(production == job.parent / 'prod', 'Unexpected production job provenance')
        prod_path = production / 'job.json'
        prod_raw = read(prod_path)
        prod = json.loads(prod_raw)
        require(digest(prod_raw) == meta['production_job_manifest_sha256'] and
                prod['nonce'] == nonce and prod['job_dir'] == directory and prod['profile'] == name
                and prod['test_image'] is False, 'Production nonce/profile provenance mismatch')
        dependencies[prod_path] = digest(prod_raw)
        header = read(job / 'job.h')
        require(digest(header) == meta['job_header_sha256'], 'Capture nonce header differs')
        header_provenance = job / 'job.h'
    require(module_raw.count(worker_raw) == 1, 'Actual compact worker not embedded exactly once')
    expected_nonce = 'static const unsigned char job_nonce[]={' + ','.join(map(str, bytes.fromhex(nonce))) + '};'
    require(expected_nonce.encode() in header and ('#define JOB_DIR "' + directory + '"').encode() in header,
            'Actual nonce/header source differs')
    dependencies[header_provenance] = digest(header)
    # Only the existing model's required adapter keys; never a deployment manifest.
    fixture = {'schema': 'MODEL_ONLY_BOOTSTRAP_ADAPTER_NOT_A_RELEASE/1', 'model_fixture_only': True,
        'admission': 'MODEL_ONLY_NO_DEVICE_PERMISSION', 'body_binding': None,
        'nonce': nonce, 'job_dir': directory, 'module': module,
        'compact_worker_sha256': digest(worker_raw),
        'bootstrap_source_sha256': PINS[str((APP / 'native/bootstrap.c').relative_to(ROOT))],
        'metadata_source': str(metadata_path.relative_to(ROOT)), 'metadata_source_sha256': digest(raw_meta)}
    return {'asset': name, 'job': str(job.relative_to(ROOT)), 'module': module,
        'worker': {'bytes': len(worker_raw), 'sha256': digest(worker_raw)},
        'metadata_source': str(metadata_path.relative_to(ROOT)), 'metadata_source_sha256': digest(raw_meta),
        'nonce_source': str(metadata_path.relative_to(ROOT)) + '#/nonce',
        'job_dir_source': str(metadata_path.relative_to(ROOT)) + '#/job_dir',
        'nonce': nonce, 'job_dir': directory, 'model_adapter': fixture,
        'model_adapter_sha256': digest((json.dumps(fixture, indent=2) + '\n').encode())}, dependencies, module_raw, worker_raw


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, default=ROOT / 'output/offline-toolchain/bootstrap-models-01.json')
    args = parser.parse_args()
    for path, expected in PINS.items():
        require(digest(read(ROOT / path)) == expected, 'Pinned generic source/model changed: ' + path)
    # Check before importing the existing model; no model CLI or live run entry is invoked.
    sys.path.insert(0, str(ROOT))
    spec = importlib.util.spec_from_file_location('pinned_bootstrap_instruction_model', MODEL)
    model = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(model)
    require(model.emulate.__module__ == spec.name, 'Unexpected bootstrap model implementation')
    inputs = [('menu_stock_window', ROOT / 'output/menu-stock-window-offline-01',
               ROOT / 'output/menu-stock-window-offline-01/manifest.json', True)]
    for name in CAPTURE_JOBS:
        job = ROOT / 'output/firmware-file-capture-offline-03' / name / 'bootstrap'
        inputs.append((name, job, job / 'bootstrap.json', False))
    results, snapshots = [], {}
    for name, job, metadata_path, menu in inputs:
        row, bound, module_raw, worker_raw = asset(name, job, metadata_path, menu)
        snapshots.update(bound)
        # Historical reports remain read-only and are hashed again after all models.
        for parent in (job, job.parent) if not menu else (job,):
            for filename in ('verification.json', 'native-model-report.json', 'emulation.json'):
                path = parent / filename
                if path.is_file():
                    snapshots[path] = digest(read(path))
        with TemporaryDirectory(prefix='camera-bootstrap-MODEL-ONLY-',
                                dir=ROOT / 'output/offline-toolchain') as temporary:
            fixture_dir = Path(temporary)
            (fixture_dir / 'libJit.so').write_bytes(module_raw)
            (fixture_dir / 'worker.elf').write_bytes(worker_raw)
            fixture_raw = (json.dumps(row['model_adapter'], indent=2) + '\n').encode()
            (fixture_dir / 'bootstrap.json').write_bytes(fixture_raw)
            require(read(fixture_dir / 'libJit.so') == module_raw and
                    read(fixture_dir / 'worker.elf') == worker_raw, 'Temporary model bytes differ')
            tests = [model.emulate(fixture_dir, case) for case in CASES]
            require(len(tests) == 16 and all(t['passed'] for t in tests), 'Incomplete bootstrap matrix')
            require([t['scenario'] for t in tests if t['exec_observed_not_executed']] == ['grandchild_exec'],
                    'Unexpected worker exec observation boundary')
            row['tests'] = tests
            row['case_count'] = len(tests)
            row['all_passed'] = True
            row['actual_module_bytes_copied_exactly'] = True
            row['worker_executed'] = False
        results.append(row)
        print(name + ': 16/16 bootstrap CPU models PASS', flush=True)
    require(all(digest(read(path)) == value for path, value in snapshots.items()), 'Original asset/history changed')
    require(all(digest(read(ROOT / path)) == value for path, value in PINS.items()), 'Pinned model/source changed during run')
    require(len(results) == 6 and sum(row['case_count'] for row in results) == 96, 'Wrong asset/case scope')
    report = {'schema': 'camera-toolchain-bootstrap-actual-artifact-models/1', 'all_passed': True,
        'scope': 'Six actual libJit.so artifacts in pinned Unicorn bootstrap initializer model; no worker execution',
        'asset_count': 6, 'case_count': 96, 'cases_per_asset': list(CASES), 'assets': results,
        'pinned_source_and_model_hashes': PINS, 'runner_sha256': digest(read(Path(__file__))),
        'original_inputs_unchanged': True,
        'original_input_hashes': {str(path.relative_to(ROOT)): value for path, value in snapshots.items()},
        'unicorn_version': unicorn.__version__, 'bootstrap_CPU_emulated': True,
        'worker_executed': False, 'real_ARM_process_executed': False, 'hardware_operations': 0,
        'temporary_adapters_are_model_only': True, 'original_manifests_and_history_updated': False,
        'admission': 'OFFLINE_MODELS_ONLY_NO_HARDWARE_PERMISSION',
        'limitations': ['Fork parent/intermediate/grandchild branches are separately injected syscall return paths, not concurrent real scheduler execution',
            'Synthetic tmpfs/files/write errors/close/execve do not validate real kernel or storage behavior',
            'Execve is checked for exact worker bytes and argv then stops emulation; embedded worker CPU behavior is outside these96 cases',
            'No dlopen/service loader, USB, target device, physical process identity, cache consistency or installation acceptance was tested']}
    destination = args.report.absolute()
    require(destination.is_relative_to(ROOT / 'output') and not any(p.is_symlink() for p in (destination, *destination.parents)),
            'Report must be a non-symlink workspace output file')
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open('x') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    print(json.dumps({'assets': 6, 'cases': 96, 'all_passed': True, 'report': str(destination),
                      'worker_executed': False, 'hardware_operations': 0}))


if __name__ == '__main__':
    main()
