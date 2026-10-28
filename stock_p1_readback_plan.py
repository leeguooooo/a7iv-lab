"""Validate the one frozen readback module entirely from local artifacts."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BASE = ROOT / 'output/stock-p1-readback-offline-01'
MANIFEST_SHA = 'd3b4a6dae8eae0573563d05acef85d34679b44a68489a3f699acf9bcaaffd78c'
MODULE_SHA = '51b7fd1006e93f944c6a85441e6578ee926d9fbcc2e93fcb8bdb88cf39fb5e7d'
NONCE = '509f422f2536081ff11ef260708b5ae7'
BOOT_REPORT_SHA = '72beafd22da92799c61196ec2bea00180aae9b7d9ba4c01fa31feed5d80b0606'
BOOT_CASES = ('success', 'wait_eintr', 'not_root', 'unlink_error', 'wrong_fs', 'low_tmpfs',
              'existing_job', 'existing_worker', 'write_error', 'short_write', 'fork_error',
              'wait_status_error', 'intermediate', 'grandchild_exec', 'exec_error', 'setsid_error')


def require(ok, message):
    if not ok:
        raise ValueError(message)


def checked_bytes(path, digest):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), 'Regular artifact required')
    raw = path.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == digest, 'Artifact/source digest changed')
    return raw


def validate():
    boot = BASE / 'bootstrap'
    m = json.loads(checked_bytes(boot / 'bootstrap.json', MANIFEST_SHA))
    require(m['schema'] == 'camera-stock-p1-readback-bootstrap-offline/1'
            and m['target'] == ['cnflasha1', 129, 25100288]
            and m['nonce'] == NONCE
            and m['module']['sha256'] == MODULE_SHA and m['module']['size'] == 12752
            and m['admission'] == 'OFFLINE_CANDIDATE_NO_DEVICE_EXECUTION', 'Fixed candidate changed')
    module = checked_bytes(boot / 'libJit.so', MODULE_SHA)
    compact = checked_bytes(boot / 'worker.elf', m['compact_worker_sha256'])
    require(module.count(compact) == 1, 'Embedded worker differs')
    checked_bytes(boot / 'job.h', m['job_header_sha256'])
    checked_bytes(ROOT / 'tools/prepare_stock_p1_readback_bootstrap_offline.py', m['builder_sha256'])
    checked_bytes(ROOT / 'ref/sony-a7m4-custom-firmware/no-fastboot-install/software/app/native/bootstrap.c',
                  m['bootstrap_source_sha256'])
    checked_bytes(ROOT / 'local/zig-aarch64-macos-0.15.2/zig', m['compiler_sha256'])
    for source, digest in m['shared_sources'].items():
        path = ROOT / source
        require(path.resolve().is_relative_to(ROOT), 'Source escaped workspace')
        checked_bytes(path, digest)
    for name, prefix in (('prod', 'production'), ('test', 'tiny')):
        job = BASE / name
        worker = json.loads(checked_bytes(job / 'job.json', m[prefix + '_job_manifest_sha256']))
        report = json.loads(checked_bytes(job / 'emulation.json', m[prefix + '_emulation_sha256']))
        checked_bytes(job / 'worker.debug.elf', worker['worker_sha256'])
        for source, digest in worker['sources'].items():
            path = ROOT / source
            require(path.resolve().is_relative_to(ROOT), 'Worker source escaped workspace')
            checked_bytes(path, digest)
        checked_bytes(ROOT / 'tools/emulate_stock_p1_readback_worker_offline.py', report['emulator_sha256'])
        require(report['all_passed'] is True and all(t['passed'] is True for t in report['tests']),
                'Worker model failed')
    report = json.loads(checked_bytes(boot / 'emulation.json', BOOT_REPORT_SHA))
    checked_bytes(ROOT / 'tools/emulate_stream_bootstrap.py', report['emulator_sha256'])
    require(report['all_passed'] is True and report['module_sha256'] == MODULE_SHA
            and report['compact_worker_sha256'] == m['compact_worker_sha256']
            and len(report['tests']) == len(BOOT_CASES)
            and {t['scenario'] for t in report['tests']} == set(BOOT_CASES)
            and all(t['passed'] is True for t in report['tests']), 'Bootstrap model incomplete')
    return m, module
