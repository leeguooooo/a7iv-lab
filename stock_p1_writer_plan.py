"""Validate the fixed saved-P1 transition locally; importing this touches no USB."""
import hashlib
import json
from pathlib import Path
import struct

from stock_p1_readback_plan import checked_bytes, require, validate as validate_readback

ROOT = Path(__file__).resolve().parent
JOB = ROOT / 'output/stock-p1-writer-offline-01/prod'
JOB_SHA = '5f9767c374265e9baff3b9a5dfd8fbb85f9e843903f52608032f747c95d944b8'
MODULE_SHA = '80cafaad2c7cb348abd982cd2a3975291c63d58042753396332a63b4c97477d2'
SOURCE_SHA = 'd415c4766c62b5b63bf106306e67b6a0512c4f97db834378e47ef79c40cf580b'
TARGET_SHA = 'e3ac140c49bd81b74799da9051b47a12ed201931380df87f7c35bc122345275e'


def validate():
    m = json.loads(checked_bytes(JOB / 'job.json', JOB_SHA))
    require(m['schema'] == 'camera-stock-p1-writer-production/1' and m['test_only'] is False
            and m['production_execution_enabled'] is False and m['direction'] == 'apply'
            and m['bytes'] == 25100288 and m['source_sha256'] == SOURCE_SHA
            and m['target_sha256'] == TARGET_SHA and len(m['windows']) == 550
            and m['module']['sha256'] == MODULE_SHA, 'Fixed P1 writer candidate changed')
    require(m['target'] == {'path': '/dev/cnflasha1', 'rdev': '252:129', 'bytes': 25100288,
                            'sysfs_sectors': 49024, 'exclusive_required': True}, 'Wrong target')
    for name, digest in m['sources'].items():
        path = ROOT / name
        require(path.resolve().is_relative_to(ROOT), 'Source escaped workspace')
        checked_bytes(path, digest)
    module = checked_bytes(JOB / 'libJit.so', MODULE_SHA)
    require(len(module) == 13912 and module.count(checked_bytes(JOB / 'worker.elf', m['compact_worker_sha256'])) == 1,
            'Writer/embedded worker differs')
    checked_bytes(JOB / 'worker.debug.elf', m['debug_sha256'])
    checked_bytes(ROOT / 'local/zig-aarch64-macos-0.15.2/zig', m['compiler_sha256'])
    before = checked_bytes(ROOT / m['source_image'], SOURCE_SHA)
    after = checked_bytes(ROOT / m['target_image'], TARGET_SHA)
    recovery = checked_bytes(ROOT / 'local/recovery/backup-01/cnflasha1.bin', SOURCE_SHA)
    require(before == recovery and len(before) == len(after) == 25100288, 'Recovery/source differs')
    expected, table, cursor, total = bytearray(before), bytearray(), 0, 0
    for index, row in enumerate(m['windows']):
        off, n = row['offset'], row['length']
        require(row['name'] == f'w{index:04d}' and cursor <= off and 0 < n <= 16384
                and off + n <= len(before), 'Window bounds/order changed')
        a, b = before[off:off + n], after[off:off + n]
        require(hashlib.sha256(a).hexdigest() == row['before_sha256']
                and hashlib.sha256(b).hexdigest() == row['after_sha256']
                and checked_bytes(JOB / 'assets' / row['name'], row['packet_sha256']) == a + b,
                'Staged window differs from images')
        table += struct.pack('<QQ32s32s', off, n, hashlib.sha256(a).digest(), hashlib.sha256(b).digest())
        expected[off:off + n] = b
        cursor, total = off + n, total + n
    require(bytes(expected) == after and 2 * total == m['stage_bytes'] == 17989640
            and checked_bytes(JOB / 'assets/table', m['table_sha256']) == table,
            'Full transition/staging differs')
    for name, digest, count in (
        ('prod', '98d66f72602732d96f1152433fa4c6d94cba73b5f8b990c4285a0f19976c719d', 16),
        ('test', '5a6264653c08495f62ce9df7255738dfcbce2d00f5df9306090fa099ce788c76', 44),
    ):
        report = json.loads(checked_bytes(JOB.parent / name / 'emulation.json', digest))
        require(report['all_passed'] is True and len(report['tests']) == count
                and all(t['passed'] is True for t in report['tests']), 'Native model failed')
        checked_bytes(ROOT / 'tools/emulate_stock_p1_writer_offline.py', report['emulator_sha256'])
        if name == 'prod':
            require(report['module_sha256'] == MODULE_SHA
                    and all(t['pwrite_calls'] == t['source_bytes_read'] == 0 for t in report['tests']),
                    'Production refusal evidence scope differs')
    validate_readback()
    return m, module
