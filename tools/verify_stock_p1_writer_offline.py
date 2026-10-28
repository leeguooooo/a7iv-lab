"""Saved-artifact audit plus selected synthetic syscall runs. No camera APIs."""
import hashlib
import json
import os
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.build_stock_p1_writer_offline import validate_job
from tools.emulate_stock_p1_writer_offline import emulate

OUT = ROOT / 'output/stock-p1-writer-offline-01'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def require(ok, message):
    if not ok:
        raise ValueError(message)


def main():
    audit = {}
    for name in ('test', 'prod'):
        job = OUT / name
        m = validate_job(job, allow_test=(name == 'test'))
        before = (ROOT / m['source_image']).read_bytes()
        after = (ROOT / m['target_image']).read_bytes()
        expected = bytearray(before)
        table = bytearray()
        cursor = total = 0
        for index, row in enumerate(m['windows']):
            start, n = row['offset'], row['length']
            require(row['name'] == f'w{index:04d}' and cursor <= start and 0 < n <= 16384
                    and start + n <= len(before), 'Invalid bounded ordered window')
            a, b = before[start:start + n], after[start:start + n]
            require(sha(a) == row['before_sha256'] and sha(b) == row['after_sha256'],
                    'Window not bound to complete images')
            require((job / 'assets' / row['name']).read_bytes() == a + b,
                    'Staged packet differs from before/after bytes')
            table += struct.pack('<QQ32s32s', start, n, hashlib.sha256(a).digest(), hashlib.sha256(b).digest())
            expected[start:start + n] = b
            cursor, total = start + n, total + n
        require(bytes(expected) == after, 'Changes outside staged windows')
        require((job / 'assets/table').read_bytes() == table and sha(table) == m['table_sha256'],
                'Native row table differs')
        require(2 * total == m['stage_bytes'], 'Staged byte count differs')
        if name == 'prod':
            reference = ROOT / 'ref/sony-a7m4-custom-firmware/no-fastboot-install/software/app/writer/writer.c'
            require((job / 'source/writer/writer.c').read_bytes() == reference.read_bytes(),
                    'Production transaction source changed')
        report = json.loads((job / 'emulation.json').read_text())
        require(report['all_passed'] and all(t['passed'] for t in report['tests']), 'Stored model failed')
        require(report['module_sha256'] == sha((job / 'libJit.so').read_bytes()), 'Model module differs')
        if name == 'prod':
            require(all(t['pwrite_calls'] == t['source_bytes_read'] == 0 for t in report['tests']),
                    'Production refusal scope differs')
        audit[name] = dict(rows=len(m['windows']), forward_bytes=total, module_sha256=m['module']['sha256'],
                           full_image_reconstructed_from_windows=True, stored_model_cases=len(report['tests']))
    cases = ('success', 'short_writes', 'write_eintr', 'write_error_rollback_ok',
             'rollback_fail', 'result_publication_failure')
    rerun = [emulate(OUT / 'test', scenario) for scenario in cases]
    result = dict(all_passed=True, artifacts=audit, independently_rerun_synthetic_cases=rerun,
                  production_full_write_path_emulated=False, hardware_operations=0,
                  writer_executor_present=False, installation_approved=False,
                  physical_restore_tested=False, unknown_after_COMMIT_reconciliation_proven=False,
                  verifier_sha256=sha(Path(__file__).read_bytes()))
    with (OUT / 'independent-root-audit.json').open('x') as f:
        os.fchmod(f.fileno(), 0o600)
        json.dump(result, f, indent=2)
        f.write('\n')
        f.flush()
        os.fsync(f.fileno())
    print(json.dumps(dict(all_passed=True, artifacts=audit, rerun_cases=len(rerun), hardware_operations=0)))


if __name__ == '__main__':
    main()
