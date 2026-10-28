"""Run only synthetic/offline P1 tests and save source-bound evidence; no USB."""
import hashlib
import json
import os
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from stock_p1_install import HOST_REPORT, TEST_MODULES, runtime_policy


def main():
    runtime_policy()
    result = unittest.TextTestRunner(verbosity=1).run(
        unittest.defaultTestLoader.loadTestsFromNames(TEST_MODULES))
    if not result.wasSuccessful():
        raise SystemExit(1)
    files = {p for pattern in ('stock_p1*.py', 'camera_stream*.py') for p in ROOT.glob(pattern)}
    files |= set((ROOT / 'tests').glob('test_stock_p1*.py'))
    files |= {Path(__file__).resolve(), ROOT / 'camera_inventory.py'}
    report = {'schema': 'camera-stock-p1-host-evidence/3', 'all_passed': True,
        'tests': result.testsRun, 'test_modules': list(TEST_MODULES), 'hardware_operations': 0,
        'synthetic_protocol_only': True, 'source_only_startup_policy_verified': True,
        'python_executable': sys.executable,
        'sources': {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(files)}}
    with HOST_REPORT.open('x') as f:
        os.fchmod(f.fileno(), 0o600)
        json.dump(report, f, indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
    print(json.dumps({'all_passed': True, 'tests': result.testsRun, 'hardware_operations': 0,
                      'source_files': len(files)}))


if __name__ == '__main__':
    main()
