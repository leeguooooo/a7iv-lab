import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

import stock_p1_readback_plan as plan


class PlanTests(unittest.TestCase):
    def test_frozen_candidate_validates_with_all_source_and_model_bindings(self):
        m, module = plan.validate()
        self.assertEqual(m['target'], ['cnflasha1', 129, 25100288])
        self.assertEqual(len(module), 12752)

    def test_changed_module_receipt_or_symlink_rejected(self):
        for scenario in ('module', 'model_report', 'symlink'):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary) / 'candidate'
                shutil.copytree(plan.BASE, base)
                if scenario == 'module':
                    path = base / 'bootstrap/libJit.so'
                    raw = bytearray(path.read_bytes());raw[-1] ^= 1;path.write_bytes(raw)
                elif scenario == 'model_report':
                    path = base / 'bootstrap/emulation.json'
                    value = json.loads(path.read_text());value['tests'].pop()
                    path.write_text(json.dumps(value))
                else:
                    path = base / 'bootstrap/libJit.so'
                    path.unlink();path.symlink_to(plan.BASE / 'bootstrap/libJit.so')
                with patch.object(plan, 'BASE', base):
                    with self.assertRaises(ValueError):
                        plan.validate()


if __name__ == '__main__':
    unittest.main()
