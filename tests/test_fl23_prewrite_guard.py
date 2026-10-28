"""Offline guard regressions: synthetic bytes and temporary local files only."""
from contextlib import ExitStack
import binascii
import hashlib
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

from tools import fl23_prewrite_guard as guard


class PrewriteGuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.config = self.root / 'config'
        self.config.mkdir()
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.paths, expected = {}, {}
        for label in ('AP', 'CP_v7', 'P1_personal_receiver_candidate'):
            raw = ('synthetic:' + label).encode()
            path = self.root / (label + '.bin')
            path.write_bytes(raw)
            self.paths[label] = path
            expected[label] = dict(sha256=hashlib.sha256(raw).hexdigest(), bytes=len(raw))
        self.stack.enter_context(mock.patch.object(guard, 'ACCEPTANCE', expected))
        header = bytearray(512)
        header[:8], header[12:16] = b'UDTRFIRM', b'0100'
        header[36:40] = bytes.fromhex('01030081')
        header[8:12] = struct.pack('<I', binascii.crc32(header[12:]) & 0xffffffff)
        self.kwargs = dict(header=bytes(header), package_model='01030081', camera_model='01030081',
                           package_region='0', camera_region='0', component_sums={'verified_component': ('0', 0)},
                           package_config_dir=self.config, power_ic_type=1,
                           required_partition_sizes={'nflasha1': 10}, device_capacities={'nflasha1': 20},
                           signature_verify_ok=True, emmc_backup_ok=True, nor_backup_ok=True,
                           upper_layer_resolved=True, artifacts={k: self.paths[k] for k in ('AP', 'CP_v7')})

    def call(self, **changes):
        return guard.gate(**dict(self.kwargs, **changes))

    def test_complete_synthetic_inputs_only_establish_structural_admission(self):
        result = self.call()
        self.assertTrue(result.offline_consistency)
        self.assertTrue(result.write_admission)
        self.assertIn('"source_and_runtime_authenticity_proven": false', result.to_json())

    def test_missing_artifacts_cannot_be_skipped_by_empty_or_partial_map(self):
        for artifacts in ({}, {'AP': self.paths['AP']}, {'CP_v7': self.paths['CP_v7']}):
            with self.subTest(labels=list(artifacts)):
                result = self.call(artifacts=artifacts)
                self.assertFalse(result.offline_consistency)
                self.assertFalse(result.write_admission)
                self.assertTrue(any(v.status == guard.FAIL and 'missing' in v.detail for v in result.verdicts))

    def test_personal_p1_required_only_in_p1_only_scope(self):
        inverse = self.root / 'inverse.bin'
        inverse.write_bytes(b'synthetic-inverse')
        result = self.call(write_scope='p1_only', p1_inverse_path=inverse)
        self.assertFalse(result.write_admission)
        result = self.call(write_scope='p1_only', p1_inverse_path=inverse, artifacts=self.paths)
        self.assertTrue(result.write_admission)
        self.assertTrue(self.call().write_admission)

    def test_unknown_label_is_fail_instead_of_skip(self):
        result = self.call(artifacts=dict(self.kwargs['artifacts'], P1=self.root / 'missing'))
        verdict = next(v for v in result.verdicts if v.name == 'hash:P1')
        self.assertEqual(verdict.status, guard.FAIL)
        self.assertFalse(result.write_admission)

    def test_missing_corrupted_or_symlink_artifact_rejected(self):
        original = self.paths['AP'].read_bytes()
        self.paths['AP'].write_bytes(b'corrupted')
        self.assertFalse(self.call().write_admission)
        self.paths['AP'].unlink()
        self.assertFalse(self.call().write_admission)
        real = self.root / 'real-app.bin'
        real.write_bytes(original)
        self.paths['AP'].symlink_to(real)
        self.assertFalse(self.call().write_admission)

    def test_missing_file_or_symlink_config_and_symlink_parent_rejected(self):
        file_path = self.root / 'config-file'
        file_path.write_bytes(b'not-directory')
        link = self.root / 'config-link'
        link.symlink_to(self.config, target_is_directory=True)
        parent_link = self.root / 'parent-link'
        parent_link.symlink_to(self.root, target_is_directory=True)
        for path in (None, self.root / 'missing', file_path, link, parent_link / 'config'):
            with self.subTest(path=path):
                result = self.call(package_config_dir=path)
                self.assertFalse(result.offline_consistency)
                self.assertFalse(result.write_admission)

    def test_broken_sub_conf_symlink_is_still_forbidden(self):
        (self.config / 'sub.conf').symlink_to(self.root / 'missing-target')
        self.assertFalse(self.call().write_admission)

    def test_signature_and_upper_layer_require_exact_true(self):
        for value in (None, False, 1, 'false', 'true', [], {}):
            with self.subTest(value=value):
                self.assertFalse(self.call(signature_verify_ok=value).write_admission)
                self.assertFalse(self.call(upper_layer_resolved=value).write_admission)

    def test_model_and_region_missing_cannot_compare_equal(self):
        self.assertEqual(guard.guard_region(None, None).status, guard.FAIL)
        self.assertEqual(guard.guard_model(None, None).status, guard.FAIL)
        self.assertFalse(self.call(package_region=None, camera_region=None).write_admission)
        for invalid in (False, True, -1, '-1', ''):
            with self.subTest(invalid=invalid):
                self.assertEqual(guard.guard_region(invalid, invalid).status, guard.FAIL)
        self.assertEqual(guard.guard_region(0, 0).status, guard.PASS)
        self.assertEqual(guard.guard_region('0', '0').status, guard.PASS)

    def test_runtime_integer_fields_refuse_bool_zero_negative_float_or_string(self):
        for invalid in (False, True, 0, -1, 1.0, '1'):
            with self.subTest(invalid=invalid):
                self.assertFalse(self.call(power_ic_type=invalid).write_admission)
                self.assertFalse(self.call(required_partition_sizes={'nflasha1': invalid}).write_admission)
                self.assertFalse(self.call(device_capacities={'nflasha1': invalid}).write_admission)

    def test_unknown_runtime_remains_pending_despite_upper_layer_true(self):
        result = self.call(camera_model=None, camera_region=None, power_ic_type=None, device_capacities=None)
        self.assertCountEqual(result.runtime_pending, ['model', 'region', 'lsi_main', 'nand_capacity'])
        self.assertFalse(result.write_admission)
        result = self.call(required_partition_sizes=None)
        self.assertIn('nand_capacity', result.runtime_pending)
        self.assertFalse(result.write_admission)

    def test_bad_partition_requirements_and_unknown_scope_refused(self):
        for requirements in ([], {'': 10}, {True: 10}, {'nflasha1': -5}):
            self.assertFalse(self.call(required_partition_sizes=requirements).write_admission)
        self.assertFalse(self.call(write_scope='unknown').write_admission)
        self.assertFalse(self.call(required_partition_sizes={'nflasha1': 21}).write_admission)

    def test_recovery_flags_cannot_be_truthy_strings_or_numeric_aliases(self):
        for value in ('false', 1):
            self.assertFalse(self.call(emmc_backup_ok=value).write_admission)
            self.assertFalse(self.call(nor_backup_ok=value).write_admission)
        self.assertFalse(self.call(emmc_backup_ok=False, user_informed_exception='true').write_admission)

    def test_malformed_crc_pairs_are_structured_failures(self):
        for sums in (None, [], {'x': ('0', False)}, {'x': ('0', -1)},
                     {'x': ('0', 0x100000000)}, {'x': ('not-hex', 0)}, {'x': (0, 0)},
                     {'x': '00'}, {'': ('0', 0)}):
            with self.subTest(sums=sums):
                self.assertEqual(guard.guard_component_crcs(sums).status, guard.FAIL)
        self.assertEqual(guard.guard_component_crcs({'x': ('0000FFFF', 65535)}).status, guard.PASS)

    def test_original_combined_false_admission_regression(self):
        result = self.call(artifacts={}, package_config_dir=self.root / 'missing',
                           signature_verify_ok='false', emmc_backup_ok='false', nor_backup_ok='false',
                           upper_layer_resolved='false', power_ic_type=True,
                           required_partition_sizes={'nflasha1': -5}, device_capacities={'nflasha1': 0})
        self.assertFalse(result.offline_consistency)
        self.assertFalse(result.recovery_policy_ok)
        self.assertFalse(result.write_admission)


if __name__ == '__main__':
    unittest.main()
