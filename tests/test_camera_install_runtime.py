import hashlib
import struct
import unittest
from unittest.mock import patch

import camera_install_runtime as runtime
from camera_backup_records import record_map
from test_camera_postinstall_verify import bk4, fat_image


def pdt(chip0=b'\x01', chip1=b'\x01'):
    def segment(value):
        return bk4({} if value is None else {runtime.POWER_IC_KEY: value})[:-256]
    return segment(chip0) + segment(chip1)


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.pdt = pdt()
        self.p1 = fat_image(b'initrd', b'kernel', struct.pack('<I', 0x01030081), bytes(4))
        self.partitions = b'major minor  #blocks  name\n\n252 129 2048 cnflasha1\n252 1 2048 pnflasha1\n'
        self.aliases = {'nflasha1': '/dev/cnflasha1'}
        self.required = {'nflasha1': 2048 * 1024}

    def decode(self, **changes):
        values = dict(pdt_raw=self.pdt, p1_raw=self.p1, partitions_raw=self.partitions,
                      alias_targets=self.aliases, required_partition_sizes=self.required,
                      normal_model_name='ILCE-7M4')
        values.update(changes)
        with patch.object(runtime, 'PDT_BYTES', len(values['pdt_raw'])), patch.object(runtime, 'P1_BYTES', len(values['p1_raw'])):
            return runtime.decode_runtime(**values)

    def test_real_small_FAT_and_BK4_parsers_decode_values_without_any_admission(self):
        self.assertEqual(record_map(self.pdt)[(1, runtime.POWER_IC_KEY)][1], b'\1')
        result = self.decode()
        self.assertEqual(result['values'], dict(model_code=0x01030081, model_code_hex='01030081', region=0,
                                                power_ic_type=1, power_ic_by_chip=[1, 1]))
        self.assertEqual(result['capacities']['nflasha1'], 2048 * 1024)
        self.assertEqual(result['partition_unit_bytes'], 1024)
        self.assertTrue(all(row['status'] == 'PASS' for row in result['decoded_value_checks']))
        self.assertEqual(result['raw_inputs']['pdt']['sha256'], hashlib.sha256(self.pdt).hexdigest())
        self.assertEqual(result['raw_inputs']['p1']['sha256'], hashlib.sha256(self.p1).hexdigest())
        for key in ('source_is_hardware', 'hardware_origin_proven', 'runtime_freshness_proven',
                    'alias_device_stat_proven', 'package_requirements_proven', 'READY',
                    'ready_for_confirmation', 'write_admission', 'installation_authorized', 'device_execution_proven'):
            self.assertIs(result[key], False)

    def test_production_default_lengths_are_fixed_not_small_fixture_sizes(self):
        self.assertEqual((runtime.PDT_BYTES, runtime.P1_BYTES), (2369436, 25100288))
        with self.assertRaisesRegex(ValueError, 'PDT length'):
            runtime.decode_runtime(pdt_raw=self.pdt, p1_raw=self.p1, partitions_raw=self.partitions,
                alias_targets=self.aliases, required_partition_sizes=self.required, normal_model_name='ILCE-7M4')

    def test_wrong_model_region_and_normal_model_name_fail_value_checks(self):
        for dat2, dat3 in ((struct.pack('<I', 0x01030082), bytes(4)),
                           (struct.pack('<I', 0x01030081), struct.pack('<I', 1))):
            with self.subTest(dat2=dat2, dat3=dat3), self.assertRaises(ValueError):
                self.decode(p1_raw=fat_image(b'i', b'k', dat2, dat3))
        for model in ('ILCE-7M4 ', 'ILCE-7M3', None, True):
            with self.subTest(model=model), self.assertRaises(ValueError):self.decode(normal_model_name=model)

    def test_DAT_fields_must_be_exact_four_bytes(self):
        for dat2, dat3 in ((b'abc', bytes(4)), (struct.pack('<I', 0x01030081), bytes(5))):
            with self.subTest(dat2=dat2, dat3=dat3), self.assertRaisesRegex(ValueError, 'exactly four bytes'):
                self.decode(p1_raw=fat_image(b'i', b'k', dat2, dat3))

    def test_power_record_both_chips_width_and_equality_are_required(self):
        for first, second in ((b'\1', b'\6'), (None, b'\1'), (b'\1', None), (b'\1\0', b'\1'), (b'\1', b'')):
            with self.subTest(first=first, second=second), self.assertRaises(ValueError):self.decode(pdt_raw=pdt(first, second))
        for value in (0, 2, 3, 255):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'numeric checks failed'):
                self.decode(pdt_raw=pdt(bytes([value]), bytes([value])))
        for value in (1, 4, 5, 6, 7):
            with self.subTest(value=value):
                self.assertEqual(self.decode(pdt_raw=pdt(bytes([value]), bytes([value])))['values']['power_ic_type'], value)

    def test_partition_units_and_pn_alias_are_explicit(self):
        value = self.decode(alias_targets={'nflasha1': '/dev/pnflasha1'}, required_partition_sizes={'nflasha1': 2048 * 1024 - 1})
        self.assertEqual(value['capacities']['nflasha1'], 2097152)
        self.assertEqual(value['alias_targets']['nflasha1'], '/dev/pnflasha1')
        with self.assertRaisesRegex(ValueError, 'numeric checks failed'):
            self.decode(required_partition_sizes={'nflasha1': 2048 * 1024 + 1})
        other_major = self.partitions.replace(b'252 ', b'253 ')
        self.assertEqual(self.decode(partitions_raw=other_major)['capacities']['nflasha1'], 2097152)

    def test_missing_disagreeing_duplicate_or_malformed_partitions_are_rejected(self):
        rows = self.partitions.splitlines()
        malformed = [b'', b'bad header\n', self.partitions + rows[-1] + b'\n',
            b'\n'.join(rows[:-1]) + b'\n', self.partitions.replace(b'1 2048 pn', b'1 2049 pn'),
            self.partitions.replace(b'129 2048', b'129 0'), self.partitions.replace(b'129 2048', b'-1 2048'),
            self.partitions.replace(b'129 2048', b'129 2.5'), self.partitions + b'\xff',
            self.partitions.replace(b'252 1 2048', b'252 129 2048'),
            self.partitions.replace(b'129 2048', b'129 999999999999999999999999999999999999')]
        for raw in malformed:
            with self.subTest(raw=raw), self.assertRaises(ValueError):self.decode(partitions_raw=raw)

    def test_alias_mapping_must_have_exact_keys_and_same_partition_absolute_targets(self):
        for aliases in ({}, {'nflasha1': '/dev/cnflasha3'}, {'nflasha1': 'cnflasha1'},
                        {'nflasha1': '/dev/../dev/cnflasha1'}, {'nflasha1': '/dev/nflasha1'},
                        {'/dev/nflasha1': '/dev/cnflasha1'},
                        {'nflasha1': '/dev/cnflasha1', 'nflasha3': '/dev/cnflasha3'}):
            with self.subTest(aliases=aliases), self.assertRaises(ValueError):self.decode(alias_targets=aliases)

    def test_pinned_expectations_and_requirement_types_cannot_be_overridden(self):
        for options in (dict(expected_model=True), dict(expected_region=False), dict(expected_region=1),
                        dict(expected_model=0x01030082), dict(required_partition_sizes={}),
                        dict(required_partition_sizes={'nflasha01': 1024}),
                        dict(required_partition_sizes={'nflasha1': True}),
                        dict(required_partition_sizes={'nflasha1': -1})):
            with self.subTest(options=options), self.assertRaises(ValueError):self.decode(**options)

    def test_mutating_input_maps_after_decode_does_not_change_report(self):
        report = self.decode()
        self.aliases['nflasha1'] = '/dev/cnflasha99';self.required['nflasha1'] = 1
        self.assertEqual(report['alias_targets']['nflasha1'], '/dev/cnflasha1')
        self.assertEqual(report['required_partition_sizes']['nflasha1'], 2097152)


if __name__ == '__main__':unittest.main()
