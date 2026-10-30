import errno
import hashlib
from pathlib import Path
import struct
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import inspect_m4_factory_registry as registry


class RecordTests(unittest.TestCase):
    def test_opaque_fields_and_uint64_pointer_round_trip(self):
        raw = b'prefix!!' + bytes.fromhex('8070605040302010') + bytes(range(80))
        record = registry.FactoryRecord.decode(raw)
        self.assertEqual(record.controller_factory, 0x1020304050607080)
        self.assertEqual(record.encode(), raw)
        self.assertEqual(record.presenter_factory, struct.unpack('<Q', b'prefix!!')[0])
        self.assertEqual(record.metadata_16, 0x03020100)
        self.assertEqual(record.metadata_20, 0x07060504)
        self.assertEqual(record.opaque_tail, bytes(range(8, 80)))

    def test_missing_extra_and_mutable_record_bytes_are_refused(self):
        for raw in (b'', bytes(95), bytes(97), bytearray(96)):
            with self.subTest(size=len(raw)), self.assertRaises(ValueError):
                registry.FactoryRecord.decode(raw)

    def test_pointer_must_be_exact_unsigned_integer(self):
        for pointer in (-1, 1 << 64, True, '1'):
            with self.subTest(pointer=pointer), self.assertRaises(ValueError):
                registry.FactoryRecord(0, pointer, 0, 0, bytes(72))

    def test_opaque_fields_must_keep_their_native_lengths(self):
        for tail in (bytes(71), bytes(73), bytearray(72)):
            with self.assertRaises(ValueError):
                registry.FactoryRecord(0, 0, 0, 0, tail)

    def test_metadata_width_and_presenter_pointer_are_checked(self):
        for value in (-1, 1 << 32, True):
            with self.assertRaises(ValueError):
                registry.FactoryRecord(0, 0, value, 0, bytes(72))
        with self.assertRaises(ValueError):
            registry.FactoryRecord(-1, 0, 0, 0, bytes(72))


class InputTests(unittest.TestCase):
    def test_null_factory_is_not_callable_when_headers_share_an_executable_segment(self):
        view = object.__new__(registry.ElfView)
        view.loads = [{'p_flags': 5, 'p_vaddr': 0, 'p_filesz': 4096}]
        self.assertFalse(view.executable(0))
        self.assertTrue(view.executable(256))
        self.assertFalse(view.executable(4096))

    def test_invalid_modes_are_refused_before_file_access(self):
        for modes in ((), (1, 1), (True,), (-1,), (0x4cf,), (0x4d0,)):
            with self.subTest(modes=modes), self.assertRaises(ValueError):
                registry.inspect('/nonexistent/firmware', modes)

    def test_wrong_size_is_refused(self):
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / 'short'
            path.write_bytes(b'not an AP')
            with self.assertRaisesRegex(ValueError, 'Exact-sized'):
                registry.inspect(path)

    def test_correct_size_with_wrong_hash_never_reaches_elf_parser(self):
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / 'sparse-model'
            with path.open('wb') as stream:
                stream.truncate(registry.AP_BYTES)
            with patch.object(registry, 'ElfView') as parser:
                with self.assertRaisesRegex(ValueError, 'Unsupported AP identity'):
                    registry.inspect(path)
            parser.assert_not_called()

    def test_symlink_input_is_not_followed(self):
        with TemporaryDirectory() as temporary:
            target = Path(temporary) / 'target'
            target.write_bytes(b'model')
            link = Path(temporary) / 'link'
            link.symlink_to(target)
            with self.assertRaises(OSError) as raised:
                registry.inspect(link)
            self.assertEqual(raised.exception.errno, errno.ELOOP)


@unittest.skipUnless((ROOT / 'local/firmware/a7m4-6.02/stock/appFw.so').exists(),
                     'Legally acquired local stock AP is not distributed with this repository')
class LocalStockTests(unittest.TestCase):
    def test_real_stock_anchor_and_raw_record_round_trip(self):
        path = ROOT / 'local/firmware/a7m4-6.02/stock/appFw.so'
        report = registry.inspect(path)
        self.assertEqual(report['input']['kind'], 'stock_6_02')
        row = report['records'][0]
        raw = bytes.fromhex(row['raw_hex'])
        self.assertEqual(len(raw), 96)
        self.assertEqual(struct.unpack_from('<Q', raw, 8)[0], 0x1dc769c)
        self.assertEqual(row['raw_sha256'], hashlib.sha256(raw).hexdigest())
        self.assertEqual(registry.FactoryRecord.decode(raw).encode(), raw)
        self.assertGreaterEqual(len(report['relocations']), 5)
        self.assertFalse(report['custom_menu_registered'])
        self.assertFalse(report['firmware_modified'])
        self.assertFalse(report['installation_authorized'])
        self.assertTrue(report['table']['native_upper_bound_proven'])
        self.assertFalse(report['table']['native_lower_bound_proven'])
        self.assertEqual(report['table']['sentinel'], 0x4cf)
        self.assertEqual(len(report['consumer_proof']), 4)

    def test_valid_inspection_cannot_overwrite_an_existing_report(self):
        with TemporaryDirectory() as temporary:
            output = Path(temporary) / 'existing.json'
            output.write_bytes(b'preserve this report')
            args = ['inspect_m4_factory_registry.py', '--ap',
                    str(ROOT / 'local/firmware/a7m4-6.02/stock/appFw.so'), '--output', str(output)]
            with patch.object(sys, 'argv', args), self.assertRaises(FileExistsError):
                registry.main()
            self.assertEqual(output.read_bytes(), b'preserve this report')


if __name__ == '__main__':
    unittest.main()
