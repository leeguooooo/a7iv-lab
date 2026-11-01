import struct
from types import SimpleNamespace
import unittest

from camera_native_library_read import NativeLibraryReader


class NativeLibraryReadTests(unittest.TestCase):
    def reader(self, failure=None, payload=b'\x7fELF-data'):
        calls = []
        def packet(device, function, frame, sink):
            block, command = struct.unpack_from('<HH', frame)
            self.assertEqual((function, block), (0x40, 0x1001))
            calls.append((command, frame[4:]))
            if failure == command:
                sink.write(struct.pack('<I', 1))
            else:
                sink.write(struct.pack('<I', 0) + (payload if command == 17 else b''))
            return 0, None
        return NativeLibraryReader(SimpleNamespace(driver=object()), bytes(16), send_packet=packet), calls

    def test_two_fixed_reads_use_select_and_get_without_upload(self):
        reader, calls = self.reader()
        for name in ('libosal_utm.so', 'libosal_uipc.so'):
            self.assertEqual(reader.read(name), b'\x7fELF-data')
        self.assertEqual(calls, [
            (15, b'\0/tmp/jiritsu/../../usr/lib/libosal_utm.so\0'), (17, b'\0\xff\0'),
            (15, b'\0/tmp/jiritsu/../../usr/lib/libosal_uipc.so\0'), (17, b'\0\xff\0'),
        ])

    def test_arbitrary_path_and_repeat_are_rejected_before_packet(self):
        reader, calls = self.reader()
        with self.assertRaises(ValueError): reader.read('/etc/passwd')
        self.assertEqual(calls, [])
        reader.read('libosal_utm.so')
        with self.assertRaises(RuntimeError): reader.read('libosal_utm.so')
        self.assertEqual(len(calls), 2)

    def test_select_or_get_failure_stops_all_later_reads(self):
        for command in (15, 17):
            reader, calls = self.reader(command)
            with self.assertRaises(RuntimeError): reader.read('libosal_utm.so')
            before = list(calls)
            with self.assertRaises(RuntimeError): reader.read('libosal_uipc.so')
            self.assertEqual(calls, before)

    def test_exact_limit_is_read_but_oversize_stops_channel(self):
        reader, _ = self.reader(payload=b'x' * 65536)
        self.assertEqual(len(reader.read('libosal_utm.so')), 65536)
        reader, calls = self.reader(payload=b'x' * 65537)
        with self.assertRaises(ValueError): reader.read('libosal_utm.so')
        before = list(calls)
        with self.assertRaises(RuntimeError): reader.read('libosal_uipc.so')
        self.assertEqual(calls, before)


if __name__ == '__main__': unittest.main()
