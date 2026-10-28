"""Real PMCA framing code with scripted reads. Never enumerates USB devices."""
from collections import deque
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "Sony-PMCA-RE"))
from pmca.usb.sony import SonySenserDevice
from camera_stream_transport_bounds import BoundedSink, ReadGuard
from camera_stream_senser import send_senser_packet
from camera_stream_channel import _DriverProxy


class ScriptedDriver:
    def __init__(self, payload, sequence=1, product=0x0337, padding=None):
        self.parts = deque()
        self.writes = []
        self.failed = False
        self.product = product
        minimum = 0 if product == 0x0336 else 512
        remaining = payload
        while remaining:
            block = remaining[:0x100000]
            header = SonySenserDevice.SenserPacketHeader.pack(
                size=len(remaining), pFunc=0x40, sequence=sequence, version=0,
                miconType=0, offsetType=0, response=0)
            prefix = max(minimum - 12, 0)
            self.parts.append((max(minimum, 12), header + block[:prefix]))
            at, count = prefix, 32768 - minimum
            while at < len(block):
                n = min(len(block) - at, count)
                self.parts.append((n, block[at:at + n]))
                at += n
                if not (n & 511):
                    self.parts.append((512, b"\0" * 512 if padding is None else padding))
                count = 32768
            remaining = remaining[len(block):]

    def getId(self):
        return 0x054c, self.product

    def write(self, data):
        self.writes.append(data)

    def read(self, count):
        expected, data = self.parts.popleft()
        if count != expected:
            raise AssertionError((count, expected))
        return data


class GuardedDriver:
    def __init__(self, raw):
        self.raw = raw
        self.guard = ReadGuard(raw, 100, clock=lambda: 1)

    def getId(self):
        return self.raw.getId()

    def write(self, data):
        return self.raw.write(data)

    def read(self, count):
        return self.guard.read(count)


class FramingTests(unittest.TestCase):
    def camera(self, payload):
        raw = ScriptedDriver(payload)
        camera = SonySenserDevice.__new__(SonySenserDevice)
        camera.driver = GuardedDriver(raw)
        camera._sequence = 1
        return camera, raw

    def test_multiframe_exact_bound(self):
        payload = b"\0" * 4 + b"DATA" * (2 * 1024 * 1024)
        camera, driver = self.camera(payload)
        sink = BoundedSink(len(payload))
        response, returned = camera.sendSenserPacket(0x40, b"read-request", sink)
        self.assertEqual(response, 0)
        self.assertIsNone(returned)
        self.assertEqual(sink.getvalue(), payload)
        self.assertEqual(len(driver.parts), 0)
        self.assertEqual(len(driver.writes), 1)

    def test_over_bound_stops_inside_real_parser(self):
        payload = b"X" * (1024 * 1024 + 1000)
        camera, _ = self.camera(payload)
        sink = BoundedSink(1024 * 1024)
        with self.assertRaises(ValueError):
            camera.sendSenserPacket(0x40, b"read-request", sink)
        self.assertLessEqual(len(sink.getvalue()), sink.maximum)
        self.assertTrue(sink.failed)

    def test_empty_header_stops(self):
        camera, driver = self.camera(b"X" * 1000)
        driver.parts[0] = (512, b"")
        with self.assertRaises(ValueError):
            camera.sendSenserPacket(0x40, b"read-request", BoundedSink(1000))
        self.assertTrue(camera.driver.guard.failed)

    def test_file_channel_with_actual_parser(self):
        from camera_stream_channel import StreamFileChannel
        payload = b"DATA" * (2 * 1024 * 1024)
        # One known-successful SELECT, then one bounded 8MiB file response.
        raw = ScriptedDriver(b"\0" * 4, sequence=1)
        raw.parts.extend(ScriptedDriver(b"\0" * 4 + payload, sequence=2).parts)
        camera = SonySenserDevice.__new__(SonySenserDevice)
        camera.driver, camera._sequence = raw, 1
        channel = StreamFileChannel(camera, bytes(range(16)))
        self.assertEqual(channel.read("chunk.bin"), payload)
        self.assertIs(camera.driver, raw)
        self.assertEqual(len(raw.writes), 2)
        self.assertEqual(len(raw.parts), 0)

    def test_bounded_framing_matches_SDK_with_real_zero_length_separators(self):
        payload = b"\0" * 4 + b"DATA" * 17500
        for product in (0x0336, 0x0337):
            with self.subTest(product=product):
                reference_raw = ScriptedDriver(payload, product=product, padding=b"")
                reference = SonySenserDevice.__new__(SonySenserDevice)
                reference.driver, reference._sequence = reference_raw, 1
                a = BoundedSink(len(payload))
                reference.sendSenserPacket(0x40, b"request", a)
                raw = ScriptedDriver(payload, product=product, padding=b"")
                device = SonySenserDevice.__new__(SonySenserDevice)
                device.driver, device._sequence = _DriverProxy(raw, 10, lambda: 1), 1
                b = BoundedSink(len(payload))
                send_senser_packet(device, 0x40, b"request", b)
                self.assertEqual(a.getvalue(), b.getvalue())
                self.assertEqual(b.getvalue(), payload)
                self.assertEqual(reference_raw.writes, raw.writes)
                self.assertFalse(device.driver.reader.failed)
                self.assertEqual(len(raw.parts), 0)

    def test_empty_DATA_is_still_terminal_with_ZLP_support(self):
        raw = ScriptedDriver(b"X" * 70000, product=0x0336, padding=b"")
        raw.parts[1] = (32768, b"")  # DATA, not the following separator.
        device = SonySenserDevice.__new__(SonySenserDevice)
        device.driver, device._sequence = _DriverProxy(raw, 10, lambda: 1), 1
        with self.assertRaises(ValueError):
            send_senser_packet(device, 0x40, b"request", BoundedSink(70000))
        self.assertTrue(device.driver.reader.failed)
        self.assertEqual(device._sequence, 1)

    def test_8MiB_file_channel_accepts_only_separator_ZLPs(self):
        from camera_stream_channel import StreamFileChannel
        payload = b"DATA" * (2 * 1024 * 1024)
        raw = ScriptedDriver(b"\0" * 4, sequence=1, product=0x0336, padding=b"")
        raw.parts.extend(ScriptedDriver(b"\0" * 4 + payload, sequence=2,
                                       product=0x0336, padding=b"").parts)
        device = SonySenserDevice.__new__(SonySenserDevice)
        device.driver, device._sequence = raw, 1
        channel = StreamFileChannel(device, bytes(range(16)))
        self.assertEqual(channel.read("chunk.bin"), payload)
        self.assertTrue(channel.healthy)
        self.assertEqual(len(raw.parts), 0)

    def test_declared_oversize_rejected_before_payload_download(self):
        raw = ScriptedDriver(b"X" * 70000, product=0x0336, padding=b"")
        device = SonySenserDevice.__new__(SonySenserDevice)
        device.driver, device._sequence = _DriverProxy(raw, 10, lambda: 1), 1
        total = len(raw.parts)
        with self.assertRaises(ValueError):
            send_senser_packet(device, 0x40, b"request", BoundedSink(1000))
        self.assertEqual(len(raw.parts), total - 1)  # Header only; no payload.


if __name__ == "__main__":
    unittest.main()
