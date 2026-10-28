import struct
import unittest
from unittest.mock import Mock
from collections import deque
from camera_stream_channel import StreamFileChannel, _DriverProxy
from camera_stream_receiver import ACK


class FakeDevice:
    def __init__(self, responses):
        self.driver = object()
        self.responses = deque(responses)
        self.calls = []

    def sendSenserPacket(self, pfunc, data, sink):
        self.calls.append((pfunc, data))
        reply = self.responses.popleft()
        if isinstance(reply, Exception):
            raise reply
        sink.write(reply)
        return 0, None


class ChannelTests(unittest.TestCase):
    nonce = bytes(range(16))

    def channel(self, responses):
        device = FakeDevice(responses)
        original = device.driver
        return StreamFileChannel(device, self.nonce,
                                 send_packet=lambda d, p, data, sink: d.sendSenserPacket(p, data, sink)), device, original

    def test_job_path_and_payload(self):
        c, d, original = self.channel([b"\0" * 4, b"\0" * 4 + b"payload"])
        self.assertEqual(c.read("chunk.bin"), b"payload")
        self.assertIs(d.driver, original)
        self.assertEqual(d.calls[0][1], struct.pack("<HH", 0x1001, 15) + b"\0" +
                         ("/tmp/jiritsu/../.." + c.directory + "/chunk.bin").encode() + b"\0")

    def test_known_missing_allows_next_poll(self):
        c, d, _ = self.channel([b"\0" * 4, struct.pack("<I", 0x10000006),
                               b"\0" * 4, b"\0" * 4 + b"ready"])
        self.assertIsNone(c.read("done", missing=True))
        self.assertTrue(c.healthy)
        self.assertEqual(c.read("done"), b"ready")

    def test_unknown_result_stops_without_resend(self):
        c, d, original = self.channel([b"\0" * 4, OSError("USB outcome unknown")])
        with self.assertRaises(OSError):
            c.read("chunk.ready")
        self.assertIs(d.driver, original)
        with self.assertRaises(RuntimeError):
            c.read("chunk.ready")
        self.assertEqual(len(d.calls), 2)

    def test_oversized_response_stops(self):
        c, d, _ = self.channel([b"\0" * 4, b"\0" * 4 + b"X" * 81])
        with self.assertRaises(ValueError):
            c.read("chunk.ready")
        self.assertFalse(c.healthy)

    def test_arbitrary_path_and_module_upload_refused(self):
        c, d, _ = self.channel([])
        with self.assertRaises(ValueError):
            c.read("../../dev/cnflasha7")
        with self.assertRaises(ValueError):
            c.write_control("module", b"code")
        self.assertEqual(d.calls, [])

    def test_wrong_camera_status_stops(self):
        c, d, _ = self.channel([b"\0" * 4, struct.pack("<I", 7)])
        with self.assertRaises(RuntimeError):
            c.read("done", missing=True)
        self.assertFalse(c.healthy)

    def test_ack_upload(self):
        c, d, _ = self.channel([b"\0" * 4, b"\0" * 4])
        ack = ACK.pack(b"M4SACK01", self.nonce, 1, b"X" * 32)
        c.write_control("ack", ack)
        self.assertEqual(d.calls[1][1], struct.pack("<HH", 0x1001, 16) + b"\0\xff\0" + ack)

    def test_unknown_ack_upload_not_replayed(self):
        c, d, _ = self.channel([b"\0" * 4, OSError("sent but no reply")])
        ack = ACK.pack(b"M4SACK01", self.nonce, 0, b"X" * 32)
        with self.assertRaises(OSError):
            c.write_control("ack", ack)
        with self.assertRaises(RuntimeError):
            c.write_control("ack", ack)
        self.assertEqual(len(d.calls), 2)

    def test_invalid_ack_never_selected(self):
        c, d, _ = self.channel([])
        ack = ACK.pack(b"M4SACK01", b"X" * 16, 0, b"X" * 32)
        with self.assertRaises(ValueError):
            c.write_control("ack", ack)
        self.assertEqual(d.calls, [])

    def test_actual_SDK_auth_constructor_and_protocol(self):
        from pmca.usb.sony import SonySenserAuthDevice
        driver = Mock()
        driver.getId.return_value = (0x054c, 0x0336)
        driver.write.return_value = None
        driver.read.side_effect = [SonySenserAuthDevice.AuthPacket.pack(
            cmd=(~ret & 0xffff), salt=0,
            data=(b"\x01" + b"\0" * 511 if ret == 6 else b"\0" * 512))
            for ret in [8, 4, 8, 4, 8, 4, 6]]
        proxy = _DriverProxy(driver, 10, lambda: 1)
        auth = SonySenserAuthDevice(proxy)
        auth.authenticate()
        driver.reset.assert_called_once_with()
        self.assertEqual((driver.read.call_count, driver.write.call_count), (7, 7))
        self.assertTrue(all(len(c.args[0]) == 516 for c in driver.write.call_args_list))

    def test_SDK_auth_unknown_read_has_no_replay(self):
        from pmca.usb.sony import SonySenserAuthDevice
        driver = Mock()
        driver.write.return_value = None
        driver.read.side_effect = OSError("synthetic auth transport failure")
        proxy = _DriverProxy(driver, 10, lambda: 1)
        with self.assertRaises(OSError):
            SonySenserAuthDevice(proxy).authenticate()
        with self.assertRaises(RuntimeError):
            proxy.write(b"no retry")
        self.assertEqual((driver.read.call_count, driver.write.call_count), (1, 1))


if __name__ == "__main__":
    unittest.main()
