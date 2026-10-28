import hashlib
from pathlib import Path
import tempfile
from unittest.mock import Mock, patch
import unittest

from camera_stream_profiles import PROFILES, profile
from camera_stream_receiver import ACK, RECORD, StreamReceiver
from camera_stream_remaining import RemainingChannel, RemainingReceiver
from camera_stream_collect import _collect_profile


class RemainingTests(unittest.TestCase):
    def test_fixed_geometry_and_last_chunk(self):
        expected = {"cnflasha4": (2, 4194304), "cnflasha10": (2, 4194304),
                    "cnflasha18": (3, 4194304), "cnflasha23": (8, 8388608), "cnflasha8": (8, 8388608), "cnflasha3": (10, 3145728),
                    "cnflasha5": (38, 4194304), "cnflasha15": (82, 2097152)}
        self.assertEqual([p.name for p in PROFILES], ["cnflasha4", "cnflasha8", "cnflasha3", "cnflasha5",
                                                     "cnflasha15", "cnflasha10", "cnflasha18", "cnflasha23"])
        for p in PROFILES:
            self.assertEqual((p.chunks, p.size % 8388608 or 8388608), expected[p.name])
        self.assertEqual(sum(p.size for p in PROFILES), 1255145472)

    def test_remaining_ACK_bound_is_profile_specific(self):
        nonce = bytes(range(16))
        c = RemainingChannel(Mock(), nonce, "cnflasha15")
        c._packet = Mock(return_value=b"")
        c.write_control("ack", ACK.pack(b"M4SACK01", nonce, 81, b"X" * 32))
        self.assertEqual(c._packet.call_count, 2)
        with self.assertRaises(ValueError):
            c.write_control("ack", ACK.pack(b"M4SACK01", nonce, 82, b"X" * 32))
        self.assertEqual(c._packet.call_count, 2)

    def test_no_arbitrary_source_or_tiny_runtime_target(self):
        with self.assertRaises(ValueError):
            profile("/dev/mem")
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(ValueError):
                StreamReceiver(Path(temporary) / "pilot", bytes(16), profile("cnflasha15").target)
            with self.assertRaises(ValueError):
                RemainingReceiver(Path(temporary) / "tiny", bytes(16), ("cnflasha15", 143, 9216))

    def test_common_collector_preserves_final_short_chunks(self):
        for p in PROFILES:
            with self.subTest(profile=p.name), tempfile.TemporaryDirectory() as temporary:
                target = (p.name, p.minor, p.tiny_size)
                class TinyReceiver(StreamReceiver):
                    ALLOWED_TARGETS = (target,)
                class Channel:
                    nonce = bytes(range(16))
                    index = 0
                    payload = bytes(i & 255 for i in range(p.tiny_size))
                    def read(self, name, missing=False):
                        start = self.index * 4096
                        raw = self.payload[start:start + 4096]
                        if name == "chunk.ready":
                            return RECORD.pack(b"M4CHNK01", self.nonce, self.index, start, len(raw),
                                               hashlib.sha256(raw).digest())
                        if name == "chunk.bin":
                            return raw
                        if name == "done":
                            return RECORD.pack(b"M4DONE01", self.nonce, self.index, len(self.payload), 0,
                                               hashlib.sha256(self.payload).digest())
                        raise AssertionError(name)
                    def write_control(self, name, data):
                        magic, nonce, index, digest = ACK.unpack(data)
                        assert name == "ack" and magic == b"M4SACK01" and nonce == self.nonce and index == self.index
                        self.index += 1
                with patch("camera_stream_receiver.CHUNK", 4096), patch("camera_stream_collect.CHUNK", 4096):
                    output = _collect_profile(Channel(), Path(temporary) / "capture", target,
                                              TinyReceiver, sleep=lambda _: None)
                self.assertEqual(output.read_bytes(), Channel.payload)


if __name__ == "__main__":
    unittest.main()
