import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from collections import deque
from camera_stream_collect import collect
from camera_stream_receiver import ACK, CHUNK, RECORD


class SyntheticChannel:
    nonce = bytes(range(16))
    payload = bytes(range(256)) * (CHUNK // 256)

    def __init__(self, stale=False, unknown=False, mismatch=False):
        self.records = [RECORD.pack(b"M4CHNK01", self.nonce, i, i * CHUNK, CHUNK,
                                    hashlib.sha256(self.payload).digest()) for i in range(2)]
        self.ready = deque(([self.records[0], self.records[0], None, self.records[1]]
                            if stale else self.records))
        self.acks = []
        self.unknown, self.mismatch = unknown, mismatch

    def read(self, name, missing=False):
        if name == "chunk.ready":
            return self.ready.popleft()
        if name == "chunk.bin":
            return self.payload
        if name == "done":
            if self.unknown:
                raise OSError("Unknown final read")
            digest = b"X" * 32 if self.mismatch else hashlib.sha256(self.payload * 2).digest()
            return RECORD.pack(b"M4DONE01", self.nonce, 2, CHUNK * 2, 0, digest)
        if name in ("result", "exec_failure"):
            return None
        raise AssertionError(name)

    def write_control(self, name, data):
        assert name == "ack"
        magic, nonce, index, digest = ACK.unpack(data)
        assert magic == b"M4SACK01" and nonce == self.nonce and index == len(self.acks)
        self.acks.append(data)


class CollectTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "session"

    def test_success(self):
        channel = SyntheticChannel()
        result = collect(channel, self.path, sleep=lambda _: None)
        self.assertEqual(result.stat().st_size, CHUNK * 2)
        self.assertEqual(len(channel.acks), 2)

    def test_stale_record_never_replays_ack(self):
        channel = SyntheticChannel(stale=True)
        collect(channel, self.path, sleep=lambda _: None)
        self.assertEqual(len(channel.acks), 2)

    def test_unknown_final_read_retains_unverified(self):
        channel = SyntheticChannel(unknown=True)
        with self.assertRaises(OSError):
            collect(channel, self.path, sleep=lambda _: None)
        self.assertEqual(json.loads((self.path / "status.json").read_text())["state"], "UNVERIFIED")
        self.assertFalse((self.path / "cnflasha7.bin").exists())

    def test_second_digest_failure(self):
        with self.assertRaises(ValueError):
            collect(SyntheticChannel(mismatch=True), self.path, sleep=lambda _: None)
        self.assertFalse((self.path / "cnflasha7.bin").exists())


if __name__ == "__main__":
    unittest.main()
