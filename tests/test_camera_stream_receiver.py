"""Host durability and fault tests; no camera or USB imports."""
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from camera_stream_receiver import ACK, CHUNK, PILOT, RECORD, StreamReceiver


class StreamTests(unittest.TestCase):
    nonce = bytes(range(16))
    block = bytes(range(256)) * (CHUNK // 256)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "session"
        self.r = StreamReceiver(self.path, self.nonce)
        self.addCleanup(self.r.abort, "TEST_CLEANUP")

    def record(self, index=0, offset=0, nonce=None, length=CHUNK, digest=None):
        return RECORD.pack(b"M4CHNK01", nonce or self.nonce, index, offset,
                           length, digest or hashlib.sha256(self.block).digest())

    def fill(self):
        for i in range(2):
            self.r.accept(self.record(i, i * CHUNK), self.block)

    def done(self, digest=None, error=0, count=2, size=PILOT[2]):
        return RECORD.pack(b"M4DONE01", self.nonce, count, size, error,
                           digest or hashlib.sha256(self.block * 2).digest())

    def state(self):
        return json.loads((self.path / "status.json").read_text())["state"]

    def test_full_readback(self):
        self.fill()
        result = self.r.finish(self.done())
        self.assertEqual(result.stat().st_size, PILOT[2])
        self.assertEqual(self.state(), "TWO_READS_MATCHED")
        self.assertFalse(json.loads((self.path / "status.json").read_text())["restore_verified"])

    def test_ack_after_data_and_manifest_sync(self):
        calls = []
        import os
        original = os.fsync
        with patch("camera_stream_receiver.os.fsync",
                   side_effect=lambda fd: (calls.append(fd), original(fd))[1]):
            ack = self.r.accept(self.record(), self.block)
        self.assertGreaterEqual(len(calls), 3)
        self.assertEqual(ACK.unpack(ack), (b"M4SACK01", self.nonce, 0,
                                         hashlib.sha256(self.block).digest()))
        self.assertEqual((self.path / "cnflasha7.partial").stat().st_size, CHUNK)
        self.assertEqual(len((self.path / "chunks.jsonl").read_text().splitlines()), 1)

    def test_corrupt_chunk(self):
        with self.assertRaises(ValueError):
            self.r.accept(self.record(digest=b"x" * 32), self.block)
        self.assertEqual(self.state(), "UNVERIFIED")
        self.assertEqual(self.r.offset, 0)

    def test_wrong_nonce(self):
        with self.assertRaises(ValueError):
            self.r.accept(self.record(nonce=b"x" * 16), self.block)

    def test_skipped_sequence(self):
        with self.assertRaises(ValueError):
            self.r.accept(self.record(index=1), self.block)

    def test_wrong_offset(self):
        with self.assertRaises(ValueError):
            self.r.accept(self.record(offset=512), self.block)

    def test_short_transport_payload(self):
        with self.assertRaises(ValueError):
            self.r.accept(self.record(), self.block[:-1])

    def test_duplicate_chunk_stops_session(self):
        self.r.accept(self.record(), self.block)
        with self.assertRaises(ValueError):
            self.r.accept(self.record(), self.block)
        with self.assertRaises(RuntimeError):
            self.r.accept(self.record(1, CHUNK), self.block)

    def test_second_pass_mismatch(self):
        self.fill()
        with self.assertRaises(ValueError):
            self.r.finish(self.done(digest=b"x" * 32))
        self.assertEqual(self.state(), "UNVERIFIED")
        self.assertFalse((self.path / "cnflasha7.bin").exists())

    def test_native_error(self):
        self.fill()
        with self.assertRaises(ValueError):
            self.r.finish(self.done(error=5))

    def test_disk_corruption_detected(self):
        self.fill()
        with (self.path / "cnflasha7.partial").open("r+b") as f:
            f.write(b"BROKEN")
        with self.assertRaises(ValueError):
            self.r.finish(self.done())
        self.assertFalse((self.path / "cnflasha7.bin").exists())

    def test_existing_final_never_overwritten(self):
        self.fill()
        final = self.path / "cnflasha7.bin"
        final.write_bytes(b"KEEP")
        with self.assertRaises(FileExistsError):
            self.r.finish(self.done())
        self.assertEqual(final.read_bytes(), b"KEEP")
        self.assertEqual(self.state(), "UNVERIFIED")

    def test_unknown_transport_no_resume(self):
        self.r.accept(self.record(), self.block)
        self.r.abort()
        with self.assertRaises(RuntimeError):
            self.r.accept(self.record(1, CHUNK), self.block)
        with self.assertRaises(FileExistsError):
            StreamReceiver(self.path, self.nonce)
        self.assertEqual(self.state(), "UNVERIFIED")

    def test_sync_failure_no_ack(self):
        real_status = self.r._status
        with patch("camera_stream_receiver.os.fsync", side_effect=OSError("disk failed")), \
                patch.object(self.r, "_status"):
            with self.assertRaises(OSError):
                self.r.accept(self.record(), self.block)
        self.assertTrue(self.r.stopped)
        self.assertEqual(self.r.offset, 0)
        real_status("UNVERIFIED", reason="simulated_sync_failure")

    def test_premature_finish(self):
        with self.assertRaises(ValueError):
            self.r.finish(self.done())

    def test_no_generic_target(self):
        with self.assertRaises(ValueError):
            StreamReceiver(Path(self.tmp.name) / "other", self.nonce,
                           ("cnflasha15", 143, 681574400))


if __name__ == "__main__":
    unittest.main()
