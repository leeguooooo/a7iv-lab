import hashlib
import json
from pathlib import Path
import struct
import tempfile
from unittest.mock import Mock, patch
import unittest

from camera_stream_execution import (BootstrapChannel, LAUNCH, LIBRARIES, SLOT,
                                     execute_authenticated, validate_launch)
from camera_stream_collect import NATIVE
from test_camera_stream_collect import SyntheticChannel


class ExecutionChannel(SyntheticChannel):
    def __init__(self):
        super().__init__()
        self.uploads, self.starts, self.slot_exists = 0, 0, False
        self.launch_bad = self.ready_bad = self.final_bad = False

    def read_loader(self, path):
        return (b"existing" if self.slot_exists else None) if path == SLOT else b"loader"

    def upload_once(self, module, digest, attempt_path):
        self.uploads += 1

    def read(self, name, missing=False):
        digest = hashlib.sha256(self.payload * 2).digest()
        if name == "launch":
            return LAUNCH.pack(b"M4BOOT01", self.nonce, 1, 2 if self.launch_bad else 3,
                               0, 0, 123, 0, 234, 234, 0, 409600000)
        if name == "ready":
            return NATIVE.pack(b"M4STR001", self.nonce, 1, 1, 0, 1 if self.ready_bad else 0,
                               234, 1, 123, 0, -1, 0, 0, 3, b"\0" * 32, b"\0" * 32)
        if name == "result":
            return NATIVE.pack(b"M4STR001", self.nonce, 1, 6, 0, 0, 234, 1, 123, 0,
                               2, 16777216, 2, 63, digest, b"X" * 32 if self.final_bad else digest)
        return super().read(name, missing)

    def write_control(self, name, data):
        if name == "start":
            assert data == b"M4START1" + self.nonce + struct.pack("<Q", 1)
            self.starts += 1
        else:
            super().write_control(name, data)


class ExecutionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.evidence = Path(self.tmp.name)
        self.channel = ExecutionChannel()
        self.loader_patch = patch.dict(LIBRARIES,
                                       {"/lib/test_loader": hashlib.sha256(b"loader").hexdigest()}, clear=True)
        self.loader_patch.start()
        self.addCleanup(self.loader_patch.stop)

    def execute(self):
        module = b"synthetic module"
        return execute_authenticated(self.channel, module, hashlib.sha256(module).hexdigest(),
                                     self.evidence, sleep=lambda _: None)

    def test_complete_orchestration(self):
        self.assertTrue(self.execute().exists())
        self.assertEqual((self.channel.uploads, self.channel.starts, len(self.channel.acks)), (1, 1, 2))
        self.assertTrue((self.evidence / "completed.json").exists())

    def test_existing_slot_not_overwritten(self):
        self.channel.slot_exists = True
        with self.assertRaises(RuntimeError):
            self.execute()
        self.assertEqual((self.channel.uploads, self.channel.starts), (0, 0))

    def test_loader_hash_mismatch_before_upload(self):
        LIBRARIES["/lib/test_loader"] = "0" * 64
        with self.assertRaises(ValueError):
            self.execute()
        self.assertEqual(self.channel.uploads, 0)

    def test_bad_launch_prevents_start(self):
        self.channel.launch_bad = True
        with self.assertRaises(ValueError):
            self.execute()
        self.assertEqual((self.channel.uploads, self.channel.starts), (1, 0))

    def test_bad_ready_prevents_start(self):
        self.channel.ready_bad = True
        with self.assertRaises(ValueError):
            self.execute()
        self.assertEqual(self.channel.starts, 0)

    def test_final_native_hash_mismatch_not_completed(self):
        self.channel.final_bad = True
        with self.assertRaises(ValueError):
            self.execute()
        self.assertFalse((self.evidence / "completed.json").exists())
        # Retain the independently verified capture and the contradictory status
        # for review; do not quietly rerun or overwrite this session.
        self.assertTrue((self.evidence / "capture/cnflasha7.bin").exists())

    def test_unknown_upload_no_start_or_more_reads(self):
        self.channel.upload_once = Mock(side_effect=OSError("upload unknown"))
        self.channel.read = Mock()
        with self.assertRaises(OSError):
            self.execute()
        self.channel.read.assert_not_called()
        self.assertEqual(self.channel.starts, 0)


class AttemptTests(unittest.TestCase):
    nonce = bytes(range(16))

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.attempt = Path(self.tmp.name) / "module-attempt.json"
        self.module = b"reviewed test module"
        self.digest = hashlib.sha256(self.module).hexdigest()

    def channel(self):
        return BootstrapChannel(Mock(), self.nonce)

    def test_unknown_after_reservation_is_not_replayed(self):
        channel = self.channel()
        channel._packet = Mock(side_effect=OSError("unknown select"))
        with self.assertRaises(OSError):
            channel.upload_once(self.module, self.digest, self.attempt)
        self.assertTrue(self.attempt.exists())
        with self.assertRaises(RuntimeError):
            channel.upload_once(self.module, self.digest, self.attempt)
        self.assertEqual(channel._packet.call_count, 1)
        fresh = self.channel()
        fresh._packet = Mock()
        with self.assertRaises(FileExistsError):
            fresh.upload_once(self.module, self.digest, self.attempt)
        fresh._packet.assert_not_called()

    def test_persistent_reservation_failure_prevents_USB(self):
        channel = self.channel()
        channel._packet = Mock()
        with patch("camera_stream_execution.durable_new", side_effect=OSError("disk failure")):
            with self.assertRaises(OSError):
                channel.upload_once(self.module, self.digest, self.attempt)
        channel._packet.assert_not_called()

    def test_wrong_module_no_reservation_or_USB(self):
        channel = self.channel()
        channel._packet = Mock()
        with self.assertRaises(ValueError):
            channel.upload_once(self.module, "0" * 64, self.attempt)
        self.assertFalse(self.attempt.exists())
        channel._packet.assert_not_called()


if __name__ == "__main__":
    unittest.main()
