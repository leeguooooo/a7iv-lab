import hashlib
import json
from pathlib import Path
import tempfile
from unittest.mock import Mock, patch
import unittest

import camera_stream_batch as batch
from camera_stream_remaining_plan import BATCH, checked_worker, checked_bootstrap
from camera_stream_profiles import PROFILES


class BatchTests(unittest.TestCase):
    def test_batch_run_flag_is_separate_from_pilot(self):
        with patch("sys.argv", ["batch", "run"]), patch.object(batch, "run_authorized") as run, patch("builtins.print"):
            with self.assertRaises(SystemExit):
                batch.main()
        run.assert_not_called()

    def test_old_four_partition_flag_cannot_authorize_planned_batch(self):
        with patch("sys.argv", ["batch", "run", "--allow-four-partition-backup"]), \
                patch.object(batch, "run_authorized") as run, patch("builtins.print"), \
                patch("sys.stderr"):
            with self.assertRaises(SystemExit):
                batch.main()
        run.assert_not_called()

    def test_failed_preflight_never_reserves_or_calls_USB(self):
        with patch.object(batch, "preflight", side_effect=ValueError("stale artifacts")), \
                patch.object(batch, "durable_new") as reserve, patch.object(batch, "run_normal_session") as session:
            with self.assertRaises(ValueError):
                batch.run_authorized()
        reserve.assert_not_called()
        session.assert_not_called()

    def test_tiny_worker_cannot_be_admitted_as_production(self):
        with self.assertRaises(ValueError):
            checked_worker(BATCH / "cnflasha15/tiny")

    def test_actual_planned_bootstrap_artifacts_validate_locally(self):
        for p in PROFILES:
            with self.subTest(profile=p.name):
                meta, module = checked_bootstrap(p.name)
                self.assertEqual(meta["target"], list(p.target))
                self.assertEqual(hashlib.sha256(module).hexdigest(), meta["module"]["sha256"])

    def test_recovery_copy_is_verified_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as temporary:
            source, destination = Path(temporary) / "source.bin", Path(temporary) / "recovery/image.bin"
            source.write_bytes(b"verified capture")
            expected = hashlib.sha256(source.read_bytes()).hexdigest()
            batch.save_recovery(source, destination, expected)
            self.assertEqual(destination.read_bytes(), source.read_bytes())
            self.assertFalse(destination.with_suffix(".partial").exists())
            destination.write_bytes(b"KEEP_OTHER_CAPTURE")
            with self.assertRaises(ValueError):
                batch.save_recovery(source, destination, expected)
            self.assertEqual(destination.read_bytes(), b"KEEP_OTHER_CAPTURE")

    def test_unknown_first_module_stops_batch_and_cannot_repeat(self):
        candidates = [({"nonce": bytes([i] * 16).hex(), "module": {"sha256": "0" * 64}}, b"synthetic module")
                      for i, _ in enumerate(PROFILES, 1)]
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            (folder / "batch.json").write_text("{}\n")
            session = Mock(side_effect=lambda body, work, **kwargs: work(Mock()))
            execution = Mock(side_effect=OSError("synthetic USB result unknown"))
            with patch.object(batch, "preflight", return_value=({}, candidates, "a" * 64)), \
                    patch.object(batch, "run_normal_session", session), \
                    patch.object(batch, "execute_remaining_authenticated", execution), \
                    patch.object(batch, "RECOVERY", folder / "recovery"):
                with self.assertRaises(OSError):
                    batch.run_authorized(folder)
                self.assertEqual(execution.call_count, 1)
                report = json.loads((folder / "execution/run.json").read_text())
                self.assertTrue(report["no_further_application_USB_requests"])
                self.assertEqual(report["verified"], [])
                self.assertFalse((folder / "execution/cnflasha8").exists())
                with self.assertRaises(FileExistsError):
                    batch.run_authorized(folder)
                self.assertEqual(session.call_count, 1)

    def test_session_return_without_captures_cannot_claim_completion(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            (folder / "batch.json").write_text("{}\n")
            with patch.object(batch, "preflight", return_value=({}, [], "a" * 64)), \
                    patch.object(batch, "run_normal_session", return_value=None), \
                    patch.object(batch, "RECOVERY", folder / "recovery"):
                with self.assertRaises(ValueError):
                    batch.run_authorized(folder)
            report = json.loads((folder / "execution/run.json").read_text())
            self.assertNotEqual(report["stage"], "ALL_PLANNED_BACKUPS_VERIFIED_EXIT_RESPONSE_RETURNED")
            self.assertEqual(report["verified"], [])


if __name__ == "__main__":
    unittest.main()
