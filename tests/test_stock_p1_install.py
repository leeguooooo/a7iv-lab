"""Entry-point ownership and service-exit tests with an entirely synthetic SDK."""
import json
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import stock_p1_install as install


class InstallTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.bundle = Path(self.tmp.name) / 'bundle';self.bundle.mkdir()
        self.exits = 0
        self.host_failure = None
        self.recovery_failure = None
        self.omit_body_event = False
        self.tamper_after_writer = False
        self.patches = [
            patch.object(install, 'ROOT', Path(self.tmp.name)),
            patch.object(install, 'BUNDLE', self.bundle),
            patch.object(install, 'GLOBAL_ATTEMPT', self.bundle / 'writer-claim.json'),
            patch.object(install, 'READBACK_ATTEMPT', self.bundle / 'readback-claim.json'),
            patch.object(install, 'RECOVERY', self.bundle / 'recovery/observed.bin'),
            patch.object(install, 'preflight', return_value=({'writer_nonce': 'a' * 32}, 'b' * 64)),
            patch.object(install.os, 'geteuid', return_value=0),
            patch.object(install, 'runtime_policy'),
            patch.object(install, 'restore_task_owner'),
            patch.object(install, 'execute_writer_authenticated', side_effect=self.writer),
            patch.object(install, 'save_recovery', side_effect=self.recovery),
            patch.object(install, 'run_normal_session', side_effect=self.sdk),
        ]
        for p in self.patches:
            p.start();self.addCleanup(p.stop)

    def writer(self, device, folder, **kwargs):
        assert kwargs == dict(write_authorized=True, same_body_verified=True, source_is_hardware=True)
        if self.host_failure:
            raise OSError('synthetic unknown COMMIT outcome')
        path = folder / 'readback/capture/cnflasha1.bin'
        path.parent.mkdir(parents=True);path.write_bytes(b'synthetic observed bytes')
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if self.tamper_after_writer:
            path.write_bytes(b'changed after verification')
        return {'state': 'SYNTHETIC_VERIFIED', 'evidence_supports_session_end': True,
                'independent_read_state': 'target', 'independent_host_sha256': digest}

    def recovery(self, source, destination, digest):
        if self.recovery_failure:
            raise OSError('synthetic recovery fsync failure')
        if hashlib.sha256(source.read_bytes()).hexdigest() != digest:
            raise ValueError('Observed file changed after verification')
        return destination

    def sdk(self, body, work, *, record_event, set_stage):
        assert body == 'b' * 64 and (self.bundle / 'entry-attempt.json').exists()
        if not self.omit_body_event:
            record_event({'model': 'ILCE-7M4', 'body_matched': True})
        set_stage('USERLAND_WORK')
        result = work(object())
        self.exits += 1
        return result

    def test_default_has_no_authorization_or_usb_side_effect(self):
        with self.assertRaises(ValueError):
            install.run_authorized()
        install.run_normal_session.assert_not_called()
        self.assertFalse((self.bundle / 'entry-attempt.json').exists())

    def test_success_exits_once_after_readback_and_recovery(self):
        result = install.run_authorized(allow_fixed_p1_write=True)
        self.assertEqual(self.exits, 1)
        self.assertEqual(result['stage'], 'P1_OUTCOME_RECONCILED_EXIT_RESPONSE_RETURNED')
        self.assertFalse(result['features_installed'])
        self.assertEqual(result['camera_health_after_exit'], 'USER_CONFIRMATION_REQUIRED')

    def test_unknown_commit_never_calls_exit_or_recovery(self):
        self.host_failure = True
        with self.assertRaises(OSError):
            install.run_authorized(allow_fixed_p1_write=True)
        self.assertEqual(self.exits, 0)
        install.save_recovery.assert_not_called()
        report = json.loads((self.bundle / 'execution/run.json').read_text())
        self.assertTrue(report['no_further_application_USB_requests'])
        self.assertTrue(report['do_not_reset_or_reboot_while_writer_outcome_unknown'])

    def test_recovery_copy_failure_never_exits_or_reruns_writer(self):
        self.recovery_failure = True
        with self.assertRaises(OSError):
            install.run_authorized(allow_fixed_p1_write=True)
        self.assertEqual(self.exits, 0)
        with self.assertRaises(FileExistsError):
            install.run_authorized(allow_fixed_p1_write=True)
        self.assertEqual(install.execute_writer_authenticated.call_count, 1)
        self.assertEqual(install.run_normal_session.call_count, 1)
        report = json.loads((self.bundle / 'execution/run.json').read_text())
        self.assertEqual(report['stage'], 'WRITER_OUTCOME_RECONCILED_RECOVERY_COPY_FAILED')
        self.assertTrue(report['native_writer_outcome_known'])

    def test_recovery_copy_uses_previously_verified_digest_not_live_file_hash(self):
        self.tamper_after_writer = True
        with self.assertRaises(ValueError):
            install.run_authorized(allow_fixed_p1_write=True)
        self.assertEqual(self.exits, 0)
        report = json.loads((self.bundle / 'execution/run.json').read_text())
        self.assertEqual(report['stage'], 'WRITER_OUTCOME_RECONCILED_RECOVERY_COPY_FAILED')

    def test_missing_sdk_body_event_never_enters_writer(self):
        self.omit_body_event = True
        with self.assertRaises(ValueError):
            install.run_authorized(allow_fixed_p1_write=True)
        install.execute_writer_authenticated.assert_not_called()
        self.assertEqual(self.exits, 0)

    def test_previously_attempted_readback_blocks_usb_entry(self):
        install.READBACK_ATTEMPT.write_text('synthetic prior claim')
        with self.assertRaises(ValueError):
            install.run_authorized(allow_fixed_p1_write=True)
        install.run_normal_session.assert_not_called()
        self.assertFalse((self.bundle / 'entry-attempt.json').exists())


if __name__ == '__main__':
    unittest.main()
