from copy import deepcopy
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

import camera_install_patch_read_execution as execution
import camera_install_patch_read_session as session
import camera_install_patch_read_plan as plan
from camera_install_journal import InstallJournal
from camera_stream_execution import durable_new
import test_camera_install_patch_read_execution as fixture_module


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class ReadSessionTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixture_module.ExecutionTests()
        self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.f = self.fixture
        self.f.manifest['sources'] = {}
        (self.f.job / 'manifest.json').write_text(json.dumps(self.f.manifest))
        self.f.assets = replace(self.f.assets, manifest_sha256=sha(self.f.job / 'manifest.json'))
        self.review = plan.seal(self.f.root / 'review', assets=self.f.assets, pending_reference=self.f.pending_ref,
            expected_body_sha256=self.f.prior.body, plan_sha256=self.f.prior.plan)
        self.history = self.f.journal.events
        self.calls = []
        self.start = Mock(side_effect=self.start_native)
        self.run = Mock(side_effect=self.run_normal)

    def start_native(self, device, folder, **options):
        self.calls.append('read')
        prepared = execution._preflight(options['assets'], options['pending_reference'],
            options['expected_body_sha256'], options['plan_sha256'], options['reservation'])
        proof = session.contract.validate_publications(
            fixture_module.frames.pack(self.f.channel.ready, prepared.spec, self.f.nonce),
            fixture_module.frames.pack(self.f.channel.result, prepared.spec, self.f.nonce),
            nonce=self.f.nonce, loader_pid=678, spec=prepared.spec)
        return proof | dict(scope=session.SCOPE, asset_reference=prepared.reference,
            reservation=options['reservation'], service_exit_completed=False,
            source_is_hardware=True, journal_cleared=False, cancellation_recorded=False)

    def run_normal(self, body, work, **options):
        self.calls.append('auth')
        self.assertTrue((self.f.job / 'physical-attempt.json').exists())
        value = work('synthetic-authenticated-device')
        path = self.f.evidence / 'current-read-session-terminal.json'
        self.assertTrue(path.exists())
        terminal = json.loads(path.read_text())
        self.assertEqual(terminal['native_receipt'], value)
        self.assertEqual(terminal['state'], 'CURRENT_READ_TERMINAL_DURABLE_BEFORE_STOP')
        self.calls.append('STOP')
        options['record_event'](dict(event='STOP_RESPONSE', mode='service', success=True))
        return value

    def invoke(self, **changes):
        options = dict(plan_sha256=self.f.prior.plan, pending_reference=self.f.pending_ref,
            review_path=self.review['review_path'], review_sha256=self.review['review_sha256'],
            assets=self.f.assets, journal=self.f.journal, lease=self.f.lease, read_authorized=True,
            run_session=self.run, start_fn=self.start, clock=self.f.clock, sleep=self.f.clock.sleep)
        options.update(changes)
        return session.run_current_read_session(self.f.prior.body, self.f.evidence, **options)

    def assert_original_pending(self):
        self.assertEqual(self.f.journal.events, self.history)
        self.assertEqual(InstallJournal.open(self.f.journal.session_dir).events, self.history)
        self.assertEqual(self.f.journal.state, 'INSTALL_PATCH_AWAITING_OPERATOR_RECONNECT')

    def test_full_terminal_is_saved_before_STOP_and_exit_never_clears_original_pending(self):
        result = self.invoke()
        self.assertEqual(self.calls, ['auth', 'read', 'STOP'])
        self.assertEqual(result['state'], 'CURRENT_READ_KNOWN_SERVICE_EXIT')
        self.assertTrue(result['service_exit_completed'])
        self.assertEqual(result['current_review']['sha256'], self.review['review_sha256'])
        self.assertEqual(result['original_plan_sha256'], self.f.prior.plan)
        self.assertNotEqual(result['current_review']['sha256'], result['original_plan_sha256'])
        self.assertFalse(result['source_is_hardware'])
        self.assertFalse(result['native_receipt']['source_is_hardware'])
        for name in session.FALSE_CLAIMS:self.assertIs(result[name], False)
        self.assert_original_pending()
        self.assertEqual(json.loads((self.f.evidence / 'current-read-session-exit.json').read_text()), result)

    def test_missing_consent_and_mixed_or_invalid_injection_reject_before_claims_or_auth(self):
        for changes in (dict(read_authorized=False), dict(run_session=None), dict(start_fn=None),
                        dict(run_session=False, start_fn=False)):
            with self.subTest(changes=changes), self.assertRaises(ValueError):self.invoke(**changes)
        self.assertFalse((self.f.job / 'physical-attempt.json').exists())
        self.run.assert_not_called();self.start.assert_not_called()
        self.assert_original_pending()

    def test_default_route_rejects_custom_context_without_any_authentication(self):
        with self.assertRaisesRegex(ValueError, 'canonical'):
            self.invoke(run_session=None, start_fn=None)
        self.assertFalse((self.f.job / 'physical-attempt.json').exists())
        self.assert_original_pending()

    def test_default_modeled_prior_is_rejected_before_source_runtime_or_auth(self):
        with patch.object(session, 'DEFAULT_LOCK', self.f.lease.path), patch.object(session, 'DEFAULT_SESSIONS', self.f.journal.session_dir.parent):
            with patch.object(session, '_source_only_runtime') as runtime:
                with self.assertRaisesRegex(ValueError, 'Modeled prior'):
                    self.invoke(run_session=None, start_fn=None)
                runtime.assert_not_called()
        self.assertFalse((self.f.job / 'physical-attempt.json').exists())
        self.assert_original_pending()

    def test_wrong_review_hash_or_snapshot_refuses_before_reservation(self):
        with self.assertRaisesRegex(ValueError, 'review changed'):
            self.invoke(review_sha256='0' * 64)
        snapshot = Path(self.review['review_path']).parent / 'sources/camera_install_patch_read_session.py'
        snapshot.write_bytes(b'changed')
        self.f.evidence = self.f.root / 'snapshot-evidence'
        self.f.evidence.mkdir()
        with self.assertRaisesRegex(ValueError, 'snapshot changed'):
            self.invoke()
        self.run.assert_not_called()
        self.assertFalse((self.f.job / 'physical-attempt.json').exists())
        self.assert_original_pending()

    def test_reservation_error_keeps_original_pending_and_never_authenticates(self):
        with patch.object(execution, 'reserve_assets', side_effect=OSError('synthetic claim persistence unknown')):
            with self.assertRaises(OSError):self.invoke()
        self.run.assert_not_called()
        self.assertTrue((self.f.evidence / 'current-read-session-unknown.json').exists())
        self.assert_original_pending()

    def test_authentication_failure_does_not_replay_or_clear_claims(self):
        self.run.side_effect = OSError('synthetic authentication unknown')
        with self.assertRaises(OSError):self.invoke()
        self.assertEqual(self.run.call_count, 1)
        self.start.assert_not_called()
        self.assertTrue((self.f.job / 'physical-attempt.json').exists())
        self.assert_original_pending()

    def test_failed_read_callback_does_not_emit_success_STOP(self):
        self.start.side_effect = OSError('synthetic START/USB outcome unknown')
        with self.assertRaises(OSError):self.invoke()
        self.assertEqual(self.calls, ['auth'])
        self.assertEqual(self.start.call_count, 1)
        self.assertFalse((self.f.evidence / 'current-read-session-terminal.json').exists())
        self.assert_original_pending()

    def test_fabricated_success_boolean_or_tampered_raw_receipt_prevents_STOP(self):
        real = self.start_native
        def tampered(*args, **options):
            value = real(*args, **options)
            value['raw_publications']['result'] = ''
            return value
        self.start.side_effect = tampered
        with self.assertRaises(ValueError):self.invoke()
        self.assertNotIn('STOP', self.calls)
        self.assert_original_pending()

    def test_full_terminal_fsync_failure_prevents_success_STOP(self):
        original = session.durable_new
        def fail(path, value):
            if Path(path).name == 'current-read-session-terminal.json':raise OSError('synthetic fsync failure')
            return original(path, value)
        with patch.object(session, 'durable_new', side_effect=fail):
            with self.assertRaises(OSError):self.invoke()
        self.assertNotIn('STOP', self.calls)
        self.assert_original_pending()

    def test_unknown_STOP_keeps_preSTOP_bytes_and_original_pending(self):
        def unknown(body, work, **options):
            self.calls.append('auth');work('synthetic-device');raise OSError('synthetic STOP unknown')
        self.run.side_effect = unknown
        with self.assertRaises(OSError):self.invoke()
        self.assertTrue((self.f.evidence / 'current-read-session-terminal.json').exists())
        self.assertFalse((self.f.evidence / 'current-read-session-exit.json').exists())
        self.assert_original_pending()

    def test_duplicate_callback_is_rejected_and_not_replayed(self):
        def twice(body, work, **options):
            work('synthetic-device');work('synthetic-device')
        self.run.side_effect = twice
        with self.assertRaisesRegex(ValueError, 'cannot be replayed'):self.invoke()
        self.assertEqual(self.start.call_count, 1)
        self.assert_original_pending()

    def test_lease_reacquired_inside_start_blocks_terminal_and_STOP(self):
        real = self.start_native
        def reacquire(*args, **options):
            value = real(*args, **options)
            self.f.lease.__exit__(None, None, None);self.f.lease.__enter__()
            return value
        self.start.side_effect = reacquire
        with self.assertRaisesRegex(ValueError, 'held lease changed'):self.invoke()
        self.assertNotIn('STOP', self.calls)
        self.assertFalse((self.f.evidence / 'current-read-session-terminal.json').exists())
        self.assert_original_pending()

    def test_lease_reacquired_after_normal_return_cannot_publish_exit(self):
        real = self.run_normal
        def changed(*args, **options):
            value = real(*args, **options)
            self.f.lease.__exit__(None, None, None);self.f.lease.__enter__()
            return value
        self.run.side_effect = changed
        with self.assertRaisesRegex(ValueError, 'held lease changed'):self.invoke()
        self.assertTrue((self.f.evidence / 'current-read-session-terminal.json').exists())
        self.assertFalse((self.f.evidence / 'current-read-session-exit.json').exists())
        self.assert_original_pending()

    def test_review_nonce_claims_prevent_session_reentry(self):
        self.invoke();count = self.run.call_count
        other = self.f.root / 'second-evidence';other.mkdir()
        with self.assertRaises(ValueError):
            session.run_current_read_session(self.f.prior.body, other, plan_sha256=self.f.prior.plan,
                pending_reference=self.f.pending_ref, review_path=self.review['review_path'],
                review_sha256=self.review['review_sha256'], assets=self.f.assets,
                journal=self.f.journal, lease=self.f.lease, read_authorized=True,
                run_session=self.run, start_fn=self.start)
        self.assertEqual(self.run.call_count, count)
        self.assert_original_pending()


class ReadPlanTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixture_module.ExecutionTests();self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.f = self.fixture
        self.f.manifest['sources'] = {}
        (self.f.job / 'manifest.json').write_text(json.dumps(self.f.manifest))
        self.f.assets = replace(self.f.assets, manifest_sha256=sha(self.f.job / 'manifest.json'))
        self.output = self.f.root / 'sealed-read'

    def seal(self):
        return plan.seal(self.output, assets=self.f.assets, pending_reference=self.f.pending_ref,
            expected_body_sha256=self.f.prior.body, plan_sha256=self.f.prior.plan)

    def test_sealer_is_host_only_and_preserves_original_plan_and_sources(self):
        result = self.seal();payload = json.loads(Path(result['review_path']).read_text())
        self.assertEqual(result['original_plan_sha256'], self.f.prior.plan)
        self.assertEqual(payload['asset_reference']['pending_reference'], self.f.pending_ref)
        self.assertEqual(payload['source_only_runtime'], session.SOURCE_ONLY_RUNTIME)
        for key in session.FALSE_CLAIMS:self.assertIs(result[key], False)
        self.assertFalse((self.f.job / 'physical-attempt.json').exists())
        sources = payload['sources']
        self.assertIn('camera_install_patch_read_execution.py', sources)
        self.assertTrue(any(key.startswith('Sony-PMCA-RE/pmca/') for key in sources))
        self.assertEqual(sha(Path(result['review_path']).parent / 'sources/camera_install_patch_read_execution.py'), sources['camera_install_patch_read_execution.py'])

    def test_sealer_refuses_existing_directory_without_overwrite(self):
        value = self.seal();before = Path(value['review_path']).read_bytes()
        with self.assertRaises(ValueError):self.seal()
        self.assertEqual(Path(value['review_path']).read_bytes(), before)

    def test_source_snapshot_or_fsync_failure_does_not_publish_review(self):
        with patch.object(plan, '_sync', side_effect=OSError('synthetic directory fsync failure')):
            with self.assertRaises(OSError):self.seal()
        self.assertFalse((self.output / 'review.json').exists())


if __name__ == '__main__':unittest.main()
