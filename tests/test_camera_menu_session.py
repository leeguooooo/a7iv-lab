"""Temporary local ledgers and injected fake sessions only; no device actions."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from camera_device_lease import CameraDeviceLease
from camera_install_journal import InstallJournal
import camera_menu_session as session


class OrchestrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.evidence = root / 'evidence'
        self.evidence.mkdir()
        self.plan, self.body = 'a' * 64, 'b' * 64
        self.journal = InstallJournal.create(root / 'sessions', 'attempt',
            plan_sha256=self.plan, body_sha256=self.body, model='ILCE-7M4')
        self.journal.advance('SD_STAGE_INTENT')
        self.journal.advance('SD_STAGED')
        # Acquire only a local temporary fixture lock, never the default device lock.
        self.lease = self.enterContext(CameraDeviceLease('offline-test', lock_path=root / 'fixture.lock'))
        self.seconds = 0
        self.clock = lambda: self.seconds
        self.observed = dict(state='PATCH_OBSERVED_AWAITING_KNOWN_EXIT_AND_NORMAL_BODY',
                             nonce=bytes(range(16)).hex(),
                             source_is_hardware=True, installation_authorized=False,
                             conservative_seconds_remaining=180)
        self.start = Mock(return_value=self.observed)
        self.normal = dict(model='ILCE-7M4', body_sha256=self.body, body_matched=True,
                           usb_vendor=0x054c, usb_product=0x0da5, finite_driver_timeout=True)
        self.wait = Mock(return_value=self.normal)
        self.calls = []
        def run(expected, work, **kwargs):
            self.assertEqual(self.journal.state, 'RAM_MAY_BE_ACTIVE')
            self.assertEqual(InstallJournal.open(self.journal.session_dir).state, 'RAM_MAY_BE_ACTIVE')
            self.calls.append('session')
            result = work('fake-authenticated-device')
            self.calls.append('known STOP')
            kwargs['record_event']({'event':'STOP_RESPONSE','mode':'service','success':True})
            return result
        self.run = Mock(side_effect=run)

    def invoke(self, **overrides):
        opts = dict(plan_sha256=self.plan, journal=self.journal, lease=self.lease,
                    ram_authorized=True, run_session=self.run,
                    start_fn=self.start, clock=self.clock, sleep=lambda _: None)
        opts.update(overrides)
        return session.run_menu_session(self.body, self.evidence, **opts)

    def assert_no_handoff(self):
        self.assertFalse((self.evidence / 'session-awaiting-reconnect.json').exists())
        self.assertEqual(self.journal.state, 'STOPPED_UNKNOWN')

    def test_known_stop_returns_pending_without_normal_probe_or_budget_deduction(self):
        self.wait.side_effect = AssertionError('operator reconnect must not be probed')
        result = self.invoke()
        self.assertEqual(result['state'], 'RAM_AWAITING_OPERATOR_RECONNECT')
        self.assertEqual(self.journal.state, 'RAM_AWAITING_OPERATOR_RECONNECT')
        self.assertEqual(result['conservative_seconds_remaining'], 180)
        self.assertEqual(json.loads((self.evidence/'session-awaiting-reconnect.json').read_text()), result)
        self.wait.assert_not_called()

    def test_return_without_explicit_stop_receipt_is_unknown(self):
        self.run.side_effect = lambda expected, work, **kwargs: work('fake-device')
        with self.assertRaisesRegex(ValueError, 'Known service STOP'):
            self.invoke()
        self.assertEqual(self.journal.state, 'STOPPED_UNKNOWN')

    def test_pending_event_binds_entire_returned_and_persisted_receipt(self):
        result = self.invoke()
        persisted = json.loads((self.evidence/'session-awaiting-reconnect.json').read_text())
        self.assertEqual(persisted, result)
        proof = hashlib.sha256(json.dumps(persisted, sort_keys=True,
            separators=(',', ':'), allow_nan=False).encode()).hexdigest()
        self.assertEqual(InstallJournal.open(self.journal.session_dir).events[-1]['details']['pending_receipt_sha256'], proof)

    def test_historical_patch_budget_is_not_pending_admission(self):
        self.observed['conservative_seconds_remaining'] = 0
        result = self.invoke()
        self.assertEqual(result['state'], 'RAM_AWAITING_OPERATOR_RECONNECT')
        self.assertEqual(result['conservative_seconds_remaining'], 0)

    def test_known_pipe_stop_returns_pending(self):
        def run(expected, work, **kwargs):
            result = work('fake-device')
            kwargs['record_event'](dict(event='STOP_RESPONSE', mode='service', known_pipe_response=True))
            return result
        self.run.side_effect = run
        result = self.invoke()
        self.assertEqual(self.journal.state, 'RAM_AWAITING_OPERATOR_RECONNECT')
        self.assertTrue(result['service_events'][0]['known_pipe_response'])

    def test_pending_preserves_known_stop_and_model_provenance(self):
        result = self.invoke()
        self.assertEqual(self.calls, ['session', 'known STOP'])
        self.assertEqual(result['service_events'], [{'event':'STOP_RESPONSE','mode':'service','success':True}])
        self.assertFalse(result['installation_authorized'])
        self.assertFalse(result['RAM_original_state_verified'])
        self.assertTrue(self.start.call_args.kwargs['body_verified'])
        self.assertFalse(result['patch_observation']['source_is_hardware'])
        self.assertFalse(result['source_is_hardware'])

    def test_no_authorization_makes_zero_session_upload_or_normal_calls(self):
        before = self.journal.events
        with self.assertRaisesRegex(ValueError, 'authorization'):
            self.invoke(ram_authorized=False)
        self.run.assert_not_called(); self.start.assert_not_called(); self.wait.assert_not_called()
        self.assertEqual(self.journal.events, before)
        self.assertEqual(InstallJournal.open(self.journal.session_dir).events, before)
        report = json.loads((self.evidence / 'session-stopped.json').read_text())
        self.assertEqual(report['state'], 'LOCAL_REJECTED_NO_DEVICE_SESSION')

    def test_intent_persistence_failure_makes_zero_device_calls_preserves_error(self):
        original = self.journal.advance
        def advance(state, **kwargs):
            if state == 'RAM_MAY_BE_ACTIVE':
                raise OSError('synthetic fsync failure')
            return original(state, **kwargs)
        with patch.object(self.journal, 'advance', side_effect=advance):
            with self.assertRaisesRegex(OSError, 'fsync failure'):
                self.invoke()
        self.run.assert_not_called(); self.start.assert_not_called(); self.wait.assert_not_called()
        self.assertEqual(self.journal.state, 'SD_STAGED')
        report = json.loads((self.evidence / 'session-stopped.json').read_text())
        self.assertEqual(report['error_type'], 'OSError')
        self.assertEqual(report['state'], 'LOCAL_REJECTED_NO_DEVICE_SESSION')
        self.assertTrue(report['journal_may_have_partial_intent'])

    def test_unknown_stop_never_probes_normal(self):
        def run(expected, work, **kwargs):
            work('fake-device')
            raise ConnectionError('unknown STOP')
        self.run.side_effect = run
        with self.assertRaises(ConnectionError): self.invoke()
        self.wait.assert_not_called()
        self.assert_no_handoff()

    def test_start_failure_is_propagated_without_successful_session_exit(self):
        self.start.side_effect = TimeoutError('unknown patch outcome')
        with self.assertRaises(TimeoutError): self.invoke()
        self.assertEqual(self.calls, ['session'])
        self.wait.assert_not_called()
        self.assert_no_handoff()

    def test_invalid_patch_cannot_reach_success_stop(self):
        self.observed['state'] = 'unproven'
        with self.assertRaises(ValueError): self.invoke()
        self.assertEqual(self.calls, ['session'])
        self.wait.assert_not_called()
        self.assert_no_handoff()

    def test_slow_known_exit_does_not_consume_live_handoff_budget(self):
        original = self.run.side_effect
        def run(*args, **kwargs):
            result = original(*args, **kwargs)
            self.seconds = 900
            return result
        self.run.side_effect = run
        result = self.invoke()
        self.assertEqual(result['conservative_seconds_remaining'], 180)
        self.assertEqual(result['budget_basis'], 'historical_patch_observation_information_only')
        self.wait.assert_not_called()

    def test_unheld_lease_makes_zero_device_calls(self):
        unheld = CameraDeviceLease('offline-unheld', lock_path=self.evidence.parent / 'unheld.lock')
        with self.assertRaisesRegex(ValueError, 'Caller-held'): self.invoke(lease=unheld)
        self.run.assert_not_called(); self.wait.assert_not_called()

    def test_wrong_binding_makes_zero_device_calls_and_preserves_journal(self):
        before = self.journal.events
        with self.assertRaisesRegex(ValueError, 'binding mismatch'):
            self.invoke(plan_sha256='d' * 64)
        self.run.assert_not_called(); self.wait.assert_not_called(); self.start.assert_not_called()
        self.assertEqual(self.journal.events, before)
        self.assertEqual(InstallJournal.open(self.journal.session_dir).events, before)
        self.assertEqual(json.loads((self.evidence / 'session-stopped.json').read_text())['state'],
                         'LOCAL_REJECTED_NO_DEVICE_SESSION')

    def test_missing_evidence_rejects_without_changing_journal_or_calling_sdk(self):
        self.evidence.rmdir()
        before = self.journal.events
        with self.assertRaisesRegex(ValueError, 'evidence directory'): self.invoke()
        self.run.assert_not_called(); self.start.assert_not_called(); self.wait.assert_not_called()
        self.assertEqual(self.journal.events, before)
        self.assertEqual(InstallJournal.open(self.journal.session_dir).events, before)
        report = json.loads((self.evidence.parent / (self.evidence.name + '-local-rejected.json')).read_text())
        self.assertEqual(report['state'], 'LOCAL_REJECTED_NO_DEVICE_SESSION')
        self.assertFalse(report['intent_persistence_attempted'])

    def test_wrong_body_binding_preserves_journal_without_device_calls(self):
        before = self.journal.events
        with self.assertRaisesRegex(ValueError, 'binding mismatch'):
            session.run_menu_session('c' * 64, self.evidence, plan_sha256=self.plan,
                journal=self.journal, lease=self.lease, ram_authorized=True,
                run_session=self.run, start_fn=self.start)
        self.run.assert_not_called(); self.start.assert_not_called(); self.wait.assert_not_called()
        self.assertEqual(self.journal.events, before)
        self.assertEqual(InstallJournal.open(self.journal.session_dir).events, before)

    def test_partial_intent_file_is_preserved_and_never_cleaned_or_appended(self):
        partial = self.journal.session_dir / '00000004.json'
        def fail_intent(*args, **kwargs):
            partial.write_bytes(b'{partial-intent')
            raise OSError('partial fsync failure')
        with patch.object(self.journal, 'advance', side_effect=fail_intent) as advance:
            with self.assertRaisesRegex(OSError, 'partial fsync'): self.invoke()
        advance.assert_called_once()
        self.assertEqual(partial.read_bytes(), b'{partial-intent')
        self.run.assert_not_called(); self.start.assert_not_called(); self.wait.assert_not_called()
        self.assertFalse((self.journal.session_dir / '00000005.json').exists())

    def assert_single_injection_is_model(self, argument):
        values = dict(run_session=None, start_fn=None)
        values[argument] = {'run_session': self.run, 'start_fn': self.start}[argument]
        with patch('camera_stream_usb_session.run_normal_session', self.run), \
                patch('camera_menu_window.start_authenticated', self.start):
            result = self.invoke(**values)
        self.assertFalse(result['source_is_hardware'])
        self.assertFalse(result['patch_observation']['source_is_hardware'])
        self.assertTrue(self.observed['source_is_hardware'])  # Caller object was not mutated.

    def test_injected_start_alone_forces_model_provenance(self):
        self.assert_single_injection_is_model('start_fn')

    def test_injected_session_alone_forces_model_provenance(self):
        self.assert_single_injection_is_model('run_session')

    def test_replaced_lease_inode_rejects_start_before_journal_or_sdk(self):
        before = self.journal.events
        self.lease.path.rename(self.lease.path.with_name('old-owner.lock'))
        self.lease.path.write_text('replacement')
        with self.assertRaisesRegex(ValueError, 'Live caller lease'): self.invoke()
        self.assertEqual(self.journal.events, before)
        self.run.assert_not_called(); self.start.assert_not_called(); self.wait.assert_not_called()

    def test_other_pending_session_blocks_start_without_changing_current_journal(self):
        other = InstallJournal.create(self.evidence.parent / 'other-root', 'other',
            plan_sha256=self.plan, body_sha256=self.body, model='ILCE-7M4')
        other.session_dir.rename(self.journal.session_dir.parent / 'other')
        before = self.journal.events
        with self.assertRaisesRegex(ValueError, 'Another install session'): self.invoke()
        self.assertEqual(self.journal.events, before)
        self.run.assert_not_called(); self.start.assert_not_called()

    def test_stale_journal_makes_zero_device_calls(self):
        InstallJournal.open(self.journal.session_dir).advance('RAM_MAY_BE_ACTIVE')
        with self.assertRaisesRegex(ValueError, 'Fresh SD_STAGED'):
            self.invoke()
        self.run.assert_not_called(); self.wait.assert_not_called()

    def test_local_stop_report_failure_does_not_replace_original_exception(self):
        self.run.side_effect = ConnectionError('original failure')
        with patch.object(session, 'durable_new', side_effect=OSError('report failed')):
            with self.assertRaisesRegex(ConnectionError, 'original failure'): self.invoke()
        self.assertEqual(self.journal.state, 'STOPPED_UNKNOWN')


class RestorationCollectionTests(unittest.TestCase):
    setUp = OrchestrationTests.setUp

    def prepare_collection(self, *, ready=True, hardware=True, receipt_hash=None):
        import camera_menu_window as menu
        self.journal.advance('RAM_MAY_BE_ACTIVE')
        initial = {name: 0 for name in menu.FIELDS}
        initial.update(version=1, phase=1, euid=0, pid=234, ppid=1, loader_pid=123,
                       flags=13, snapshot_before_status=-11, snapshot_end_status=-11)
        for phase in ('before', 'end'):
            for name in menu.OBSERVATIONS:
                initial[phase+'_'+name] = -1
        patched = dict(initial, phase=5, flags=765, patched=1, app_patched=1,
            app_write_attempted=1, app_pid=345, base_addr=4096, target_addr=12112,
            app_base_addr=8192, app_target_addr=40227528,
            machine_version=0x0602, app_machine_version=0x00060002, proc_candidates=1,
            snapshot_before_status=0, snapshot_end_status=0)
        self.native = dict(patched, phase=6, flags=1021, restored=1, app_restored=1, hold_seconds=615)
        self.observation = dict(self.observed, nonce=bytes(range(16)).hex(), ready=initial,
                                patched=patched, source_is_hardware=hardware)
        self.handoff = dict(plan_sha256=self.plan, body_sha256=self.body, model='ILCE-7M4',
                            patch_observation=self.observation,
                            service_events=[dict(event='STOP_RESPONSE',mode='service',success=True)])
        self.journal.advance('RAM_AWAITING_OPERATOR_RECONNECT', details={
            'window_nonce':self.observation['nonce'],
            'patch_observation_sha256':hashlib.sha256(json.dumps(self.observation,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
            'pending_receipt_sha256':receipt_hash or hashlib.sha256(json.dumps(self.handoff,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()})
        self.collect = Mock(return_value=dict(native=self.native, native_terminal_observed=True,
                                              both_RAM_targets_proven_safe=True))
        def run(expected, work, **kwargs):
            self.calls.append('collection session')
            result = work('fake-authenticated-device')
            self.calls.append('known collection STOP')
            kwargs['record_event']({'event':'STOP_RESPONSE','mode':'service','success':True})
            return result
        self.run = Mock(side_effect=run)
        self.assets = object()

    def invoke_collection(self, **overrides):
        values = dict(plan_sha256=self.plan, journal=self.journal, lease=self.lease,
            collection_authorized=True, firmware_never_started_confirmed=True,
            run_session=self.run, collect_fn=self.collect, assets=self.assets,
            clock=self.clock, sleep=lambda _: None)
        values.update(overrides)
        return session.collect_menu_restoration(self.body, self.evidence, self.handoff, **values)

    def invoke_hardware_collection(self):
        # Mock the default implementation boundaries; public injectable args stay None.
        with patch('camera_stream_usb_session.run_normal_session', self.run), \
                patch('camera_menu_window.collect_authenticated', self.collect):
            return self.invoke_collection(run_session=None, collect_fn=None)

    def test_known_exit_then_specialized_hardware_ram_restoration_record(self):
        self.prepare_collection()
        original = self.journal.record_ram_restoration_verified
        def record(artifact):
            self.assertEqual(self.calls, ['collection session', 'known collection STOP'])
            return original(artifact)
        with patch.object(self.journal, 'record_ram_restoration_verified', side_effect=record) as record_mock:
            result = self.invoke_hardware_collection()
        record_mock.assert_called_once()
        self.assertEqual(self.journal.state, 'RAM_RESTORATION_VERIFIED')
        self.assertEqual(InstallJournal.open(self.journal.session_dir).state, 'RAM_RESTORATION_VERIFIED')
        self.assertEqual(result['scope'], 'VOLATILE_RAM_WINDOW_ONLY')
        self.assertFalse(result['firmware_installation_proven'])
        self.assertEqual((result['module_uploads'], result['START_attempts']), (0, 0))
        self.assertIs(self.collect.call_args.args[2], self.observation)
        self.assertIs(self.collect.call_args.kwargs['assets'], self.assets)
        self.assertTrue(self.collect.call_args.kwargs['body_verified'])
        self.assertTrue(self.collect.call_args.kwargs['firmware_never_started_confirmed'])

    def test_pending_can_close_after_more_than_native_window_duration(self):
        self.prepare_collection(ready=False)
        self.seconds = 10000
        self.invoke_hardware_collection()
        self.assertEqual(self.journal.state, 'RAM_RESTORATION_VERIFIED')

    def test_each_explicit_confirmation_required_before_new_session(self):
        self.prepare_collection()
        before = self.journal.events
        for values in ({'collection_authorized': False}, {'firmware_never_started_confirmed': False}):
            with self.subTest(values=values):
                with self.assertRaisesRegex(ValueError, 'confirmations'):
                    self.invoke_collection(**values)
        self.run.assert_not_called(); self.collect.assert_not_called()
        self.assertEqual(InstallJournal.open(self.journal.session_dir).events, before)

    def test_changed_original_patch_is_rejected_before_collection(self):
        self.prepare_collection()
        before = self.journal.events
        self.observation['conservative_seconds_remaining'] = 999
        with self.assertRaisesRegex(ValueError, 'pending RAM event'):
            self.invoke_collection()
        self.run.assert_not_called(); self.collect.assert_not_called()
        self.assertEqual(self.journal.events, before)

    def test_changed_known_stop_diagnostic_is_rejected_before_collection(self):
        self.prepare_collection()
        before = self.journal.events
        self.handoff['service_events'][0] = dict(event='STOP_RESPONSE',mode='service',known_pipe_response=True)
        session._known_service_exit(self.handoff['service_events'])
        with self.assertRaisesRegex(ValueError, 'pending RAM receipt'):
            self.invoke_hardware_collection()
        self.run.assert_not_called(); self.collect.assert_not_called()
        self.assertEqual(InstallJournal.open(self.journal.session_dir).events, before)

    def test_wrong_pending_receipt_hash_is_rejected_before_collection(self):
        self.prepare_collection(receipt_hash='e'*64)
        before = self.journal.events
        with self.assertRaisesRegex(ValueError, 'pending RAM receipt'):
            self.invoke_hardware_collection()
        self.run.assert_not_called(); self.collect.assert_not_called()
        self.assertEqual(InstallJournal.open(self.journal.session_dir).events, before)

    def test_collection_return_without_stop_evidence_is_unknown(self):
        self.prepare_collection()
        self.run.side_effect = lambda expected, work, **kwargs: work('fake-device')
        with self.assertRaisesRegex(ValueError, 'Known service STOP'):
            self.invoke_collection()
        self.assertEqual(self.journal.state, 'STOPPED_UNKNOWN')
        self.assertFalse((self.evidence/'ram-restoration.json').exists())

    def test_wrong_handoff_binding_is_local_rejection(self):
        self.prepare_collection()
        before = self.journal.events
        self.handoff['body_sha256'] = 'c' * 64
        with self.assertRaisesRegex(ValueError, 'handoff plan/body'): self.invoke_collection()
        self.run.assert_not_called(); self.collect.assert_not_called()
        self.assertEqual(self.journal.events, before)

    def test_flash_history_blocks_collection_without_any_session(self):
        self.prepare_collection()
        with self.assertRaises(ValueError):
            self.journal.advance('FLASH_MAY_HAVE_STARTED')
        self.journal.advance('STOPPED_UNKNOWN')
        before = self.journal.events
        with self.assertRaises(ValueError): self.invoke_collection()
        self.run.assert_not_called(); self.collect.assert_not_called()
        self.assertEqual(self.journal.events, before)

    def test_unknown_stop_does_not_record_restoration_or_issue_more_requests(self):
        self.prepare_collection()
        def run(expected, work, **kwargs):
            work('fake-device')
            raise ConnectionError('unknown STOP')
        self.run.side_effect = run
        with patch.object(self.journal, 'record_ram_restoration_verified') as record:
            with self.assertRaises(ConnectionError): self.invoke_collection()
        record.assert_not_called()
        self.assertEqual(self.journal.state, 'STOPPED_UNKNOWN')
        self.collect.assert_called_once()
        self.assertFalse((self.evidence / 'ram-restoration.json').exists())

    def test_missing_native_record_does_not_infer_restore_or_success_stop(self):
        self.prepare_collection()
        self.collect.side_effect = TimeoutError('old record missing')
        with self.assertRaises(TimeoutError): self.invoke_collection()
        self.assertEqual(self.calls, ['collection session'])
        self.assertEqual(self.journal.state, 'STOPPED_UNKNOWN')
        self.assertFalse((self.evidence / 'ram-restoration.json').exists())

    def test_changed_native_worker_is_rejected_before_success_stop(self):
        self.prepare_collection()
        self.native['pid'] = 999
        with self.assertRaisesRegex(ValueError, 'Bound terminal'): self.invoke_collection()
        self.assertEqual(self.calls, ['collection session'])
        self.assertEqual(self.journal.state, 'STOPPED_UNKNOWN')

    def test_false_safety_assertion_cannot_replace_native_restore_proof(self):
        self.prepare_collection()
        self.native['restore_status'] = -5
        with self.assertRaisesRegex(ValueError, 'Both RAM targets'): self.invoke_collection()
        self.assertEqual(self.calls, ['collection session'])
        self.assertEqual(self.journal.state, 'STOPPED_UNKNOWN')

    def assert_injected_collection_is_model(self, *, session_injected):
        self.prepare_collection(hardware=True)
        with patch('camera_stream_usb_session.run_normal_session', self.run), \
                patch('camera_menu_window.collect_authenticated', self.collect):
            with self.assertRaisesRegex(ValueError, 'hardware'):
                self.invoke_collection(run_session=self.run if session_injected else None,
                                       collect_fn=None if session_injected else self.collect)
        report = json.loads((self.evidence / 'ram-restoration.json').read_text())
        self.assertFalse(report['source_is_hardware'])
        self.assertTrue(self.observation['source_is_hardware'])
        self.assertEqual(self.journal.state, 'STOPPED_UNKNOWN')
        self.assertNotIn('RAM_RESTORATION_VERIFIED', [event['state'] for event in self.journal.events])

    def test_injected_collect_session_cannot_close_hardware_ledger(self):
        self.assert_injected_collection_is_model(session_injected=True)

    def test_injected_collector_cannot_close_hardware_ledger(self):
        self.assert_injected_collection_is_model(session_injected=False)

    def test_other_pending_session_blocks_collection_locally(self):
        self.prepare_collection()
        other = InstallJournal.create(self.evidence.parent / 'other-root', 'other',
            plan_sha256=self.plan, body_sha256=self.body, model='ILCE-7M4')
        other.session_dir.rename(self.journal.session_dir.parent / 'other')
        before = self.journal.events
        with self.assertRaisesRegex(ValueError, 'Another install session'): self.invoke_collection()
        self.assertEqual(self.journal.events, before)
        self.run.assert_not_called(); self.collect.assert_not_called()

    def test_replaced_lease_inode_blocks_collection_without_journal_change(self):
        self.prepare_collection()
        before = self.journal.events
        self.lease.path.rename(self.lease.path.with_name('old-owner.lock'))
        self.lease.path.write_text('replacement')
        with self.assertRaisesRegex(ValueError, 'Live caller lease'): self.invoke_collection()
        self.assertEqual(self.journal.events, before)
        self.run.assert_not_called(); self.collect.assert_not_called()

    def test_model_receipt_remains_model_and_cannot_close_hardware_ledger(self):
        self.prepare_collection(hardware=False)
        with self.assertRaisesRegex(ValueError, 'hardware'): self.invoke_collection()
        report = json.loads((self.evidence / 'ram-restoration.json').read_text())
        self.assertFalse(report['source_is_hardware'])
        self.assertEqual(report['scope'], 'VOLATILE_RAM_WINDOW_ONLY')
        self.assertEqual(self.journal.state, 'STOPPED_UNKNOWN')
        self.assertNotIn('RAM_RESTORATION_VERIFIED', [event['state'] for event in self.journal.events])

    def test_ledger_failure_preserves_original_error_without_extra_device_calls(self):
        self.prepare_collection()
        with patch.object(self.journal, 'record_ram_restoration_verified', side_effect=OSError('ledger fsync')):
            with self.assertRaisesRegex(OSError, 'ledger fsync'): self.invoke_hardware_collection()
        self.collect.assert_called_once()
        self.assertEqual(self.run.call_count, 1)
        self.assertEqual(self.journal.state, 'STOPPED_UNKNOWN')
