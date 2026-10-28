"""Temporary local ledgers and injected fake sessions only; no device actions."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
from types import ModuleType, SimpleNamespace
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
            return result
        self.run = Mock(side_effect=run)

    def invoke(self, **overrides):
        opts = dict(plan_sha256=self.plan, journal=self.journal, lease=self.lease,
                    ram_authorized=True, run_session=self.run, wait_normal=self.wait,
                    start_fn=self.start, clock=self.clock, sleep=lambda _: None)
        opts.update(overrides)
        return session.run_menu_session(self.body, self.evidence, **opts)

    def assert_no_handoff(self):
        self.assertFalse((self.evidence / 'session-handoff.json').exists())
        self.assertEqual(self.journal.state, 'STOPPED_UNKNOWN')

    def test_success_orders_durable_intent_callback_known_exit_and_normal(self):
        def wait(*args, **kwargs):
            self.assertEqual(self.calls, ['session', 'known STOP'])
            self.seconds = 15
            return self.normal
        self.wait.side_effect = wait
        result = self.invoke()
        self.assertEqual(result['state'], 'VOLATILE_WINDOW_HANDOFF')
        self.assertEqual(result['conservative_seconds_remaining'], 165)
        self.assertFalse(result['installation_authorized'])
        self.assertFalse(result['RAM_original_state_verified'])
        self.assertEqual(self.journal.state, 'READY_FOR_CONFIRMATION')
        self.assertTrue((self.evidence / 'session-handoff.json').exists())
        self.assertTrue(self.start.call_args.kwargs['body_verified'])
        self.assertFalse(self.start.call_args.kwargs['source_is_hardware'])
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

    def test_wrong_normal_body_cannot_handoff(self):
        self.normal['body_sha256'] = 'c' * 64
        with self.assertRaisesRegex(ValueError, 'Same-body'): self.invoke()
        self.assert_no_handoff()

    def test_time_after_patch_observation_in_exit_and_normal_wait_is_deducted(self):
        self.wait.side_effect = lambda *a, **kw: setattr(self, 'seconds', 91) or self.normal
        with self.assertRaisesRegex(ValueError, 'Insufficient conservative window'): self.invoke()
        self.assert_no_handoff()

    def test_slow_capture_and_maps_wait_are_not_deducted_twice(self):
        # Capture took 180s before native START; maps wait consumed 300 of its 600s.
        def start(*args, **kwargs):
            self.seconds = 480
            return dict(self.observed, conservative_seconds_remaining=300)
        def wait(*args, **kwargs):
            self.seconds = 490  # Known STOP plus normal reappearance cost another 10s.
            return self.normal
        self.start.side_effect = start
        self.wait.side_effect = wait
        result = self.invoke()
        self.assertEqual(result['conservative_seconds_remaining'], 290)
        self.assertEqual(result['post_observation_elapsed_seconds'], 10)
        self.assertEqual(result['patch_observed_monotonic'], 480)
        self.assertEqual(result['budget_basis'], 'patch_report_remaining_minus_post_observation_elapsed')
        self.assertFalse(result['timer_is_independent_watchdog'])

    def test_clock_regression_after_patch_rejects_handoff(self):
        self.start.side_effect = lambda *a, **kw: setattr(self, 'seconds', 100) or self.observed
        self.wait.side_effect = lambda *a, **kw: setattr(self, 'seconds', 99) or self.normal
        with self.assertRaisesRegex(ValueError, 'Monotonic clock regressed'): self.invoke()
        self.assert_no_handoff()

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
                run_session=self.run, start_fn=self.start, wait_normal=self.wait)
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
        values = dict(run_session=None, start_fn=None, wait_normal=None)
        values[argument] = {'run_session': self.run, 'start_fn': self.start, 'wait_normal': self.wait}[argument]
        with patch('camera_stream_usb_session.run_normal_session', self.run), \
                patch('camera_menu_window.start_authenticated', self.start), \
                patch.object(session, 'wait_for_normal', self.wait):
            result = self.invoke(**values)
        self.assertFalse(result['source_is_hardware'])
        self.assertFalse(result['patch_observation']['source_is_hardware'])
        self.assertTrue(self.observed['source_is_hardware'])  # Caller object was not mutated.

    def test_injected_start_alone_forces_model_provenance(self):
        self.assert_single_injection_is_model('start_fn')

    def test_injected_wait_alone_forces_model_provenance(self):
        self.assert_single_injection_is_model('wait_normal')

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


class NormalDetectionTests(unittest.TestCase):
    def setUp(self):
        self.serial = 'offline-reference'
        self.body = hashlib.sha256(self.serial.encode()).hexdigest()
        class Driver:
            def getId(self): return (0x054c, 0x0da5)
        class Normal: pass
        self.driver = Driver()
        self.driver.backend = SimpleNamespace(dev=SimpleNamespace(default_timeout=5000, serial_number=self.serial))
        self.device = Normal(); self.device.driver = self.driver
        self.info = Mock(return_value=SimpleNamespace(modelName='ILCE-7M4'))
        @contextlib.contextmanager
        def import_driver(name):
            print('SDK secret', file=sys.stderr)
            yield object()
        commands, sony, generic = (ModuleType(n) for n in ('pmca.commands.usb', 'pmca.usb.sony', 'pmca.usb.driver.generic'))
        self.enumerate = Mock(return_value=[self.device])
        commands.importDriver, commands.listDevices = import_driver, self.enumerate
        sony.SonyMscExtCmdDevice = Normal
        sony.SonyExtCmdCamera = lambda dev: SimpleNamespace(getCameraInfo=self.info)
        generic.GenericUsbDriver = Driver
        self.stack = contextlib.ExitStack(); self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.dict(sys.modules, {'pmca.commands.usb': commands,
            'pmca.usb.sony': sony, 'pmca.usb.driver.generic': generic}))
        self.original_path = sys.path[:]
        self.addCleanup(lambda: sys.path.__setitem__(slice(None), self.original_path))

    def test_only_readonly_normal_info_is_used_and_sdk_logs_suppressed(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            proof = session._probe_normal(self.body)
        self.assertEqual(out.getvalue(), '')
        self.assertTrue(proof['body_matched'])
        self.info.assert_called_once_with()
        self.enumerate.assert_called_once()

    def test_wrong_serial_is_rejected(self):
        self.driver.backend.dev.serial_number = 'wrong-body'
        with self.assertRaisesRegex(ValueError, 'body mismatch'): session._probe_normal(self.body)

    def test_wrong_model_is_rejected(self):
        self.info.return_value.modelName = 'ILCE-OTHER'
        with self.assertRaisesRegex(ValueError, 'model changed'): session._probe_normal(self.body)

    def test_wrong_pid_is_rejected_before_camera_info(self):
        self.driver.getId = lambda: (0x054c, 0x0336)
        with self.assertRaisesRegex(ValueError, 'Unsupported normal USB path'): session._probe_normal(self.body)
        self.info.assert_not_called()

    def test_invalid_reference_hash_is_rejected_before_enumeration(self):
        with self.assertRaisesRegex(ValueError, 'SHA-256'): session._probe_normal('invalid')
        self.enumerate.assert_not_called()

    def test_infinite_or_invalid_driver_timeout_is_rejected(self):
        for value in (None, 0, float('inf'), 6000):
            with self.subTest(timeout=value):
                self.driver.backend.dev.default_timeout = value
                with self.assertRaisesRegex(ValueError, 'Finite normal'): session._probe_normal(self.body)
        self.info.assert_not_called()

    def test_ambiguous_devices_rejected(self):
        self.enumerate.return_value = [self.device, self.device]
        with self.assertRaisesRegex(ValueError, 'Ambiguous'): session._probe_normal(self.body)

    def test_absence_times_out_without_recovery(self):
        ticks = iter([0, 0, 31])
        with patch.object(session, '_probe_normal', return_value=None) as probe:
            with self.assertRaises(TimeoutError):
                session.wait_for_normal(self.body, clock=lambda: next(ticks), sleep=lambda _: None)
        probe.assert_called_once_with(self.body)


class RestorationCollectionTests(unittest.TestCase):
    setUp = OrchestrationTests.setUp

    def prepare_collection(self, *, ready=True, hardware=True):
        import camera_menu_window as menu
        self.journal.advance('RAM_MAY_BE_ACTIVE')
        if ready:
            self.journal.advance('READY_FOR_CONFIRMATION')
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
                            patch_observation=self.observation)
        self.collect = Mock(return_value=dict(native=self.native, native_terminal_observed=True,
                                              both_RAM_targets_proven_safe=True))
        def run(expected, work, **kwargs):
            self.calls.append('collection session')
            result = work('fake-authenticated-device')
            self.calls.append('known collection STOP')
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

    def test_ram_may_be_active_can_close_with_actual_receipt(self):
        self.prepare_collection(ready=False)
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

    def test_wrong_handoff_binding_is_local_rejection(self):
        self.prepare_collection()
        before = self.journal.events
        self.handoff['body_sha256'] = 'c' * 64
        with self.assertRaisesRegex(ValueError, 'handoff plan/body'): self.invoke_collection()
        self.run.assert_not_called(); self.collect.assert_not_called()
        self.assertEqual(self.journal.events, before)

    def test_flash_history_blocks_collection_without_any_session(self):
        self.prepare_collection()
        self.journal.advance('FLASH_MAY_HAVE_STARTED')
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
