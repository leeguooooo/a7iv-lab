"""One-shot install preparation on temporary files and injected callbacks only."""
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

from camera_device_lease import CameraDeviceLease
from camera_install_journal import InstallJournal, JournalError, assert_no_pending_installs
import camera_install_volatile as contract
import camera_install_patch_session as session


def records():
    nonce = bytes(range(16))
    ready = dict.fromkeys(contract.FIELDS, 0)
    ready.update(version=2, phase=1, pid=234, ppid=1, loader_pid=123, flags=13,
                 snapshot_before_status=-11, snapshot_end_status=-11)
    for name in contract.SNAPSHOT_FIELDS:
        ready[name] = -1
    patched = ready | dict(phase=5, flags=765, maps_bytes=136, app_maps_bytes=120, polls=1,
        base_addr=0x40000000, target_addr=0x40000000 + 8016, machine_version=0x602, patched=1,
        app_pid=456, app_base_addr=0x50000000, app_target_addr=0x50000000 + 40219336,
        app_machine_version=0x60002, app_patched=1, app_write_attempted=1,
        proc_candidates=1, identity_checks=6, snapshot_before_status=0, snapshot_end_status=0)
    patched.update({name: 0 for name in contract.SNAPSHOT_FIELDS})
    terminal = patched | dict(phase=7, identity_checks=8)
    raw = {name: contract.FRAME.pack(contract.MAGIC, nonce, *(row[k] for k in contract.FIELDS)).hex()
           for name, row in (('ready', ready), ('patched', patched), ('result', terminal))}
    return nonce.hex(), raw


class InstallPatchSessionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.evidence = self.root / 'evidence'
        self.evidence.mkdir()
        self.body = 'b' * 64
        repository = session.ROOT
        workspace = self.root / 'source-fixture'
        for name in session.REQUIRED_SOURCES:
            path = workspace / name
            path.parent.mkdir(parents=True, exist_ok=True)
            original = repository / name
            path.write_bytes(original.read_bytes() if original.is_file() else b'# Offline fixture source.\n')
        sdk = workspace / 'Sony-PMCA-RE/pmca/__init__.py'
        sdk.parent.mkdir(parents=True)
        sdk.write_text('')
        self.enterContext(patch.object(session, 'ROOT', workspace))
        nonce, self.raw = records()
        self.reference = dict(schema='camera-install-patch-assets/1', patch=dict(
            directory=str(self.root / 'patch-assets'), manifest_sha256='1' * 64,
            module_sha256='2' * 64, native_model_sha256='3' * 64, bootstrap_model_sha256='4' * 64,
            nonce=nonce, job_dir='/tmp_wbshd/m4ivp_' + nonce), captures=dict(
            directory=str(self.root / 'capture-assets'),
            pre_app=dict(manifest_sha256='5' * 64, module_sha256='6' * 64, nonce='8' * 32),
            pre_ufp=dict(manifest_sha256='7' * 64, module_sha256='9' * 64, nonce='a' * 32)))
        self.prepared = types.SimpleNamespace(reference=self.reference, manifest={'sources': {}})
        self.review = self.root / 'review.json'
        review = dict(schema=session.REVIEW_SCHEMA, scope=session.CONSENT_SCOPE, model='ILCE-7M4',
            body_sha256=self.body, asset_reference=self.reference, installation_authorized=False,
            hardware_admission_proven=False, flash_authorized=False, source_only_runtime=session.SOURCE_ONLY_RUNTIME,
            sources={name: hashlib.sha256((session.ROOT / name).read_bytes()).hexdigest()
                     for name in session.review_source_paths(self.prepared)})
        reference = self.root / 'historical-body.json'
        reference.write_text(json.dumps(dict(body=dict(model='ILCE-7M4', usb_serial_sha256=self.body))))
        snapshots = self.root / 'sources'
        snapshots.mkdir()
        for name in review['sources']:
            target = snapshots / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((session.ROOT / name).read_bytes())
        review.update(body_reference=dict(path=str(reference),
            sha256=hashlib.sha256(reference.read_bytes()).hexdigest(), historical_only=True),
            source_snapshot_directory=str(snapshots), execution_approval_received=False, hardware_operations=0)
        self.review.write_text(json.dumps(review))
        self.plan = hashlib.sha256(self.review.read_bytes()).hexdigest()
        self.journal = InstallJournal.create(self.root / 'sessions', 'attempt',
            plan_sha256=self.plan, body_sha256=self.body, model='ILCE-7M4')
        self.journal.advance('SD_STAGE_INTENT')
        self.journal.advance('SD_STAGED')
        self.lease = self.enterContext(CameraDeviceLease('offline-install-patch',
                                                       lock_path=self.root / 'fixture.lock'))
        self.enterContext(patch.object(session, 'GLOBAL_SESSIONS', self.root / 'global-sessions'))
        self.preflight = Mock(return_value=self.prepared)
        self.reservation = dict(schema='synthetic-reservation', nonce=nonce, lease_instance=self.lease.metadata['instance'])
        self.reserve = Mock(return_value=self.reservation)
        self.observed = dict(state='VOLATILE_PATCH_APPLIED_NOT_RESTORED', nonce=nonce, loader_pid=123,
            raw_publications=self.raw, asset_reference=self.reference, reservation=self.reservation,
            source_is_hardware=True, installation_authorized=False, device_execution_proven=True,
            plan_sha256=self.plan, body_sha256=self.body, model='ILCE-7M4',
            scope=session.CONSENT_SCOPE, service_exit_completed=False)
        self.start = Mock(return_value=self.observed)
        self.calls = []
        def run(expected, work, **kwargs):
            self.assertEqual(self.journal.state, session.MAY_STATE)
            self.assertEqual(InstallJournal.open(self.journal.session_dir).state, session.MAY_STATE)
            self.calls.append('entry')
            result = work('synthetic-authenticated-device')
            persisted = json.loads((self.evidence / 'install-patch-terminal.json').read_text())
            self.assertEqual(persisted['native_receipt']['raw_publications'], self.raw)
            self.calls.append('STOP')
            kwargs['record_event'](dict(event='STOP_RESPONSE', mode='service', success=True))
            return result
        self.run = Mock(side_effect=run)

    def invoke(self, **kwargs):
        values = dict(plan_sha256=self.plan, review_path=self.review, journal=self.journal, lease=self.lease,
            volatile_patch_authorized=True, formal_preparation_authorized=True,
            patches_remain_acknowledged=True, assets=object(), capture_assets=object(),
            preflight_fn=self.preflight, reserve_fn=self.reserve, run_session=self.run, start_fn=self.start)
        values.update(kwargs)
        return session.run_install_patch_session(self.body, self.evidence, **values)

    def test_full_receipt_is_durable_before_known_stop_and_pending_never_ready(self):
        result = self.invoke()
        self.assertEqual(self.calls, ['entry', 'STOP'])
        self.assertEqual(result['state'], session.PENDING_STATE)
        self.assertEqual(self.journal.state, session.PENDING_STATE)
        self.assertEqual(InstallJournal.open(self.journal.session_dir).state, session.PENDING_STATE)
        self.assertEqual(result['native_receipt']['raw_publications'], self.raw)
        self.assertFalse(result['source_is_hardware'])
        self.assertFalse(result['native_receipt']['source_is_hardware'])
        self.assertFalse(result['native_receipt']['device_execution_proven'])
        for key in ('installation_authorized', 'firmware_installation_proven',
                    'RAM_restoration_proven', 'normal_body_reappearance_verified'):
            self.assertFalse(result[key])
        for state in ('READY_FOR_CONFIRMATION', 'FLASH_MAY_HAVE_STARTED', 'RAM_MAY_BE_ACTIVE',
                      'RAM_RESTORATION_VERIFIED', 'CANCELLED_BEFORE_DEVICE_WRITE'):
            with self.subTest(state=state), self.assertRaises(JournalError):
                self.journal.advance(state)
        with self.assertRaises(JournalError):
            assert_no_pending_installs(self.journal.session_dir.parent)
        with self.assertRaises(JournalError):
            InstallJournal.create(self.journal.session_dir.parent, 'another', **self.journal.binding)

    def test_preflight_and_reservation_happen_before_auth_in_correct_states(self):
        def preflight(*args):
            self.assertEqual(self.journal.state, 'SD_STAGED')
            self.calls.append('preflight')
            return self.prepared
        def reserve(*args, **kwargs):
            self.assertEqual(self.journal.state, session.MAY_STATE)
            self.calls.append('reserve')
            return self.reservation
        self.preflight.side_effect, self.reserve.side_effect = preflight, reserve
        self.invoke()
        self.assertEqual(self.calls, ['preflight', 'reserve', 'entry', 'STOP'])

    def test_each_consent_is_required_before_intent(self):
        for field in ('volatile_patch_authorized', 'formal_preparation_authorized', 'patches_remain_acknowledged'):
            with self.subTest(field=field):
                before = self.journal.events
                with self.assertRaises(ValueError):
                    self.invoke(**{field: False})
                self.assertEqual(self.journal.events, before)
                self.run.assert_not_called()
                self.reserve.assert_not_called()

    def test_stale_code_review_and_used_assets_fail_before_intent(self):
        for failure in ('review', 'used-assets'):
            with self.subTest(failure=failure):
                self.evidence = self.root / ('evidence-' + failure)
                self.evidence.mkdir()
                before = self.journal.events
                if failure == 'review':
                    options = dict(plan_sha256='c' * 64)
                else:
                    options = {}
                    self.preflight.side_effect = ValueError('capture nonce already claimed')
                with self.assertRaises(ValueError):
                    self.invoke(**options)
                self.assertEqual(self.journal.events, before)
                self.run.assert_not_called()
                self.reserve.assert_not_called()

    def test_local_review_source_tamper_and_asset_mismatch_fail_before_intent(self):
        original = json.loads(self.review.read_text())
        for changed in (original | dict(asset_reference={}), original | dict(sources={}),
                        original | dict(scope='FULL_FIRMWARE_INSTALL')):
            self.review.write_text(json.dumps(changed))
            new_plan = hashlib.sha256(self.review.read_bytes()).hexdigest()
            before = self.journal.events
            with self.assertRaises(ValueError):
                session.validate_review(self.review, new_plan, self.body, self.prepared)
            self.assertEqual(self.journal.events, before)
        self.run.assert_not_called()

    def test_other_global_pending_ledger_blocks_before_intent(self):
        InstallJournal.create(session.GLOBAL_SESSIONS, 'global-other', **self.journal.binding)
        before = self.journal.events
        with self.assertRaises(JournalError):
            self.invoke()
        self.assertEqual(self.journal.events, before)
        self.run.assert_not_called()

    def test_stale_journal_and_released_or_replaced_lease_fail_before_io(self):
        stale = InstallJournal.open(self.journal.session_dir)
        self.journal.advance('STOPPED_UNKNOWN')
        with self.assertRaises((ValueError, JournalError)):
            self.invoke(journal=stale)
        self.run.assert_not_called()
        self.lease.metadata['state'] = 'RELEASED'
        with self.assertRaises(ValueError):
            self.invoke()
        self.run.assert_not_called()

    def test_reopened_same_inode_without_ownership_is_rejected(self):
        os.close(self.lease.fd)
        replacement = os.open(self.lease.path, os.O_RDWR)
        self.lease.fd = replacement
        with self.assertRaisesRegex(ValueError, 'lease lock'):
            self.invoke()
        self.run.assert_not_called()

    def test_source_and_snapshot_bytes_are_checked_not_passed_flags(self):
        for index, path in enumerate((session.ROOT / 'camera_install_patch.py',
                                      self.root / 'sources/camera_install_patch_session.py')):
            with self.subTest(path=path):
                self.evidence = self.root / ('source-check-' + str(index))
                self.evidence.mkdir()
                original = path.read_bytes()
                path.write_bytes(original + b'\n')
                with self.assertRaisesRegex(ValueError, 'changed'):
                    self.invoke()
                path.write_bytes(original)
                self.assertEqual(self.journal.state, 'SD_STAGED')
                self.run.assert_not_called()
                self.reserve.assert_not_called()

    def test_reservation_failure_consumes_no_auth_and_preserves_unknown_intent(self):
        self.reserve.side_effect = OSError('local claim persistence unknown')
        with self.assertRaises(OSError):
            self.invoke()
        self.run.assert_not_called()
        self.start.assert_not_called()
        self.assertEqual(self.journal.state, 'STOPPED_UNKNOWN')

    def test_intent_persistence_failure_never_enters_a_session(self):
        original = self.journal.advance
        def advance(state, **kwargs):
            if state == session.MAY_STATE:
                raise OSError('intent fsync failed')
            return original(state, **kwargs)
        with patch.object(self.journal, 'advance', side_effect=advance):
            with self.assertRaises(OSError):
                self.invoke()
        self.assertEqual(self.journal.state, 'STOPPED_UNKNOWN')
        self.run.assert_not_called()
        self.reserve.assert_not_called()

    def test_partial_intent_fsync_failure_preserves_blocking_file_without_auth(self):
        import camera_install_journal as ledger
        target = self.journal.session_dir / '00000004.json'
        original = ledger.os.fsync
        def fail_intent_fsync(fd):
            if target.exists() and os.fstat(fd).st_ino == target.stat().st_ino:
                os.ftruncate(fd, 17)
                raise OSError('partial intent fsync outcome unknown')
            return original(fd)
        with patch.object(ledger.os, 'fsync', side_effect=fail_intent_fsync):
            with self.assertRaisesRegex(OSError, 'partial intent'):
                self.invoke()
        self.assertEqual(len(target.read_bytes()), 17)
        self.run.assert_not_called()
        self.reserve.assert_not_called()
        report = json.loads((self.evidence / 'install-patch-stopped.json').read_text())
        self.assertEqual(report['state'], 'STOPPED_UNKNOWN')
        self.assertTrue(report['intent_persistence_attempted'])
        self.assertTrue(report['journal_may_have_partial_intent'])
        self.assertFalse(report['device_session_started'])
        with self.assertRaises(JournalError):
            InstallJournal.open(self.journal.session_dir)
        with self.assertRaises(JournalError):
            assert_no_pending_installs(self.journal.session_dir.parent)

    def test_replaced_inode_or_reused_descriptor_is_not_a_held_lease(self):
        os.unlink(self.lease.path)
        self.lease.path.write_text('{}')
        with self.assertRaises(ValueError):
            self.invoke()
        self.run.assert_not_called()

    def test_bad_or_incomplete_native_bytes_never_trigger_success_stop(self):
        self.observed['raw_publications'] = {}
        with self.assertRaises(ValueError):
            self.invoke()
        self.assertEqual(self.calls, ['entry'])
        self.assertEqual(self.journal.state, 'STOPPED_UNKNOWN')

    def test_native_receipt_for_another_body_or_plan_cannot_reach_stop(self):
        self.observed['body_sha256'] = 'd' * 64
        with self.assertRaisesRegex(ValueError, 'Bound complete native receipt'):
            self.invoke()
        self.assertEqual(self.calls, ['entry'])
        self.assertEqual(self.journal.state, 'STOPPED_UNKNOWN')

    def test_terminal_persistence_failure_prevents_stop(self):
        original = session.durable_new
        def persist(path, value):
            if Path(path).name == 'install-patch-terminal.json':
                raise OSError('synthetic terminal fsync failure')
            return original(path, value)
        with patch.object(session, 'durable_new', side_effect=persist):
            with self.assertRaises(OSError):
                self.invoke()
        self.assertEqual(self.calls, ['entry'])
        self.assertEqual(self.journal.state, 'STOPPED_UNKNOWN')

    def test_unknown_entry_and_start_do_not_request_success_stop(self):
        self.run.side_effect = ConnectionError('authentication outcome unknown')
        with self.assertRaises(ConnectionError):
            self.invoke()
        self.start.assert_not_called()
        self.assertEqual(self.journal.state, 'STOPPED_UNKNOWN')
        self.assertFalse((self.evidence / 'install-patch-terminal.json').exists())

    def test_unknown_start_never_returns_work_to_success_stop(self):
        self.start.side_effect = TimeoutError('START outcome unknown')
        with self.assertRaises(TimeoutError):
            self.invoke()
        self.assertEqual(self.calls, ['entry'])
        self.assertEqual(self.journal.state, 'STOPPED_UNKNOWN')
        self.assertFalse((self.evidence / 'install-patch-terminal.json').exists())

    def test_old_restore_collector_is_blocked_in_new_pending_state(self):
        self.invoke()
        from camera_menu_session import collect_menu_restoration
        run = Mock()
        with self.assertRaises(ValueError):
            collect_menu_restoration(self.body, self.root / 'old-restore', {}, plan_sha256=self.plan,
                journal=self.journal, lease=self.lease, collection_authorized=True,
                firmware_never_started_confirmed=True, run_session=run, collect_fn=Mock())
        run.assert_not_called()
        self.assertEqual(self.journal.state, session.PENDING_STATE)

    def test_unknown_stop_retains_durable_bytes_and_appends_unknown(self):
        def run(expected, work, **kwargs):
            work('synthetic-device')
            raise ConnectionError('STOP outcome unknown')
        self.run.side_effect = run
        with self.assertRaises(ConnectionError):
            self.invoke()
        self.assertTrue((self.evidence / 'install-patch-terminal.json').is_file())
        self.assertEqual(self.journal.state, 'STOPPED_UNKNOWN')
        self.assertFalse((self.evidence / 'install-patch-awaiting-reconnect.json').exists())

    def test_receipt_mutation_blocks_journal_reopen_and_new_session(self):
        self.invoke()
        path = self.evidence / 'install-patch-awaiting-reconnect.json'
        value = json.loads(path.read_text())
        value['native_receipt']['raw_publications']['result'] = '00'
        path.write_text(json.dumps(value))
        with self.assertRaises(JournalError):
            InstallJournal.open(self.journal.session_dir)
        self.run.reset_mock()
        with self.assertRaises((JournalError, ValueError)):
            self.invoke()
        self.run.assert_not_called()

    def test_default_real_path_rejects_non_global_lease_and_journal_before_intent(self):
        before = self.journal.events
        with self.assertRaisesRegex(ValueError, 'global journal and device lease'):
            self.invoke(preflight_fn=None, reserve_fn=None, run_session=None, start_fn=None)
        self.assertEqual(self.journal.events, before)
        self.start.assert_not_called()

    def test_source_only_startup_requires_flags_and_an_absent_cache_prefix(self):
        prefix = session.ROOT / session.SOURCE_ONLY_RUNTIME['pycache_prefix']
        flags = types.SimpleNamespace(ignore_environment=1, no_user_site=1)
        with patch.object(session.sys, 'dont_write_bytecode', True), \
             patch.object(session.sys, 'flags', flags), \
             patch.object(session.sys, 'pycache_prefix', str(prefix)):
            session._source_only_runtime()
            flags.ignore_environment = 0
            with self.assertRaisesRegex(ValueError, 'Source-only'):
                session._source_only_runtime()
            flags.ignore_environment = 1
            prefix.mkdir(parents=True)
            with self.assertRaisesRegex(ValueError, 'Source-only'):
                session._source_only_runtime()

    def test_injected_callbacks_cannot_enter_default_real_session(self):
        with self.assertRaisesRegex(ValueError, 'Injected.*session'):
            self.invoke(run_session=None)
        self.start.assert_not_called()
