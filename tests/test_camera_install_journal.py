"""Temporary host directories only: no SDK, devices, proc, or mounted media."""
import hashlib
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest import mock

import camera_install_journal as ledger


class JournalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.host = Path(self.temp.name)
        self.root = self.host / 'sessions'
        self.binding = dict(plan_sha256='a' * 64, body_sha256='b' * 64, model='synthetic-FL23')
        self.journal = ledger.InstallJournal.create(self.root, 'attempt-1', **self.binding)

    def completed_report(self):
        for phase in ('SD_STAGE_INTENT', 'SD_STAGED', 'RAM_MAY_BE_ACTIVE',
                      'READY_FOR_CONFIRMATION', 'FLASH_MAY_HAVE_STARTED',
                      'DEVICE_COMPLETION_REPORTED'):
            self.journal.advance(phase)
        path = self.host / 'verification.json'
        path.write_text(json.dumps(dict(self.binding, source_is_hardware=True, all_passed=True)))
        return path

    def assert_blocked(self):
        with self.assertRaises(ledger.JournalError):
            ledger.assert_no_pending_installs(self.root)

    def test_complete_with_artifact_is_only_success_terminal(self):
        artifact = self.completed_report()
        self.assert_blocked()  # SDK completion is not content acceptance.
        event = self.journal.record_content_verified(artifact)
        self.assertEqual(event['details']['verification_artifact']['sha256'],
                         hashlib.sha256(artifact.read_bytes()).hexdigest())
        reopened = ledger.InstallJournal.open(self.journal.session_dir)
        self.assertEqual(reopened.state, 'CONTENT_VERIFIED')
        ledger.assert_no_pending_installs(self.root)
        with self.assertRaises(ledger.JournalError):
            reopened.advance('PLANNED')

    def test_cancel_before_device_write_allows_next_session(self):
        self.journal.advance('SD_STAGE_INTENT')
        self.journal.advance('SD_STAGED')
        self.journal.advance('READY_FOR_CONFIRMATION')
        self.journal.advance('CANCELLED_BEFORE_DEVICE_WRITE')
        ledger.assert_no_pending_installs(self.root)
        second = ledger.InstallJournal.create(self.root, 'attempt-2', **self.binding)
        self.assertEqual(second.state, 'PLANNED')

    def test_ram_intent_prevents_cancel_even_without_flash(self):
        for state in ('SD_STAGE_INTENT', 'SD_STAGED', 'RAM_MAY_BE_ACTIVE', 'READY_FOR_CONFIRMATION'):
            self.journal.advance(state)
        with self.assertRaisesRegex(ledger.JournalError, 'possible device write'):
            self.journal.advance('CANCELLED_BEFORE_DEVICE_WRITE')
        self.assert_blocked()

    def test_skip_to_flash_or_success_is_rejected(self):
        for state in ('SD_STAGED', 'READY_FOR_CONFIRMATION', 'FLASH_MAY_HAVE_STARTED',
                      'DEVICE_COMPLETION_REPORTED', 'CONTENT_VERIFIED'):
            with self.subTest(state=state), self.assertRaises(ledger.JournalError):
                self.journal.advance(state)
        self.assertEqual(len(self.journal.events), 1)

    def test_unknown_is_permanently_pending_without_auto_recovery(self):
        self.journal.advance('STOPPED_UNKNOWN', details={'pid_ended': True, 'lock_released': True,
                                                      'elapsed_seconds': 10**10})
        reopened = ledger.InstallJournal.open(self.journal.session_dir)
        for state in ledger.STATES:
            with self.subTest(state=state), self.assertRaises(ledger.JournalError):
                reopened.advance(state)
        self.assert_blocked()

    def test_pending_blocks_new_session_before_creation(self):
        with self.assertRaisesRegex(ledger.JournalError, 'Pending install'):
            ledger.InstallJournal.create(self.root, 'attempt-2', **self.binding)
        self.assertFalse((self.root / 'attempt-2').exists())

    def test_truncated_tampered_and_noncanonical_event_refuse_advance(self):
        path = self.journal.session_dir / '00000001.json'
        original = path.read_bytes()
        changed = json.loads(original)
        changed['details'] = {'tampered': True}
        for damaged in (original[:20], ledger._canonical(changed), original + b'\n'):
            with self.subTest(damaged=damaged[:30]):
                path.write_bytes(damaged)
                self.assert_blocked()
                with self.assertRaises(ledger.JournalError):
                    self.journal.advance('SD_STAGE_INTENT')
        path.write_bytes(original)

    def test_missing_sequence_and_partial_extra_file_block(self):
        self.journal.advance('SD_STAGE_INTENT')
        path = self.journal.session_dir / '00000002.json'
        original = path.read_bytes()
        path.unlink()
        (self.journal.session_dir / '00000003.json').write_bytes(original)
        self.assert_blocked()
        (self.journal.session_dir / '00000003.json').unlink()
        path.write_bytes(b'{')
        self.assert_blocked()

    def test_binding_change_is_rejected_even_with_recomputed_checksum(self):
        self.journal.advance('SD_STAGE_INTENT')
        path = self.journal.session_dir / '00000002.json'
        event = json.loads(path.read_bytes())
        event['binding']['body_sha256'] = 'c' * 64
        event.pop('event_sha256')
        event['event_sha256'] = ledger._sha(ledger._canonical(event))
        path.write_bytes(ledger._canonical(event))
        self.assert_blocked()

    def test_broken_previous_chain_even_with_valid_event_checksum_blocks(self):
        self.journal.advance('SD_STAGE_INTENT')
        path = self.journal.session_dir / '00000002.json'
        event = json.loads(path.read_bytes())
        event['prev_sha256'] = 'd' * 64
        event.pop('event_sha256')
        event['event_sha256'] = ledger._sha(ledger._canonical(event))
        path.write_bytes(ledger._canonical(event))
        self.assert_blocked()

    def test_acceptance_artifact_cannot_skip_phase_boundaries(self):
        artifact = self.host / 'premature-verification.json'
        artifact.write_text(json.dumps(dict(self.binding, source_is_hardware=True, all_passed=True)))
        with self.assertRaisesRegex(ledger.JournalError, 'Invalid phase transition'):
            self.journal.record_content_verified(artifact)
        self.assertEqual(self.journal.state, 'PLANNED')

    def test_stale_snapshot_does_not_silently_follow_other_writer(self):
        stale = ledger.InstallJournal.open(self.journal.session_dir)
        self.journal.advance('SD_STAGE_INTENT')
        with self.assertRaisesRegex(ledger.JournalError, 'Stale'):
            stale.advance('SD_STAGE_INTENT')
        self.assertEqual(len(list(self.journal.session_dir.iterdir())), 2)

    def test_two_instances_race_for_same_sequence_only_one_wins(self):
        other = ledger.InstallJournal.open(self.journal.session_dir)
        barrier = threading.Barrier(2)
        original_open = ledger.os.open
        results = []

        def synchronized_open(path, flags, *args):
            if Path(path).name == '00000002.json' and flags & ledger.os.O_EXCL:
                barrier.wait(timeout=5)
            return original_open(path, flags, *args)

        def append(journal):
            try:
                journal.advance('SD_STAGE_INTENT')
                results.append('ok')
            except FileExistsError:
                results.append('collision')

        with mock.patch.object(ledger.os, 'open', side_effect=synchronized_open):
            threads = [threading.Thread(target=append, args=(item,)) for item in (self.journal, other)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=10)
                self.assertFalse(thread.is_alive())
        self.assertCountEqual(results, ['ok', 'collision'])
        self.assertEqual(ledger.InstallJournal.open(self.journal.session_dir).state, 'SD_STAGE_INTENT')

    def test_wrong_acceptance_binding_source_and_result_rejected(self):
        artifact = self.completed_report()
        original = json.loads(artifact.read_bytes())
        for key, value in [('plan_sha256', 'c' * 64), ('body_sha256', 'c' * 64),
                           ('model', 'other-model'), ('source_is_hardware', False),
                           ('source_is_hardware', 1), ('all_passed', False), ('all_passed', 1)]:
            with self.subTest(key=key, value=value):
                artifact.write_text(json.dumps(dict(original, **{key: value})))
                with self.assertRaises(ledger.JournalError):
                    self.journal.record_content_verified(artifact)
                self.assertEqual(self.journal.state, 'DEVICE_COMPLETION_REPORTED')
        self.assert_blocked()

    def test_artifact_is_revalidated_when_scanning_safe_session(self):
        artifact = self.completed_report()
        self.journal.record_content_verified(artifact)
        artifact.write_text('{}')
        self.assert_blocked()
        artifact.unlink()
        self.assert_blocked()

    def test_empty_session_unexpected_file_and_symlink_block(self):
        self.journal.advance('CANCELLED_BEFORE_DEVICE_WRITE')
        empty = self.root / 'crashed-before-first-record'
        empty.mkdir()
        self.assert_blocked()
        empty.rmdir()
        junk = self.root / 'unexpected'
        junk.write_text('partial attempt')
        self.assert_blocked()
        junk.unlink()
        junk.symlink_to(self.journal.session_dir, target_is_directory=True)
        self.assert_blocked()

    def test_disk_failure_leaves_blocking_record_and_no_action_return(self):
        with mock.patch.object(ledger.os, 'fsync', side_effect=OSError('synthetic disk failure')):
            with self.assertRaisesRegex(OSError, 'synthetic disk failure'):
                self.journal.advance('SD_STAGE_INTENT')
        self.assertEqual(self.journal.state, 'PLANNED')
        self.assert_blocked()
        with self.assertRaises(ledger.JournalError):
            self.journal.advance('SD_STAGE_INTENT')

    def manual_report(self, *, flash=False):
        if flash:
            self.completed_report()
        self.journal.advance('STOPPED_UNKNOWN')
        stopped = self.journal.events[-1]
        report = dict(self.binding, source_is_hardware=True, all_passed=True,
                      session_id=stopped['session_id'], stopped_event_sha256=stopped['event_sha256'],
                      prior_on_device_writer_stopped=True, operator_review_note='Human reviewed synthetic evidence',
                      scope='full-install' if flash else 'ram-only',
                      firmware_flash_was_never_started=True, RAM_original_state_verified=True)
        if flash:
            for field, assertion in (('fresh_readback_artifact', 'fresh_readback'),
                                     ('writer_stopped_artifact', 'on_device_writer_stopped')):
                evidence = self.host / (field + '.json')
                evidence.write_text(json.dumps(dict(report, **{assertion: True})))
                report[field] = dict(path=str(evidence), sha256=hashlib.sha256(evidence.read_bytes()).hexdigest())
        artifact = self.host / 'manual-review.json'
        artifact.write_text(json.dumps(report))
        return artifact, report

    def test_manual_ram_reconciliation_retains_history_and_requires_new_operation(self):
        artifact, _ = self.manual_report()
        before = self.journal.events
        self.journal.record_manual_reconciliation(artifact, explicit_user_approval=True)
        self.assertEqual(self.journal.events[:-1], before)
        self.assertEqual(self.journal.state, 'MANUALLY_RECONCILED_SAFE')
        ledger.assert_no_pending_installs(self.root)
        with self.assertRaises(ledger.JournalError):
            self.journal.advance('RAM_MAY_BE_ACTIVE')
        ledger.InstallJournal.create(self.root, 'fresh-inspection', **self.binding)

    def test_manual_reconciliation_strict_approval_and_no_advance_bypass(self):
        artifact, _ = self.manual_report()
        for approval in (False, None, 1, 'yes'):
            with self.subTest(approval=approval), self.assertRaises(ledger.JournalError):
                self.journal.record_manual_reconciliation(artifact, explicit_user_approval=approval)
        with self.assertRaises(ledger.JournalError):
            self.journal.advance('MANUALLY_RECONCILED_SAFE', details={'explicit_user_approval': True})
        self.assert_blocked()

    def test_manual_reconciliation_refuses_bad_source_scope_identity_and_review(self):
        artifact, original = self.manual_report()
        for key, value in [('source_is_hardware', False), ('all_passed', False),
                           ('body_sha256', 'c' * 64), ('plan_sha256', 'c' * 64), ('model', 'other'),
                           ('scope', 'auto-clear'), ('prior_on_device_writer_stopped', 1),
                           ('operator_review_note', '  '), ('RAM_original_state_verified', False),
                           ('firmware_flash_was_never_started', False), ('session_id', 'other'),
                           ('stopped_event_sha256', 'd' * 64)]:
            with self.subTest(key=key):
                artifact.write_text(json.dumps(dict(original, **{key: value})))
                with self.assertRaises(ledger.JournalError):
                    self.journal.record_manual_reconciliation(artifact, explicit_user_approval=True)
                self.assert_blocked()

    def test_pid_time_and_host_lock_are_insufficient_for_manual_clear(self):
        artifact, report = self.manual_report()
        for key in ('prior_on_device_writer_stopped', 'RAM_original_state_verified',
                    'firmware_flash_was_never_started'):
            report.pop(key)
        report.update(pid_ended=True, elapsed_seconds=10**10, host_lock_released=True)
        artifact.write_text(json.dumps(report))
        with self.assertRaises(ledger.JournalError):
            self.journal.record_manual_reconciliation(artifact, explicit_user_approval=True)
        self.assert_blocked()

    def test_flash_history_refuses_ram_only_scope(self):
        artifact, report = self.manual_report(flash=True)
        report['scope'] = 'ram-only'
        artifact.write_text(json.dumps(report))
        with self.assertRaisesRegex(ledger.JournalError, 'possible flash'):
            self.journal.record_manual_reconciliation(artifact, explicit_user_approval=True)
        self.assert_blocked()

    def test_full_install_reconciliation_is_distinct_from_target_success(self):
        artifact, report = self.manual_report(flash=True)
        # The fresh readback can identify a partial/current state, not necessarily
        # the requested target. Safety to inspect does not claim target success.
        report['target_content_verified'] = False
        artifact.write_text(json.dumps(report))
        self.journal.record_manual_reconciliation(artifact, explicit_user_approval=True)
        self.assertEqual(self.journal.state, 'MANUALLY_RECONCILED_SAFE')
        self.assertNotEqual(self.journal.state, 'CONTENT_VERIFIED')
        ledger.assert_no_pending_installs(self.root)
        nested = Path(report['writer_stopped_artifact']['path'])
        nested.write_text('{}')
        self.assert_blocked()

    def test_full_reconciliation_requires_fresh_readback_and_writer_stop_evidence(self):
        artifact, original = self.manual_report(flash=True)
        for field in ('fresh_readback_artifact', 'writer_stopped_artifact'):
            report = dict(original)
            report.pop(field)
            artifact.write_text(json.dumps(report))
            with self.subTest(field=field), self.assertRaises(ledger.JournalError):
                self.journal.record_manual_reconciliation(artifact, explicit_user_approval=True)
        self.assert_blocked()

    def test_full_reconciliation_rejects_stale_or_nonhardware_nested_evidence(self):
        artifact, original = self.manual_report(flash=True)
        for field, assertion in (('fresh_readback_artifact', 'fresh_readback'),
                                 ('writer_stopped_artifact', 'on_device_writer_stopped')):
            evidence = Path(original[field]['path'])
            good = json.loads(evidence.read_bytes())
            for key, value in ((assertion, False), ('source_is_hardware', False),
                               ('stopped_event_sha256', 'd' * 64), ('body_sha256', 'c' * 64)):
                with self.subTest(field=field, key=key):
                    evidence.write_text(json.dumps(dict(good, **{key: value})))
                    report = dict(original)
                    report[field] = dict(path=str(evidence),
                                         sha256=hashlib.sha256(evidence.read_bytes()).hexdigest())
                    artifact.write_text(json.dumps(report))
                    with self.assertRaises(ledger.JournalError):
                        self.journal.record_manual_reconciliation(artifact, explicit_user_approval=True)
            evidence.write_text(json.dumps(good))
        self.assert_blocked()

    def test_manual_evidence_tamper_reblocks_previously_safe_session(self):
        artifact, _ = self.manual_report()
        self.journal.record_manual_reconciliation(artifact, explicit_user_approval=True)
        ledger.assert_no_pending_installs(self.root)
        artifact.write_text('{}')
        self.assert_blocked()

    def test_manual_reconciliation_only_from_unknown(self):
        report = self.host / 'early-review.json'
        report.write_text(json.dumps(dict(self.binding, source_is_hardware=True, all_passed=True)))
        with self.assertRaisesRegex(ledger.JournalError, 'STOPPED_UNKNOWN'):
            self.journal.record_manual_reconciliation(report, explicit_user_approval=True)

    def ram_report(self, *, ready=False):
        for phase in ('SD_STAGE_INTENT', 'SD_STAGED', 'RAM_MAY_BE_ACTIVE'):
            self.journal.advance(phase)
        if ready:
            self.journal.advance('READY_FOR_CONFIRMATION')
        report = dict(self.binding, source_is_hardware=True, all_passed=True,
                      scope='VOLATILE_RAM_WINDOW_ONLY', both_RAM_targets_proven_safe=True,
                      firmware_flash_was_never_started=True)
        path = self.host / 'ram-restoration.json'
        path.write_text(json.dumps(report))
        return path, report

    def test_install_patch_may_cannot_cancel_flash_ready_or_old_restore(self):
        for phase in ('SD_STAGE_INTENT', 'SD_STAGED', 'INSTALL_PATCH_MAY_BE_ACTIVE'):
            self.journal.advance(phase)
        for state in ('READY_FOR_CONFIRMATION', 'FLASH_MAY_HAVE_STARTED',
                      'CANCELLED_BEFORE_DEVICE_WRITE', 'RAM_MAY_BE_ACTIVE',
                      'RAM_AWAITING_OPERATOR_RECONNECT', 'RAM_RESTORATION_VERIFIED',
                      'INSTALL_PATCH_AWAITING_OPERATOR_RECONNECT'):
            with self.subTest(state=state), self.assertRaises(ledger.JournalError):
                self.journal.advance(state)
        artifact = self.host / 'old-restore.json'
        artifact.write_text(json.dumps(dict(self.binding, source_is_hardware=True, all_passed=True,
            scope='VOLATILE_RAM_WINDOW_ONLY', both_RAM_targets_proven_safe=True,
            firmware_flash_was_never_started=True)))
        with self.assertRaises(ledger.JournalError):
            self.journal.record_ram_restoration_verified(artifact)
        self.assert_blocked()

    def test_install_patch_pending_requires_complete_artifact_endpoint(self):
        for phase in ('SD_STAGE_INTENT', 'SD_STAGED', 'INSTALL_PATCH_MAY_BE_ACTIVE'):
            self.journal.advance(phase)
        artifact = self.host / 'counterfeit-pending.json'
        artifact.write_text(json.dumps(dict(self.binding,
            state='INSTALL_PATCH_AWAITING_OPERATOR_RECONNECT', all_passed=True,
            source_is_hardware=True, service_exit_completed=True)))
        with self.assertRaises(ledger.JournalError):
            self.journal.record_install_patch_awaiting_reconnect(artifact)
        self.assertEqual(self.journal.state, 'INSTALL_PATCH_MAY_BE_ACTIVE')
        self.assert_blocked()

    def test_operator_reconnect_pending_blocks_new_work_cancel_and_flash(self):
        artifact, _ = self.ram_report()
        self.journal.advance('RAM_AWAITING_OPERATOR_RECONNECT')
        self.assertNotIn(self.journal.state, ledger.TERMINAL_SAFE)
        self.assertEqual(ledger.InstallJournal.open(self.journal.session_dir).state,
                         'RAM_AWAITING_OPERATOR_RECONNECT')
        with self.assertRaises(ledger.JournalError):
            ledger.assert_no_pending_installs(self.root)
        for state in ('READY_FOR_CONFIRMATION', 'FLASH_MAY_HAVE_STARTED',
                      'CANCELLED_BEFORE_DEVICE_WRITE', 'RAM_MAY_BE_ACTIVE'):
            with self.subTest(state=state), self.assertRaises(ledger.JournalError):
                self.journal.advance(state)
        with self.assertRaises(ledger.JournalError):
            ledger.InstallJournal.create(self.root, 'another', **self.binding)
        self.journal.record_ram_restoration_verified(artifact)
        ledger.assert_no_pending_installs(self.root)

    def test_operator_reconnect_pending_can_become_unknown(self):
        self.ram_report()
        self.journal.advance('RAM_AWAITING_OPERATOR_RECONNECT')
        self.journal.advance('STOPPED_UNKNOWN')
        with self.assertRaises(ledger.JournalError):
            ledger.assert_no_pending_installs(self.root)

    def test_normal_ram_restoration_closes_without_unknown_or_install_success(self):
        artifact, _ = self.ram_report()
        previous = self.journal.events
        event = self.journal.record_ram_restoration_verified(artifact)
        self.assertEqual(self.journal.state, 'RAM_RESTORATION_VERIFIED')
        self.assertEqual(self.journal.events[:-1], previous)
        self.assertNotIn('STOPPED_UNKNOWN', [e['state'] for e in self.journal.events])
        self.assertNotIn('CONTENT_VERIFIED', [e['state'] for e in self.journal.events])
        self.assertEqual(event['details']['ram_restoration_artifact'], {
            'path': str(artifact.absolute()), 'sha256': hashlib.sha256(artifact.read_bytes()).hexdigest()})
        ledger.assert_no_pending_installs(self.root)
        with self.assertRaises(ledger.JournalError):
            self.journal.advance('READY_FOR_CONFIRMATION')

    def test_ram_restoration_from_ready_is_supported_without_flash(self):
        artifact, _ = self.ram_report(ready=True)
        self.journal.record_ram_restoration_verified(artifact)
        ledger.assert_no_pending_installs(self.root)

    def test_ram_restoration_refuses_wrong_scope_model_source_and_flags(self):
        artifact, original = self.ram_report()
        for key, value in [('scope', 'FIRMWARE_FILES_AND_CRITICAL_SETTINGS'),
                           ('source_is_hardware', False), ('source_is_hardware', 1),
                           ('all_passed', False), ('both_RAM_targets_proven_safe', 1),
                           ('both_RAM_targets_proven_safe', False),
                           ('firmware_flash_was_never_started', False),
                           ('plan_sha256', 'c' * 64), ('body_sha256', 'c' * 64),
                           ('model', 'other-model')]:
            with self.subTest(key=key, value=value):
                artifact.write_text(json.dumps(dict(original, **{key: value})))
                with self.assertRaises(ledger.JournalError):
                    self.journal.record_ram_restoration_verified(artifact)
                self.assertEqual(self.journal.state, 'RAM_MAY_BE_ACTIVE')
                self.assert_blocked()

    def test_ram_restoration_refuses_flash_history_and_unknown(self):
        artifact, _ = self.ram_report(ready=True)
        self.journal.advance('FLASH_MAY_HAVE_STARTED')
        with self.assertRaisesRegex(ledger.JournalError, 'possible flash writes'):
            self.journal.record_ram_restoration_verified(artifact)
        self.journal.advance('STOPPED_UNKNOWN')
        with self.assertRaisesRegex(ledger.JournalError, 'possible flash writes'):
            self.journal.record_ram_restoration_verified(artifact)
        self.assert_blocked()

    def test_ram_restoration_cannot_bypass_method_or_reconcile_unknown(self):
        artifact, _ = self.ram_report()
        with self.assertRaisesRegex(ledger.JournalError, 'record_ram_restoration_verified'):
            self.journal.advance('RAM_RESTORATION_VERIFIED')
        self.journal.advance('STOPPED_UNKNOWN')
        with self.assertRaisesRegex(ledger.JournalError, 'active RAM-only phase'):
            self.journal.record_ram_restoration_verified(artifact)
        self.assert_blocked()

    def test_ram_restoration_evidence_tamper_and_deletion_reblock_scans(self):
        artifact, _ = self.ram_report()
        self.journal.record_ram_restoration_verified(artifact)
        ledger.assert_no_pending_installs(self.root)
        artifact.write_text('{}')
        self.assert_blocked()
        artifact.unlink()
        self.assert_blocked()

    def test_returned_events_cannot_mutate_binding_or_history(self):
        events = self.journal.events
        events[0]['binding']['model'] = 'changed'
        self.assertEqual(self.journal.binding, self.binding)


if __name__ == '__main__':
    unittest.main()
