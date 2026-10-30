"""Local filesystem/journal models only; production flow parsing is substituted."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import camera_install_flow as flow
import camera_install_cancel as inactive
import camera_operation_guard as guard
from camera_device_lease import CameraDeviceLease
from camera_install_journal import InstallJournal
from tools import reconcile_card_activation as tool


class TerminalCardTests(unittest.TestCase):
    def setUp(self):
        self.temp = self.enterContext(tempfile.TemporaryDirectory(dir=flow.ROOT / 'output'))
        self.root = Path(self.temp)
        self.folder = self.root / 'flow'
        for name in ('events', 'steps/runtime', 'steps/stage'):
            (self.folder / name).mkdir(parents=True, exist_ok=True)
        self.mount = self.root / 'model-card'
        self.mount.mkdir()
        self.candidate = b'local model candidate'
        self.original = b'local model original'
        self.digest = hashlib.sha256(self.candidate).hexdigest()
        self.enterContext(patch.object(tool.sd, 'DIGEST', self.digest))
        self.enterContext(patch.object(tool.sd, 'SIZE', len(self.candidate)))
        self.enterContext(patch.object(inactive, 'CANDIDATE_SHA256', self.digest))
        self.enterContext(patch.object(inactive, 'CANDIDATE_BYTES', len(self.candidate)))
        self.staging = self.mount / '.camera-use-staging' / ('fl23-' + self.digest[:16] + '-0123456789abcdef')
        self.staging.mkdir(parents=True)
        self.target = self.staging / 'candidate.staged'
        self.target.write_bytes(self.candidate)
        self.active = self.mount / 'BODYDATA.DAT'
        self.active.write_bytes(self.original)
        self.backup = self.staging / 'original-BODYDATA.DAT'
        self.body = 'b' * 64
        self.volume = dict(body_sha256=self.body, body_matched=True, volume_uuid='MODEL-CARD-UUID',
                           filesystem='exfat', volume_bytes=100000, mount=str(self.mount),
                           device='disk-model1', parent='disk-model', registry_id=17, free_bytes=50000)
        self.journals = self.root / 'journals'
        self.enterContext(patch.object(flow, 'DEFAULT_SESSIONS', self.journals))
        self.enterContext(patch.object(guard, 'DEFAULT_SESSIONS', self.journals))
        self.journal = InstallJournal.create(self.journals, 'card-model', plan_sha256='a' * 64,
                                             body_sha256=self.body, model='ILCE-7M4')
        self.config = dict(body_sha256=self.body, model_fixture_only=False,
                           original_plan_reference=dict(sha256='a' * 64),
                           sources={'camera_install_flow.py': hashlib.sha256((flow.ROOT / 'camera_install_flow.py').read_bytes()).hexdigest()})
        self.config_ref = self.write(self.root / 'config.json', self.config)
        self.header = dict(schema=flow.SCHEMA, injected_execution=False,
                           config_reference=self.config_ref, journal_session=str(self.journal.session_dir))
        self.write(self.folder / 'flow.json', self.header)
        runtime_ref = self.write(self.folder / 'steps/runtime/runtime.json', {'model_test_only': True})
        self.stage = dict(state='STAGED_UNRECOGNIZED_FILE_VERIFIED_NOT_ACTIVATED',
                          source_sha256=self.digest, bytes=len(self.candidate),
                          existing_root_update_unchanged=True, BODYDATA_DAT_created_or_replaced=False,
                          camera_internal_firmware_modified=False, updater_invoked=False,
                          volume_identity=deepcopy(self.volume), target=str(self.target),
                          existing_root_update=dict(exists=True, bytes=len(self.original),
                                                    sha256=hashlib.sha256(self.original).hexdigest()))
        self.stage_ref = self.write(self.folder / 'steps/stage/completed.json', self.stage)
        self.journal.advance('SD_STAGE_INTENT')
        self.journal.advance('SD_STAGED', details=dict(stage_report=self.stage_ref['path'],
                                                      stage_report_sha256=self.stage_ref['sha256']))
        events = []
        for name, artifact in [('runtime', runtime_ref), ('stage', self.stage_ref)]:
            result_ref = self.write(self.folder / 'steps' / name / 'result.json', dict(artifact_reference=artifact))
            flow._append(self.folder, events, name, 'INTENT')
            flow._append(self.folder, events, name, 'COMPLETED', receipt_reference=result_ref)
        flow._append(self.folder, events, 'activate', 'INTENT')
        flow._append(self.folder, events, 'activate', 'UNKNOWN', error_type='OSError', automatic_retry=False)
        intent_volume = deepcopy(self.volume)
        intent_volume['free_bytes'] -= len(self.candidate)
        self.intent = dict(state='CARD_FILENAME_ACTIVATION_INTENT', source=str(self.target),
                           target=str(self.active), backup=str(self.backup),
                           existing_root_update=self.stage['existing_root_update'],
                           volume_identity=intent_volume, updater_invoked=False)
        self.write(self.folder / 'steps/stage/activation-intent.json', self.intent)
        stopped = dict(state='ACTIVATION_STOPPED_UNKNOWN', phase='ORIGINAL_BACKUP_RENAME_MAY_HAVE_OCCURRED',
                        error_type='OSError', updater_invoked=False,
                        candidate=dict(path=str(self.target), exists=True, regular=True, symlink=False),
                        target=dict(path=str(self.active), exists=True, regular=True, symlink=False),
                        backup=dict(path=str(self.backup), exists=False))
        self.write(self.folder / 'steps/stage/activation-stopped.json', stopped)
        self.enterContext(patch.object(flow, '_open', side_effect=self.open_model))
        self.enterContext(patch.object(flow, '_source_only_runtime'))
        self.enterContext(patch.object(tool, 'validate_completed_runtime',
                                      return_value=dict(source_is_hardware=True, receiver_compatible=True)))
        self.enterContext(patch.object(tool, 'CameraDeviceLease',
                                      side_effect=lambda action: CameraDeviceLease(action, lock_path=self.root / 'lease')))
        self.discovery = self.enterContext(patch.object(tool.sd, 'discover', side_effect=lambda: deepcopy(self.volume)))
        self.flow_before = {p.name: p.read_bytes() for p in (self.folder / 'events').iterdir()}
        self.history_before = self.journal.events

    def write(self, path, value):
        path.write_text(json.dumps(value))
        return flow.reference(path)

    def open_model(self, folder):
        if Path(folder) != self.folder:
            raise ValueError('Wrong model flow')
        header = json.loads((self.folder / 'flow.json').read_bytes())
        config = tool.read(header['config_reference'])
        events = [json.loads(p.read_bytes()) for p in sorted((self.folder / 'events').iterdir())]
        return self.folder, header, config, events, InstallJournal.open(header['journal_session'])

    def proposal(self):
        return tool.prepare(self.folder, self.root / 'proposal')

    def approved(self, proposal):
        p = tool.read(proposal)
        return self.write(self.root / 'approval.json', dict(schema=tool.APPROVAL_SCHEMA, scope=tool.SCOPE,
            proposal_reference=proposal, reviewed_sources=p['sources'], source_review_accepted=True,
            termination_authorized=True, operator_never_started_confirmed=True,
            operator_health_confirmed=True, installation_authorized=False,
            statement='MODEL ONLY: terminate this failed card activation; do not resume or update'))

    def run_terminal(self):
        proposal = self.proposal()
        return tool.terminate(proposal, self.approved(proposal), termination_authorized=True)

    def assert_unchanged(self):
        self.assertEqual(InstallJournal.open(self.journal.session_dir).events, self.history_before)
        self.assertEqual({p.name: p.read_bytes() for p in (self.folder / 'events').iterdir()}, self.flow_before)

    def test_prepare_only_seals_local_history_and_source_without_card_discovery(self):
        proposal = self.proposal()
        value = tool.read(proposal)
        self.assertFalse(value['approved'])
        self.assertFalse(value['termination_authorized'])
        self.discovery.assert_not_called()
        self.assert_unchanged()

    def test_valid_model_cancels_journal_only_preserving_UNKNOWN_and_both_card_files(self):
        result = self.run_terminal()
        self.assertEqual(result['state'], 'TERMINAL_CANCELLED_UNKNOWN_FLOW_RETAINED')
        journal = InstallJournal.open(self.journal.session_dir)
        self.assertEqual(journal.state, 'CANCELLED_BEFORE_DEVICE_WRITE')
        self.assertEqual(journal.events[:-1], self.history_before)
        self.assertEqual(self.active.read_bytes(), self.original)
        self.assertEqual(self.target.read_bytes(), self.candidate)
        self.assertFalse(self.backup.exists())
        self.assertEqual({p.name: p.read_bytes() for p in (self.folder / 'events').iterdir()}, self.flow_before)
        proof = tool.read(result['proof_reference'])
        self.assertFalse(proof['native_execution'])
        self.assertFalse(proof['card_observation']['source_is_hardware'])
        self.assertEqual(proof['card_observation']['observer_kind'], 'INJECTED_FILESYSTEM_OBSERVER')
        self.assertFalse(result['activation_completed'])

    def test_approval_missing_or_operator_confirmation_false_never_reads_card(self):
        proposal = self.proposal()
        approval = self.approved(proposal)
        data = tool.read(approval)
        for key in ('source_review_accepted', 'termination_authorized',
                    'operator_never_started_confirmed', 'operator_health_confirmed'):
            with self.subTest(key=key):
                changed = deepcopy(data)
                changed[key] = False
                ref = self.write(self.root / (key + '.json'), changed)
                with self.assertRaises(ValueError):
                    tool.terminate(proposal, ref, termination_authorized=True)
        with self.assertRaises(ValueError):
            tool.terminate(proposal, approval)
        self.discovery.assert_not_called()
        self.assert_unchanged()

    def test_approval_cannot_bind_different_source_or_proposal(self):
        proposal = self.proposal()
        data = tool.read(self.approved(proposal))
        data['reviewed_sources']['tools/reconcile_card_activation.py'] = '0' * 64
        bad = self.write(self.root / 'bad-review.json', data)
        with self.assertRaises(ValueError):
            tool.terminate(proposal, bad, termination_authorized=True)
        self.discovery.assert_not_called()
        self.assert_unchanged()

    def test_injected_flow_rejected_before_any_observer(self):
        self.header['injected_execution'] = True
        self.write(self.folder / 'flow.json', self.header)
        with self.assertRaisesRegex(ValueError, 'Production'):
            self.proposal()
        self.discovery.assert_not_called()
        self.assert_unchanged()

    def test_extra_flow_step_rejects_card_only_scope(self):
        events = self.open_model(self.folder)[3]
        flow._append(self.folder, events, 'patch', 'INTENT')
        with self.assertRaisesRegex(ValueError, 'Only runtime'):
            self.proposal()
        self.discovery.assert_not_called()

    def test_RAM_intent_rejects_card_only_scope_before_observer(self):
        self.journal.advance('RAM_MAY_BE_ACTIVE')
        with self.assertRaisesRegex(ValueError, 'pre-RAM'):
            self.proposal()
        self.discovery.assert_not_called()

    def test_missing_hardware_runtime_provenance_rejected_before_observer(self):
        with patch.object(tool, 'validate_completed_runtime', return_value=dict(source_is_hardware=False, receiver_compatible=True)):
            with self.assertRaisesRegex(ValueError, 'Actual completed runtime'):
                self.proposal()
        self.discovery.assert_not_called()
        self.assert_unchanged()

    def test_existing_backup_proves_no_change_unavailable(self):
        self.backup.write_bytes(self.original)
        with self.assertRaisesRegex(ValueError, 'Backup appeared'):
            self.run_terminal()
        self.assert_unchanged()

    def test_actually_moved_first_rename_cannot_be_terminated_as_no_change(self):
        self.active.rename(self.backup)
        with self.assertRaises(ValueError):
            self.run_terminal()
        self.assert_unchanged()

    def test_same_size_candidate_corruption_rejected(self):
        self.target.write_bytes(b'X' * len(self.candidate))
        with self.assertRaisesRegex(ValueError, 'full readback'):
            self.run_terminal()
        self.assert_unchanged()

    def test_same_size_root_corruption_rejected(self):
        self.active.write_bytes(b'X' * len(self.original))
        with self.assertRaisesRegex(ValueError, 'Root BODYDATA differs'):
            self.run_terminal()
        self.assert_unchanged()

    def test_symlink_candidate_rejected(self):
        other = self.root / 'other'
        other.write_bytes(self.candidate)
        self.target.unlink()
        self.target.symlink_to(other)
        with self.assertRaises(ValueError):
            self.run_terminal()
        self.assert_unchanged()

    def test_backup_appears_after_readback_blocks_terminal_append(self):
        original = tool._final_card_check

        def appeared(*args):
            self.backup.write_bytes(self.original)
            return original(*args)

        with patch.object(tool, '_final_card_check', side_effect=appeared):
            with self.assertRaisesRegex(ValueError, 'Backup appeared'):
                self.run_terminal()
        self.assert_unchanged()

    def test_identical_bytes_with_replaced_inode_after_readback_are_rejected(self):
        original = tool._final_card_check

        def replaced(*args):
            changed = self.root / 'replacement'
            changed.write_bytes(self.original)
            changed.replace(self.active)
            return original(*args)

        with patch.object(tool, '_final_card_check', side_effect=replaced):
            with self.assertRaisesRegex(ValueError, 'file identity changed'):
                self.run_terminal()
        self.assert_unchanged()

    def test_card_handle_drift_during_read_is_rejected(self):
        calls = 0

        def discover():
            nonlocal calls
            calls += 1
            value = deepcopy(self.volume)
            if calls > 1:
                value['registry_id'] += 1
            return value

        self.discovery.side_effect = discover
        with self.assertRaisesRegex(ValueError, 'handles changed'):
            self.run_terminal()
        self.assert_unchanged()

    def test_context_file_changes_after_prepare_rejected_before_read(self):
        proposal = self.proposal()
        approval = self.approved(proposal)
        p = self.folder / 'events/00000006.json'
        p.write_bytes(p.read_bytes() + b' ')
        with self.assertRaisesRegex(ValueError, 'Sealed context'):
            tool.terminate(proposal, approval, termination_authorized=True)
        self.discovery.assert_not_called()
        self.assertEqual(InstallJournal.open(self.journal.session_dir).events, self.history_before)

    def test_terminal_proof_fsync_failure_does_not_append(self):
        proposal = self.proposal()
        approval = self.approved(proposal)
        with patch.object(tool, 'durable_new', side_effect=OSError('proof fsync')):
            with self.assertRaises(OSError):
                tool.terminate(proposal, approval, termination_authorized=True)
        self.assert_unchanged()

    def test_lease_change_before_append_is_rejected(self):
        real = tool._final_card_check

        def changed(*args):
            result = real(*args)
            (self.root / 'lease').write_text('{}')
            return result

        with patch.object(tool, '_final_card_check', side_effect=changed):
            with self.assertRaises(ValueError):
                self.run_terminal()
        self.assert_unchanged()

    def test_append_failure_is_not_retried_and_partial_record_is_retained(self):
        calls = []

        def failed(journal, state, **kwargs):
            calls.append(state)
            (journal.session_dir / '00000004.json').write_bytes(b'{')
            raise OSError('partial journal append')

        with patch.object(InstallJournal, 'advance', new=failed):
            with self.assertRaises(OSError):
                self.run_terminal()
        self.assertEqual(calls, ['CANCELLED_BEFORE_DEVICE_WRITE'])
        self.assertEqual((self.journal.session_dir / '00000004.json').read_bytes(), b'{')
        self.assertEqual({p.name: p.read_bytes() for p in (self.folder / 'events').iterdir()}, self.flow_before)

    def test_completed_terminal_attempt_cannot_be_replayed(self):
        result = self.run_terminal()
        proposal = tool.reference(self.root / 'proposal/proposal.json')
        approval = tool.reference(self.root / 'approval.json')
        count = self.discovery.call_count
        with self.assertRaises(ValueError):
            tool.terminate(proposal, approval, termination_authorized=True)
        self.assertEqual(self.discovery.call_count, count)
        self.assertEqual(len(InstallJournal.open(self.journal.session_dir).events), 4)
        self.assertFalse(result['old_flow_resumable'])

    def test_status_distinguishes_pending_and_terminal_without_card_access(self):
        proposal = self.proposal()
        count = self.discovery.call_count
        self.assertEqual(tool.status(proposal)['state'], 'STILL_UNKNOWN')
        self.assertEqual(self.discovery.call_count, count)
        tool.terminate(proposal, self.approved(proposal), termination_authorized=True)
        count = self.discovery.call_count
        result = tool.status(proposal)
        self.assertTrue(result['termination_recorded'])
        self.assertFalse(result['old_flow_resumable'])
        self.assertEqual(self.discovery.call_count, count)

    def test_damaged_source_snapshot_rejects_before_card_access(self):
        proposal = self.proposal()
        approval = self.approved(proposal)
        (self.root / 'proposal/sources/tools/reconcile_card_activation.py').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'snapshot differs'):
            tool.terminate(proposal, approval, termination_authorized=True)
        self.discovery.assert_not_called()
        self.assert_unchanged()

    def test_append_success_output_failure_is_readable_without_second_append(self):
        proposal = self.proposal()
        approval = self.approved(proposal)
        reference = tool.reference

        def output_failure(path):
            if Path(path).parent == self.folder / 'events' and InstallJournal.open(self.journal.session_dir).state == 'CANCELLED_BEFORE_DEVICE_WRITE':
                raise OSError('post-append output failure')
            return reference(path)

        with patch.object(tool, 'reference', side_effect=output_failure):
            with self.assertRaises(OSError):
                tool.terminate(proposal, approval, termination_authorized=True)
        self.assertEqual(InstallJournal.open(self.journal.session_dir).state, 'CANCELLED_BEFORE_DEVICE_WRITE')
        count = self.discovery.call_count
        self.assertTrue(tool.status(proposal)['termination_recorded'])
        self.assertEqual(self.discovery.call_count, count)
        self.assertEqual(len(InstallJournal.open(self.journal.session_dir).events), 4)


if __name__ == '__main__':
    unittest.main()
