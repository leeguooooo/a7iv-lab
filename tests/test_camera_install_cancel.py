"""Cancellation evidence from temporary files and synthetic current-word frames."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import camera_install_cancel as cancel


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class InactiveCardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.mount = self.root / 'card'
        self.mount.mkdir()
        self.payload, self.original = b'candidate fixture', b'official fixture'
        self.enterContext(patch.object(cancel, 'CANDIDATE_SHA256', sha(self.payload)))
        self.enterContext(patch.object(cancel, 'CANDIDATE_BYTES', len(self.payload)))
        self.relative = Path('.camera-use-staging') / ('fl23-' + sha(self.payload)[:16] + '-0123456789abcdef') / 'candidate.staged'
        self.candidate = self.mount / self.relative
        self.candidate.parent.mkdir(parents=True)
        self.candidate.write_bytes(self.payload)
        self.body = 'b' * 64
        self.root_update = self.mount / 'BODYDATA.DAT'
        self.root_update.write_bytes(self.original)
        self.volume = dict(body_sha256=self.body, body_matched=True, volume_uuid='fixture-uuid',
            filesystem='exfat', volume_bytes=8 << 30, device='disk9s1', parent='disk9',
            mount=str(self.mount), registry_id=9)
        self.stage = dict(state='STAGED_UNRECOGNIZED_FILE_VERIFIED_NOT_ACTIVATED',
            target=str(self.candidate), source_sha256=sha(self.payload), bytes=len(self.payload),
            volume_identity=copy.deepcopy(self.volume), existing_root_update_unchanged=True,
            BODYDATA_DAT_created_or_replaced=False, camera_internal_firmware_modified=False,
            updater_invoked=False, existing_root_update=dict(exists=True, bytes=len(self.original), sha256=sha(self.original)))
        self.stage_path = self.root / 'stage-completed.json'
        self.write_stage()
        self.discover = Mock(side_effect=lambda: copy.deepcopy(self.volume))

    def write_stage(self):
        raw = json.dumps(self.stage).encode()
        self.stage_path.write_bytes(raw)
        self.reference = dict(path=str(self.stage_path), sha256=sha(raw))

    def observe(self):
        return cancel.observe_inactive_card(self.reference, body_sha256=self.body, discover=self.discover)

    def test_remounted_same_card_is_read_without_any_mutation(self):
        new = self.root / 'remounted'
        self.mount.rename(new)
        self.mount = new
        self.candidate, self.root_update = new / self.relative, new / 'BODYDATA.DAT'
        self.volume.update(mount=str(new), device='disk11s1', parent='disk11', registry_id=11)
        result = self.observe()
        self.assertEqual(result['candidate']['sha256'], sha(self.payload))
        self.assertEqual(result['root_update']['sha256'], sha(self.original))
        self.assertEqual(self.candidate.read_bytes(), self.payload)
        self.assertEqual(self.root_update.read_bytes(), self.original)
        self.assertFalse(result['source_is_hardware'])
        self.assertFalse(result['explicit_card_writes'])
        self.assertEqual(self.discover.call_count, 4)

    def test_absent_original_root_must_stay_absent(self):
        self.root_update.unlink()
        self.stage['existing_root_update'] = dict(exists=False)
        self.write_stage()
        result = self.observe()
        self.assertFalse(result['root_update']['exists'])
        self.root_update.write_bytes(self.original)
        with self.assertRaisesRegex(ValueError, 'appeared'):
            self.observe()

    def test_active_candidate_is_not_withdrawn_or_accepted(self):
        self.root_update.write_bytes(self.payload)
        with self.assertRaisesRegex(ValueError, 'size differs|Root BODYDATA differs'):
            self.observe()
        self.assertEqual(self.root_update.read_bytes(), self.payload)
        self.assertEqual(self.candidate.read_bytes(), self.payload)

    def test_missing_or_changed_candidate_and_original_baseline_are_refused(self):
        for path, raw in ((self.candidate, b'x' * len(self.payload)), (self.root_update, b'x' * len(self.original))):
            with self.subTest(path=path):
                original = path.read_bytes()
                path.write_bytes(raw)
                with self.assertRaises(ValueError):
                    self.observe()
                path.write_bytes(original)
        self.candidate.unlink()
        with self.assertRaises(ValueError):
            self.observe()

    def test_each_stable_identity_change_is_refused(self):
        for key, changed in dict(body_sha256='c' * 64, volume_uuid='other', filesystem='msdos', volume_bytes=4096).items():
            with self.subTest(key=key):
                self.discover.side_effect = lambda: dict(self.volume, **{key: changed})
                with self.assertRaisesRegex(ValueError, 'identity|Same-body'):
                    self.observe()

    def test_handle_changes_mid_read_are_refused(self):
        for key in ('device', 'parent', 'mount', 'registry_id'):
            with self.subTest(key=key):
                self.discover.side_effect = [self.volume.copy(), self.volume.copy(), dict(self.volume, **{key: str(self.root / 'changed') if key == 'mount' else 'changed'})]
                with self.assertRaisesRegex(ValueError, 'handles changed'):
                    self.observe()

    def test_file_changed_after_readback_is_refused(self):
        calls = 0
        def observe():
            nonlocal calls
            calls += 1
            if calls == 4:
                self.candidate.write_bytes(b'x' * len(self.payload))
            return self.volume.copy()
        self.discover.side_effect = observe
        with self.assertRaisesRegex(ValueError, 'Pinned card file changed'):
            self.observe()

    def test_symlinked_candidate_root_or_parent_is_refused(self):
        other = self.root / 'other'
        other.write_bytes(self.payload)
        self.candidate.unlink()
        self.candidate.symlink_to(other)
        with self.assertRaises(ValueError):
            self.observe()
        self.candidate.unlink()
        self.candidate.write_bytes(self.payload)
        self.root_update.unlink()
        self.root_update.symlink_to(other)
        with self.assertRaisesRegex(ValueError, 'Unsafe root'):
            self.observe()

    def test_stage_hash_and_target_path_are_bound(self):
        self.stage_path.write_text('{}')
        with self.assertRaisesRegex(ValueError, 'hash differs'):
            self.observe()
        self.stage['target'] = str(self.root_update)
        self.write_stage()
        with self.assertRaisesRegex(ValueError, 'Unsafe staged receipt path'):
            self.observe()

    def test_no_default_discovery_entry_exists(self):
        with self.assertRaisesRegex(ValueError, 'Explicit filesystem observer'):
            cancel.observe_inactive_card(self.reference, body_sha256=self.body, discover=None)
        self.discover.assert_not_called()


class CancellationAssessmentTests(unittest.TestCase):
    write_stage = InactiveCardTests.write_stage

    def setUp(self):
        InactiveCardTests.setUp(self)
        import test_camera_install_patch_session as session_fixture
        from camera_install_journal import InstallJournal
        self.session = session_fixture.InstallPatchSessionTests()
        self.session.setUp()
        self.addCleanup(self.session.doCleanups)
        self.session.journal = InstallJournal.create(self.session.root / 'cancel-sessions', 'pending',
            plan_sha256=self.session.plan, body_sha256=self.body, model='ILCE-7M4')
        self.session.journal.advance('SD_STAGE_INTENT')
        self.session.journal.advance('SD_STAGED', details=dict(stage_report=self.reference['path'],
            stage_report_sha256=self.reference['sha256']))
        self.session.invoke()
        pending_path = self.session.evidence / 'install-patch-awaiting-reconnect.json'
        self.pending_reference = dict(path=str(pending_path), sha256=sha(pending_path.read_bytes()))
        self.nonce = b'r' * 16

    def assess(self, states=('ORIGINAL', 'ORIGINAL'), **changes):
        import camera_install_patch_read as read
        import test_camera_install_patch_read as read_fixture
        raw = Path(self.pending_reference['path']).read_bytes()
        spec = read.target_spec(raw, body_sha256=self.body, plan_sha256=self.session.plan)
        ready, result = read_fixture.rows(spec, states)
        options = dict(journal=self.session.journal, pending_reference=self.pending_reference,
            stage_reference=self.reference, ready_raw=read_fixture.pack(ready, spec, self.nonce),
            result_raw=read_fixture.pack(result, spec, self.nonce), probe_nonce=self.nonce,
            loader_pid=678, discover=self.discover, operator_never_started_confirmed=True,
            operator_health_confirmed=True)
        options.update(changes)
        return cancel.assess_cancellation(**options)

    def test_original_words_and_inactive_card_only_produce_a_checklist(self):
        from camera_install_journal import InstallJournal, assert_no_pending_installs, JournalError
        before = self.session.journal.events
        result = self.assess()
        self.assertTrue(result['eligible_for_separately_reviewed_cancellation'])
        for key in ('cancellation_recorded', 'journal_cleared', 'restore', 'ready',
                    'RAM_restoration_proven', 'RAM_original_state_verified', 'source_is_hardware',
                    'device_execution_proven', 'hardware_admission_proven', 'installation_authorized'):
            self.assertIs(result[key], False)
        self.assertEqual(result['pending_receipt_sha256'], self.pending_reference['sha256'])
        self.assertEqual(result['stage_sha256'], self.reference['sha256'])
        self.assertEqual(result['probe_nonce'], self.nonce.hex())
        payload = dict(result)
        digest = payload.pop('assessment_sha256')
        self.assertEqual(digest, sha(cancel._canonical(payload)))
        self.assertFalse(result['card_contents_or_names_modified'])
        self.assertEqual(InstallJournal.open(self.session.journal.session_dir).events, before)
        with self.assertRaises(JournalError):
            assert_no_pending_installs(self.session.journal.session_dir.parent)
        self.assertEqual(self.candidate.read_bytes(), self.payload)
        self.assertEqual(self.root_update.read_bytes(), self.original)

    def test_patched_mixed_and_other_are_never_eligible(self):
        for states in (('PATCHED', 'PATCHED'), ('ORIGINAL', 'PATCHED'), ('OTHER', 'ORIGINAL')):
            with self.subTest(states=states):
                self.assertFalse(self.assess(states)['eligible_for_separately_reviewed_cancellation'])

    def test_operator_assertions_are_strict_and_independent(self):
        for key in ('operator_never_started_confirmed', 'operator_health_confirmed'):
            for value in (False, 1, 'yes'):
                with self.subTest(key=key, value=value):
                    self.assertFalse(self.assess(**{key: value})['eligible_for_separately_reviewed_cancellation'])

    def test_invalid_or_missing_probe_never_reaches_card_observer(self):
        for changes in (dict(result_raw=b''), dict(result_raw=b'old-phase7'), dict(loader_pid=999),
                        dict(probe_nonce=bytes(range(16)))):
            with self.subTest(changes=changes):
                self.discover.reset_mock()
                with self.assertRaises(ValueError):
                    self.assess(**changes)
                self.discover.assert_not_called()

    def test_pid_gone_forensic_probe_is_not_cancellation_evidence(self):
        import camera_install_patch_read as read
        import test_camera_install_patch_read as read_fixture
        spec = read.target_spec(Path(self.pending_reference['path']).read_bytes(),
                                body_sha256=self.body, plan_sha256=self.session.plan)
        _, failed = read_fixture.rows(spec)
        failed.update(phase=90, error=-3, lib_mem_status=-3)
        raw = read_fixture.pack(failed, spec, self.nonce)
        self.assertEqual(read.decode_record(raw, self.nonce, spec)['error'], -3)
        with self.assertRaises(ValueError):
            self.assess(result_raw=raw)
        self.discover.assert_not_called()

    def test_stale_pending_or_stage_binding_is_refused_without_card_reads(self):
        for key, reference in (('pending_reference', self.pending_reference), ('stage_reference', self.reference)):
            with self.subTest(key=key):
                self.discover.reset_mock()
                with self.assertRaises(ValueError):
                    self.assess(**{key: reference | {'sha256': '0' * 64}})
                self.discover.assert_not_called()

    def test_active_card_cannot_be_cancelled_by_assessment(self):
        self.root_update.write_bytes(self.payload)
        with self.assertRaises(ValueError):
            self.assess()
        self.assertEqual(self.root_update.read_bytes(), self.payload)
        self.assertEqual(self.session.journal.state, 'INSTALL_PATCH_AWAITING_OPERATOR_RECONNECT')


if __name__ == '__main__':
    unittest.main()
