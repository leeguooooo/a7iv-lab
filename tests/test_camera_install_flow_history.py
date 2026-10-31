"""Known model ABIs only: no real camera artifacts, SDK or device operations."""
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import camera_install_flow as flow
import camera_install_flow_continuation as bridge
import camera_install_flow_history as history
import camera_install_journal as ledger
from camera_operation_guard import assert_operation_allowed
from tools import card_protocol_probe as probe
import test_camera_install_flow_continuation as fixtures
MODEL = fixtures.MODEL
from install_model_fixture import formal_complete


class HistoricalFlowTests(unittest.TestCase):
    def setUp(self):
        self.f = fixtures.ContinuationTests('test_seal_activate_keeps_original_bytes_and_completed_steps')
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.ro_name = 'camera_readonly_identity.py'
        self.ro_v1 = b"raise RuntimeError('ARCHIVE MUST NEVER EXECUTE')\n"
        (self.f.root / self.ro_name).write_bytes(self.ro_v1)
        (self.f.snapshots / self.ro_name).write_bytes(self.ro_v1)
        self.f.config['sources'][self.ro_name] = flow.sha(self.ro_v1)
        self.f.config['card_activation_protocol'] = flow.BACKUP_COPY_ATOMIC_REPLACE
        self.f.config_ref = self.f.write(Path(self.f.config_ref['path']), self.f.config)
        self.f.header['config_reference'] = self.f.config_ref
        self.f.write(self.f.folder / 'flow.json', self.f.header)
        self.f.approval['config_sha256'] = self.f.config_ref['sha256']
        self.f.approval_ref = self.f.write(Path(self.f.approval_ref['path']), self.f.approval)
        self.f.enterContext(patch.object(bridge, 'APPROVAL_SHA256', self.f.approval_ref['sha256']))
        self.enterContext(patch.multiple(history, ROOT=self.f.root, DEFAULT_SESSIONS=self.f.sessions,
                BEFORE_CONTROLLER=bridge.BEFORE_CONTROLLER, BEFORE_EMULATOR=bridge.BEFORE_EMULATOR,
                AFTER_CONTROLLER=bridge.AFTER_CONTROLLER, AFTER_EMULATOR=bridge.AFTER_EMULATOR,
                CONTINUATION_HELPER=flow.sha(self.f.after[bridge.HELPER]),
                APPROVAL_SHA256=bridge.APPROVAL_SHA256, REQUIRED_SOURCES_V1=frozenset(self.f.before)))
        self.enterContext(patch.object(history, 'validate_completed_pending', self.f.pending_check))
        self.enterContext(patch.object(history, 'validate_completed_runtime', self.f.runtime_check))
        self.f.activate()
        self.volume = dict(self.f.card, device='MODEL', parent='MODEL', mount='/MODEL_ONLY', registry_id='MODEL')
        self.probe_ref = flow._artifact(self.f.events, 'probe')

    def producer(self):
        return probe._flow_producer(self.probe_ref, 'probe', self.f.folder, self.volume)

    def drift(self):
        (self.f.root / self.ro_name).write_bytes(b'UNRELATED FUTURE RO V2 MODEL SOURCE')

    def terminal_model(self):
        formal_complete(self.f, self.f.journal)
        self.verification = self.f.write(self.f.out / 'MODEL-content.json',
                dict(schema=MODEL, model_fixture_only=True, source_is_hardware=False, **self.f.journal.binding))
        original = ledger._verification
        def model_verification(ref, binding):
            _, value = flow.load_reference(ref)
            if value.get('schema') == MODEL:
                self.assertTrue(value['model_fixture_only'])
                self.assertFalse(value['source_is_hardware'])
                self.assertTrue(all(value.get(k) == v for k, v in binding.items()))
                return value
            return original(ref, binding)
        self.enterContext(patch.object(ledger, '_verification', side_effect=model_verification))
        self.f.journal.record_content_verified(self.verification['path'])
        original_formal = ledger._formal_details
        def model_card_dependency(state, details, binding, prior, folder):
            value = original_formal(state, details, binding, prior, folder)
            if state == 'INSTALL_READY_FOR_OPERATOR_START':
                self.producer()
            return value
        self.enterContext(patch.object(ledger, '_formal_details', side_effect=model_card_dependency))
        # Production continuation records a pinned read intent first.
        active_ref = bridge.reference(self.f.folder/'source-continuation.json')
        flow._append(self.f.folder, self.f.events, 'prepare-read', 'INTENT',
                source_continuation_reference=active_ref, journal_event_sha256=self.f.journal.events[4]['event_sha256'])
        wrapper = self.f.write(self.f.out/'MODEL-prepare-result.json', dict(artifact_reference=self.f.pending))
        flow._append(self.f.folder, self.f.events, 'prepare-read', 'COMPLETED', receipt_reference=wrapper, source_is_hardware=False)
        for step in ('post', 'content'):
            flow._append(self.f.folder, self.f.events, step, 'INTENT',
                    journal_event_sha256=self.f.journal.events[-1]['event_sha256'])
            wrapper = self.f.write(self.f.out / (step + '-MODEL-result.json'), dict(artifact_reference=self.verification))
            flow._append(self.f.folder, self.f.events, step, 'COMPLETED', receipt_reference=wrapper, source_is_hardware=False)
        self.terminal_bytes = {p.name: p.read_bytes() for p in self.f.journal.session_dir.iterdir()}

    def capsule(self, change):
        ref = self.f.review
        value = bridge.load(ref)
        change(value)
        self.f.review = self.f.write(Path(ref['path']), value)
        active = self.f.folder / 'source-continuation.json'
        wrapper = json.loads(active.read_bytes())
        wrapper['review_reference'] = self.f.review
        active.write_text(json.dumps(wrapper))

    def test_producer_uses_snapshots_after_unrelated_live_source_and_source_paths_drift(self):
        expected = self.producer()
        self.drift()
        with patch.object(flow, 'source_paths', side_effect=AssertionError('live closure queried')):
            actual = self.producer()
        self.assertEqual(expected, actual)

    def test_terminal_history_and_global_guard_survive_live_source_upgrade(self):
        self.terminal_model()
        self.drift()
        self.assertEqual(ledger.InstallJournal.open(self.f.journal.session_dir).state, 'CONTENT_VERIFIED')
        assert_operation_allowed(sessions_root=self.f.sessions)
        self.assertEqual(self.terminal_bytes, {p.name:p.read_bytes() for p in self.f.journal.session_dir.iterdir()})

    def test_current_execution_and_default_status_remain_strict(self):
        self.drift()
        for operation in (lambda: flow.validate_config(self.f.config_ref), lambda: flow.status(self.f.folder),
                          lambda: flow.run_step(self.f.folder, 'read', step_authorized=True, camera_ready=True)):
            with self.assertRaises(ValueError):
                operation()
        self.assertEqual(len(list((self.f.folder/'events').iterdir())), 12)

    def test_known_current_controller_pin_matches_reviewed_source(self):
        self.assertEqual(history.CURRENT_CONTROLLER, flow.sha(Path(flow.__file__).read_bytes()))

    def test_original_and_new_current_direct_profiles_replay_without_live_hashes(self):
        active_path = self.f.folder/'source-continuation.json'
        active_path.unlink()  # Temporary model only, never the actual sidecar.
        self.drift()
        self.producer()
        config = self.f.config
        sources = dict(self.f.after)
        sources[self.ro_name] = self.ro_v1
        sources['camera_install_flow_history.py'] = b'KNOWN MODEL HISTORY PARSER SOURCE'
        snapshots = self.f.out/'new-direct-sources'
        snapshots.mkdir()
        for name, raw in sources.items():
            path=snapshots/name; path.parent.mkdir(parents=True,exist_ok=True); path.write_bytes(raw)
        config['sources'] = {name:flow.sha(raw) for name,raw in sources.items()}
        config['source_snapshot_directory'] = str(snapshots)
        config_ref = self.f.write(Path(self.f.config_ref['path']), config)
        self.f.header['config_reference'] = config_ref
        self.f.write(self.f.folder/'flow.json', self.f.header)
        with patch.object(history, 'CURRENT_CONTROLLER', bridge.AFTER_CONTROLLER):
            self.producer()

    def test_archive_code_is_never_executed(self):
        with patch('builtins.exec', side_effect=AssertionError('archive executed')) as execute:
            self.producer()
        execute.assert_not_called()

    def test_old_and_continuation_snapshot_tampering_are_rejected(self):
        review = bridge.load(self.f.review)
        for directory in (self.f.snapshots, Path(review['source_snapshot_directory'])):
            path = directory / self.ro_name
            saved = path.read_bytes()
            path.chmod(0o600)
            path.write_bytes(b'tampered')
            with self.assertRaisesRegex(ValueError, 'Historical source'):
                self.producer()
            path.write_bytes(saved)

    def test_self_consistent_unknown_controller_profile_is_rejected(self):
        def change(review):
            name = bridge.CHANGED[0]
            raw = b'UNKNOWN ARCHIVED CONTROLLER'
            path = Path(review['source_snapshot_directory']) / name
            path.chmod(0o600); path.write_bytes(raw)
            review['sources'][name] = flow.sha(raw)
            review['source_delta'][name]['after'] = flow.sha(raw)
        self.capsule(change)
        with self.assertRaisesRegex(ValueError, 'Unsupported historical'):
            self.producer()

    def test_source_capsule_flow_body_card_or_header_mismatch_is_rejected(self):
        original = bridge.load(self.f.review)
        active_path = self.f.folder/'source-continuation.json'
        active_bytes = active_path.read_bytes()
        for field, value in (('body_sha256','c'*64), ('flow_directory',str(self.f.out)),
                             ('card_identity',{}), ('config_reference',self.f.plan)):
            self.capsule(lambda r: r.update({field:value}))
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.producer()
            self.f.review = self.f.write(Path(self.f.review['path']), original)
            active_path.write_bytes(active_bytes)

    def test_recorded_capsule_hash_cannot_be_swapped(self):
        self.terminal_model()
        path = self.f.folder/'source-continuation.json'
        value = json.loads(path.read_bytes())
        value['lease_identity_at_activation']['instance'] = 'f'*32
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, 'capsule does not match'):
            self.producer()

    def test_wrong_producer_reference_or_unknown_role_is_rejected(self):
        with self.assertRaises(ValueError):
            probe._flow_producer(self.f.pending, 'probe', self.f.folder, self.volume)
        with self.assertRaises(ValueError):
            history.open_producer(self.f.folder, 'start')
        outside = self.f.root/'outside'
        outside.mkdir()
        with self.assertRaises(ValueError):
            history.open_producer(outside, 'probe')

    def test_changed_producer_prefix_is_not_accepted(self):
        path = self.f.folder/'events/00000004.json'
        value = json.loads(path.read_bytes()); value['source_is_hardware'] = False
        path.write_text(json.dumps(value))
        with self.assertRaises(ValueError):
            self.producer()

    def test_replayed_producer_event_or_missing_intent_is_rejected(self):
        self.capsule(lambda r: r.update(event_prefix=r['event_prefix'][:3]+r['event_prefix'][2:]))
        with self.assertRaises(ValueError):
            self.producer()

    def test_pending_or_unknown_never_gain_historical_closed_status(self):
        for state in ('PENDING','STOPPED_UNKNOWN'):
            if state == 'STOPPED_UNKNOWN':
                self.f.journal.advance('STOPPED_UNKNOWN')
            self.drift()
            with self.assertRaisesRegex(ValueError, 'CONTENT_VERIFIED'):
                flow.status(self.f.folder, historical=True)
            with self.assertRaises(Exception):
                assert_operation_allowed(sessions_root=self.f.sessions)
        self.assertEqual(ledger.InstallJournal.open(self.f.journal.session_dir).state, 'STOPPED_UNKNOWN')

    def test_closed_status_requires_content_verifier_even_after_valid_terminal_replay(self):
        self.terminal_model(); self.drift()
        with self.assertRaisesRegex(ValueError, 'actual content proof'):
            flow.status(self.f.folder, historical=True)
        def scoped_content(folder, config, events, journal):
            self.assertEqual(journal.state, 'CONTENT_VERIFIED')
            self.assertTrue(flow._load(self.verification)['model_fixture_only'])
            self.assertFalse(flow._load(self.verification)['source_is_hardware'])
        with patch.object(history, '_content_proof_v1', side_effect=scoped_content) as verifier:
            value = flow.status(self.f.folder, historical=True)
        self.assertEqual(value['state'], 'CONTENT_VERIFIED')
        verifier.assert_called_once()
        self.assertTrue(value['historical_query_only'])
        self.assertFalse(value['execution_authorized'])


if __name__ == '__main__':
    unittest.main()
