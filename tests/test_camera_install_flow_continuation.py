"""Source migration in a temporary model workspace; no SDK/device actors run.

Native pending/runtime validators are mocked only for an explicit model schema.
The real source, artifact, event, journal, lease and flow state guards remain.
"""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import camera_install_flow as flow
import camera_install_flow_continuation as bridge
import camera_install_journal as ledger
from camera_device_lease import CameraDeviceLease
from camera_install_patch_session import canonical_sha256
from camera_stream_execution import durable_new

MODEL = 'camera-source-continuation-test-fixture/1'


class ContinuationTests(unittest.TestCase):
    def setUp(self):
        self.temp = self.enterContext(tempfile.TemporaryDirectory())
        self.root = Path(self.temp).resolve()
        self.out = self.root / 'output'
        self.out.mkdir()
        self.folder = self.out / 'live-model'
        self.folder.mkdir()
        (self.folder / 'events').mkdir()
        (self.folder / 'steps').mkdir()
        self.sessions = self.out / 'sessions'
        self.lock = self.out / 'owner.lock'
        for module in (flow, bridge):
            self.enterContext(patch.object(module, 'ROOT', self.root))
            self.enterContext(patch.object(module, 'DEFAULT_LOCK', self.lock))
            self.enterContext(patch.object(module, 'DEFAULT_SESSIONS', self.sessions))
        self.before = {bridge.CHANGED[0]: b'old model controller', bridge.CHANGED[1]: b'old model emulator',
                       'native/install_patch_read.c': b'UNCHANGED NATIVE',
                       'camera_stream_channel.py': b'UNCHANGED TRANSPORT',
                       'Sony-PMCA-RE/pmca/usb/sony.py': b'UNCHANGED SDK'}
        self.after = dict(self.before)
        self.after.update({bridge.CHANGED[0]: b'new reviewed model controller',
                           bridge.CHANGED[1]: b'new reviewed model emulator', bridge.HELPER: b'new reviewed helper'})
        for name, raw in self.after.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        for key, value in (('BEFORE_CONTROLLER', flow.sha(self.before[bridge.CHANGED[0]])),
                           ('BEFORE_EMULATOR', flow.sha(self.before[bridge.CHANGED[1]])),
                           ('AFTER_CONTROLLER', flow.sha(self.after[bridge.CHANGED[0]])),
                           ('AFTER_EMULATOR', flow.sha(self.after[bridge.CHANGED[1]]))):
            self.enterContext(patch.object(bridge, key, value))
        self.enterContext(patch.object(flow, 'source_paths', return_value=tuple(self.after)))
        self.snapshots = self.out / 'old-sources'
        self.snapshots.mkdir()
        for name, raw in self.before.items():
            path = self.snapshots / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        self.body = 'b' * 64
        patch_assets = {'schema': MODEL, 'model_fixture_only': True}
        original = dict(schema='camera-install-patch-session-plan/1', scope='INSTALL_PREPARATION_VOLATILE_PATCH_ONLY',
                body_sha256=self.body, model='ILCE-7M4', package_sha256=flow.DIGEST, plaintext_sha256=flow.PLAIN_SHA,
                local_checks_passed=True, prepared_offline_only=True, execution_approval_received=False,
                installation_authorized=False, hardware_admission_proven=False, flash_authorized=False,
                asset_reference=patch_assets)
        self.plan = self.write(self.out / 'plan.json', original)
        runtime_assets = dict(schema=MODEL, model_fixture_only=True)
        runtime_review = self.write(self.out / 'runtime-review.json', dict(asset_reference=runtime_assets,
                body_sha256=self.body, original_plan_sha256=self.plan['sha256']))
        post = self.out / 'post'
        post.mkdir()
        self.config = dict(schema=flow.CONFIG_SCHEMA, body_sha256=self.body, candidate_sha256=flow.DIGEST,
                original_plan_reference=self.plan, patch=dict(review_reference=self.plan, asset_reference=patch_assets),
                runtime=dict(review_reference=runtime_review, asset_reference=runtime_assets),
                post=dict(directory=str(post), asset_reference={}),
                sources={name: flow.sha(raw) for name, raw in self.before.items()},
                source_snapshot_directory=str(self.snapshots), installation_authorized=False)
        self.config_ref = self.write(self.out / 'config.json', self.config)
        self.approval = dict(schema='onsite-explicit-preparation-approval/1', config_sha256=self.config_ref['sha256'],
                flow=str(self.folder.relative_to(self.root)), authorized_steps=dict.fromkeys(('stage','activate','patch',*bridge.READ_STEPS),1),
                patches_remain_acknowledged=True, firmware_never_started=True, slot1_confirmed=True,
                single_writer_acknowledged=True, installation_authorized=False, manual_update_start_authorized=False,
                automatic_retry=False)
        self.approval_ref = self.write(self.out / 'approval.json', self.approval)
        self.enterContext(patch.object(bridge, 'APPROVAL_SHA256', self.approval_ref['sha256']))
        self.journal = ledger.InstallJournal.create(self.sessions, 'model-original',
                plan_sha256=self.plan['sha256'], body_sha256=self.body, model='ILCE-7M4')
        self.journal.advance('SD_STAGE_INTENT')
        self.journal.advance('SD_STAGED')
        self.journal.advance('INSTALL_PATCH_MAY_BE_ACTIVE')
        self.pending = self.write(self.out / 'pending.json', dict(schema=MODEL, model_fixture_only=True))
        def fixture_pending(reference, binding, history):
            _, value = flow.load_reference(reference)
            self.assertEqual(value['schema'], MODEL)
            self.assertTrue(value['model_fixture_only'])
            return value
        self.enterContext(patch.object(ledger, '_install_patch_pending', side_effect=fixture_pending))
        self.journal.record_install_patch_awaiting_reconnect(self.pending['path'])
        def fixture_complete(reference, **kwargs):
            _, value = flow.load_reference(reference)
            self.assertEqual(value['schema'], MODEL)
            self.assertTrue(value['model_fixture_only'])
            return dict(source_is_hardware=True, model_fixture_only=True)
        self.pending_check = self.enterContext(patch.object(bridge, 'validate_completed_pending', side_effect=fixture_complete))
        self.runtime_check = self.enterContext(patch.object(bridge, 'validate_completed_runtime', side_effect=fixture_complete))
        self.header = dict(schema=flow.SCHEMA, config_reference=self.config_ref, journal_session=str(self.journal.session_dir),
                injected_execution=False, source_is_hardware=False, installation_authorized=False, candidate_sha256=flow.DIGEST)
        self.write(self.folder / 'flow.json', self.header)
        self.card = dict(body_sha256=self.body, volume_uuid='MODEL_CARD', filesystem='MODEL_FS', volume_bytes=123)
        self.events = []
        for step in ('runtime', 'probe', 'stage', 'activate', 'patch'):
            flow._append(self.folder, self.events, step, 'INTENT', journal_event_sha256=self.journal.events[0]['event_sha256'])
            value = dict(schema=MODEL, model_fixture_only=True, volume_identity=self.card)
            if step == 'activate':
                value.update(state='ACTIVATED_PREVIEW_ONLY', updater_invoked=False)
            artifact = self.pending if step == 'patch' else self.write(self.out / (step + '.json'), value)
            wrapper = self.write(self.out / (step + '-result.json'), dict(artifact_reference=artifact))
            flow._append(self.folder, self.events, step, 'COMPLETED', receipt_reference=wrapper, source_is_hardware=True)
        flow._append(self.folder, self.events, 'prepare-read', 'INTENT', journal_event_sha256=self.journal.events[-1]['event_sha256'])
        flow._append(self.folder, self.events, 'prepare-read', 'REJECTED_LOCAL', journal_unchanged=True,
                SDK_requests_attempted=False, manual_instruction_released=False, automatic_retry=False)
        self.original_bytes = {p: p.read_bytes() for p in (*self.folder.joinpath('events').iterdir(),
                *self.journal.session_dir.iterdir(), self.folder / 'flow.json', Path(self.config_ref['path']))}
        self.lease = CameraDeviceLease('model-source-continuation', lock_path=self.lock)
        self.lease.__enter__()
        self.addCleanup(lambda lease=self.lease: lease.__exit__(None, None, None) if lease.fd is not None else None)
        self.review = None

    def write(self, path, value):
        path.write_text(json.dumps(value))
        return flow.reference(path)

    def seal(self):
        self.review = bridge.seal(self.folder, self.out / 'repair-review', approval_reference=self.approval_ref, lease=self.lease)
        return self.review

    def activate(self):
        self.seal()
        return bridge.activate(self.review, lease=self.lease)

    def tamper_review(self, change):
        value = bridge.load(self.review)
        change(value)
        self.review = self.write(Path(self.review['path']), value)

    def test_default_config_and_init_stay_strict(self):
        with self.assertRaisesRegex(ValueError, 'Complete current|Flow source'):
            flow.validate_config(self.config_ref)
        with self.assertRaises(ValueError):
            flow.init_flow(self.config_ref, self.out / 'fresh')
        self.assertFalse((self.out / 'fresh').exists())

    def test_seal_activate_keeps_original_bytes_and_completed_steps(self):
        active = self.activate()
        value = flow.status(self.folder)
        self.assertEqual(value['state'], bridge.PENDING)
        self.assertEqual(set(value['completed_steps']), {'runtime','probe','stage','activate','patch'})
        self.assertEqual(value['locally_rejected_steps'], ['prepare-read'])
        for path, raw in self.original_bytes.items():
            self.assertEqual(path.read_bytes(), raw)
        self.assertFalse(bridge.load(active)['operation_consent_granted'])
        with self.assertRaises(FileExistsError):
            bridge.activate(self.review, lease=self.lease)

    def test_review_and_sidecar_cannot_be_reused_for_another_flow(self):
        self.activate()
        other = self.out / 'other-flow'
        other.mkdir()
        (other / 'flow.json').write_bytes((self.folder / 'flow.json').read_bytes())
        (other / 'source-continuation.json').write_bytes((self.folder / 'source-continuation.json').read_bytes())
        with self.assertRaisesRegex(ValueError, 'Flow-bound'):
            bridge.validate_active(other, self.header)

    def test_old_source_snapshot_tampering_is_rejected(self):
        self.seal()
        (self.snapshots / 'camera_stream_channel.py').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'Historical source'):
            bridge.activate(self.review, lease=self.lease)
        self.assertFalse((self.folder / 'source-continuation.json').exists())

    def test_native_and_transport_changes_cannot_be_relabelled(self):
        self.seal()
        for name in ('native/install_patch_read.c', 'camera_stream_channel.py'):
            original = (self.root / name).read_bytes()
            (self.root / name).write_bytes(b'UNREVIEWED')
            with self.subTest(name=name), self.assertRaises(ValueError):
                bridge.activate(self.review, lease=self.lease)
            (self.root / name).write_bytes(original)

    def test_arbitrary_controller_edit_cannot_enter_the_allowed_filename(self):
        (self.root / bridge.CHANGED[0]).write_bytes(b'arbitrary controller change')
        with self.assertRaisesRegex(ValueError, 'exact reviewed'):
            self.seal()

    def test_extra_source_delta_is_rejected_even_with_updated_hashes(self):
        self.seal()
        name = 'camera_stream_channel.py'
        (self.root / name).write_bytes(b'extra delta')
        value = bridge.load(self.review)
        (Path(value['source_snapshot_directory']) / name).chmod(0o600)
        (Path(value['source_snapshot_directory']) / name).write_bytes(b'extra delta')
        self.tamper_review(lambda r: r['sources'].update({name: flow.sha(b'extra delta')}))
        with self.assertRaisesRegex(ValueError, 'exact reviewed'):
            bridge.activate(self.review, lease=self.lease)

    def test_mixed_new_snapshot_is_rejected(self):
        self.seal()
        sources = Path(bridge.load(self.review)['source_snapshot_directory'])
        path = sources / bridge.HELPER
        path.chmod(0o600)
        path.write_bytes(b'old helper')
        with self.assertRaisesRegex(ValueError, 'Current continuation'):
            bridge.activate(self.review, lease=self.lease)

    def test_body_card_pending_and_journal_binding_are_exact(self):
        self.seal()
        for field, value in (('body_sha256', 'c'*64), ('journal_ancestor_sha256', 'd'*64),
                             ('pending_reference', self.config_ref), ('card_identity', {})):
            original = bridge.load(self.review)
            self.tamper_review(lambda r: r.update({field: value}))
            with self.subTest(field=field), self.assertRaises(ValueError):
                bridge.activate(self.review, lease=self.lease)
            self.review = self.write(Path(self.review['path']), original)

    def test_local_rejection_must_prove_no_sdk_or_manual_instruction(self):
        path = self.folder / 'events/00000012.json'
        event = json.loads(path.read_bytes())
        event['SDK_requests_attempted'] = True
        event['event_sha256'] = flow.sha(flow.canonical({k: v for k, v in event.items() if k != 'event_sha256'}))
        path.write_text(json.dumps(event))
        with self.assertRaisesRegex(ValueError, 'local-only'):
            self.seal()

    def test_simulated_pending_or_runtime_cannot_be_promoted_by_wrapper(self):
        self.seal()
        for validator in (self.pending_check, self.runtime_check):
            original = validator.side_effect
            validator.side_effect = lambda *a, **k: dict(source_is_hardware=False)
            with self.assertRaisesRegex(ValueError, 'real sources'):
                bridge.validate_review(self.review)
            validator.side_effect = original

    def test_prefix_survives_new_events_and_old_producer_avoids_future_journal_cycle(self):
        self.activate()
        flow._append(self.folder, self.events, 'prepare-read', 'INTENT',
                source_continuation_reference=bridge.reference(self.folder/'source-continuation.json'),
                journal_event_sha256=self.journal.events[-1]['event_sha256'])
        artifact = self.write(self.out / 'new-preparation.json', dict(schema=MODEL))
        wrapper = self.write(self.out / 'new-preparation-result.json', dict(artifact_reference=artifact))
        flow._append(self.folder, self.events, 'prepare-read', 'COMPLETED', receipt_reference=wrapper, source_is_hardware=False)
        # A producer needs only its bound old ancestor; future events may be unreadable
        # while an admission validator is recursively checking that producer.
        (self.journal.session_dir / '00000006.json').write_bytes(b'FUTURE MUST NOT BE OPENED')
        import camera_install_flow_history as history
        with self.subTest('explicit known model ABI'), \
             patch.multiple(history, ROOT=self.root, DEFAULT_SESSIONS=self.sessions,
                 BEFORE_CONTROLLER=bridge.BEFORE_CONTROLLER, BEFORE_EMULATOR=bridge.BEFORE_EMULATOR,
                 AFTER_CONTROLLER=bridge.AFTER_CONTROLLER, AFTER_EMULATOR=bridge.AFTER_EMULATOR,
                 CONTINUATION_HELPER=flow.sha(self.after[bridge.HELPER]),
                 APPROVAL_SHA256=bridge.APPROVAL_SHA256, REQUIRED_SOURCES_V1=frozenset(self.before)), \
             patch.object(history, 'validate_completed_pending', self.pending_check), \
             patch.object(history, 'validate_completed_runtime', self.runtime_check), \
             patch.object(ledger.InstallJournal, 'open', side_effect=AssertionError('latest journal opened')):
            _, _, _, prefix, binding = flow._open(self.folder, _producer_step='probe')
        self.assertEqual(prefix[-1]['step'], 'probe')
        self.assertEqual(binding['body_sha256'], self.body)

    def test_unknown_new_attempt_blocks_and_original_unknown_cannot_activate(self):
        self.activate()
        flow._append(self.folder, self.events, 'read', 'INTENT', journal_event_sha256=self.journal.events[-1]['event_sha256'])
        flow._append(self.folder, self.events, 'read', 'UNKNOWN', automatic_retry=False)
        with self.assertRaisesRegex(ValueError, 'Unresolved'):
            flow.run_step(self.folder, 'read', step_authorized=True, camera_ready=True)

    def test_read_steps_use_existing_consent_but_later_steps_need_exact_fresh_source_reference(self):
        active = self.activate()
        for step in bridge.READ_STEPS:
            bridge.authorize_step(self.folder, step, {})
        for step in ('admit','start','cancel'):
            with self.subTest(step=step), self.assertRaisesRegex(ValueError, 'fresh operator'):
                bridge.authorize_step(self.folder, step, self.approval)
            with self.assertRaises(ValueError):
                bridge.authorize_step(self.folder, step, dict(source_continuation_reference=self.config_ref))
            bridge.authorize_step(self.folder, step, dict(source_continuation_reference=active))
        # Passing the source gate does not create a formal approval or change state.
        self.assertEqual(ledger.InstallJournal.open(self.journal.session_dir).state, bridge.PENDING)

    def test_actual_continued_steps_append_without_reapplying_patch(self):
        active = self.activate()
        self.lease.__exit__(None, None, None)
        called = []
        def actor(step, folder, config, events, journal, lease, operator, **kwargs):
            self.assertIn(step, bridge.READ_STEPS)
            self.assertEqual(journal.state, bridge.PENDING)
            self.assertEqual(config, self.config)
            self.assertIsNotNone(lease.fd)
            called.append(step)
            artifact = self.write(folder / 'model-result.json', dict(schema=MODEL, model_fixture_only=True))
            return dict(artifact_reference=artifact)
        with patch.object(flow, '_system'), patch.object(flow, '_dispatch', side_effect=actor):
            for step in bridge.READ_STEPS:
                flow.run_step(self.folder, step, step_authorized=True, camera_ready=True)
        self.assertEqual(called, list(bridge.READ_STEPS))
        events = [json.loads(p.read_bytes()) for p in sorted((self.folder / 'events').iterdir())]
        self.assertEqual(events[12]['step'], 'prepare-read')
        self.assertEqual(events[12]['attempt'], 2)
        for event in events[12:]:
            if event['phase'] == 'INTENT':
                self.assertEqual(event['source_continuation_reference'], active)
        for path, raw in self.original_bytes.items():
            self.assertEqual(path.read_bytes(), raw)
        self.assertEqual(ledger.InstallJournal.open(self.journal.session_dir).state, bridge.PENDING)

    def test_activation_rejects_changed_journal_or_event_prefix(self):
        self.seal()
        original = bridge.load(self.review)
        self.tamper_review(lambda r: r.update(journal_directory=str(self.out / 'another-journal')))
        with self.assertRaises(ValueError):
            bridge.activate(self.review, lease=self.lease)
        self.review = self.write(Path(self.review['path']), original)
        path = self.folder / 'events/00000012.json'
        value = json.loads(path.read_bytes())
        value['phase'] = 'UNKNOWN'
        value['event_sha256'] = flow.sha(flow.canonical({k:v for k,v in value.items() if k != 'event_sha256'}))
        path.write_text(json.dumps(value))
        with self.assertRaises(ValueError):
            bridge.activate(self.review, lease=self.lease)
        self.assertFalse((self.folder / 'source-continuation.json').exists())

    def test_released_lease_cannot_activate(self):
        self.seal()
        self.lease.__exit__(None, None, None)
        with self.assertRaises(ValueError):
            bridge.activate(self.review, lease=self.lease)
        self.assertFalse((self.folder / 'source-continuation.json').exists())

    def test_exact_source_gate_does_not_skip_formal_actor_guards(self):
        active = self.activate()
        self.lease.__exit__(None, None, None)
        operator = self.write(self.out / 'new-operator.json', dict(source_continuation_reference=active))
        with patch.object(flow, '_system'):
            # The existing admit actor still requires all full-admission references.
            with self.assertRaisesRegex(ValueError, 'Explicit complete admission references'):
                flow.run_step(self.folder, 'admit', step_authorized=True, operator_reference=operator)
        self.assertEqual(ledger.InstallJournal.open(self.journal.session_dir).state, bridge.PENDING)

    def test_source_context_is_rechecked_after_lease_acquisition_before_intent(self):
        self.activate()
        self.lease.__exit__(None, None, None)
        original = CameraDeviceLease.__enter__
        def swapped(lease):
            held = original(lease)
            active = self.folder / 'source-continuation.json'
            value = json.loads(active.read_bytes())
            value['lease_identity_at_activation']['instance'] = 'f'*32
            active.write_text(json.dumps(value))
            return held
        before = len(self.events)
        with patch.object(flow, '_system'), patch.object(CameraDeviceLease, '__enter__', swapped):
            with self.assertRaisesRegex(ValueError, 'continuation changed'):
                flow.run_step(self.folder, 'read', step_authorized=True, camera_ready=True)
        self.assertEqual(len(list((self.folder / 'events').iterdir())), before)


if __name__ == '__main__':
    unittest.main()
