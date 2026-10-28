from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import camera_install_journal as ledger
import camera_local_rejection as rejection


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class LocalRejectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.session_id = 'synthetic-historical-attempt'
        self.folder = self.root / 'output/camera-workflows' / self.session_id
        self.folder.mkdir(parents=True)
        self.plan = self.root / 'output/offline-toolchain/toolchain-plan-06.json'
        snapshots = self.plan.with_suffix('.sources')
        snapshots.mkdir(parents=True)
        lines = [''] * 310
        lines[306] = '    check_current_staged_card(staged)'
        lines[308] = "    evidence=folder/'menu';evidence.mkdir(mode=0o700)"
        lines[309] = '    result=run_menu_session(record["body_sha256"],evidence)'
        source = snapshots / 'camera_workflow.py'
        source.write_text('\n'.join(lines) + '\n')
        menu = snapshots / 'camera_menu_session.py'
        menu.write_text('synthetic source snapshot\n')
        sources = {p.name: digest(p) for p in (source, menu)}
        self.patch('SOURCE_SHAS', sources)
        self.write(self.plan, dict(source_snapshot_directory=str(snapshots), sources=sources,
                                   reference_body_sha256='b' * 64, model='synthetic'))
        self.binding = dict(plan_sha256=digest(self.plan), body_sha256='b' * 64, model='synthetic')
        self.sessions = self.root / 'output/full-install-sessions'
        self.journal = ledger.InstallJournal.create(self.sessions, self.session_id, **self.binding)
        for state in ('SD_STAGE_INTENT', 'SD_STAGED'):
            self.journal.advance(state)
        self.journal.advance('STOPPED_UNKNOWN', details=dict(operation='window', error_type='ValueError',
            automatic_retry=False, automatic_STOP=False, automatic_reboot=False))
        self.write(self.folder / 'workflow.json', dict(schema='camera-guided-rehearsal/1',
            plan=str(self.plan), journal=str(self.journal.session_dir), **self.binding))
        self.write(self.folder / 'window-intent.json', dict(action='window',
            plan_sha256=digest(self.plan), firmware_never_started_operator_confirmed=True,
            automatic_retry=False))
        self.execution = self.root / 'output/execution.json'
        transcript = self.root / 'original-transcript.jsonl'
        command = ('sudo -n ./camera-workflow device window --workflow output/camera-workflows/' +
                   self.session_id + ' --authorize-step --camera-ready --firmware-never-started')
        call = dict(type='custom_tool_call', call_id='synthetic-call-id', name='exec',
            input='text(await tools.exec_command({cmd:' + json.dumps(command) +
                  ',"max_output_tokens":1500,"yield_time_ms":1000}));\n')
        filename = str(self.root / 'camera_workflow.py')
        trace = ('Traceback (most recent call last):\n'
            f'  File "{filename}", line 307, in device_action\n'
            '    check_current_staged_card(staged)\n'
            f'  File "{filename}", line 225, in check_current_staged_card\n'
            '    require(all(current.get(k)==previous.get(k) for k in\n'
            f'  File "{filename}", line 26, in require\n'
            '    raise ValueError(message)\n'
            'ValueError: Current camera/card differs from staged evidence\n')
        result = dict(type='custom_tool_call_output', call_id='synthetic-call-id',
            output=[dict(type='input_text', text='Script completed'),
                    dict(type='input_text', text=json.dumps(dict(exit_code=1, output=trace)))])
        originals = [dict(timestamp=str(i), type='response_item', payload=payload)
                     for i, payload in enumerate((call, result))]
        raw_lines = [(json.dumps(item) + '\n').encode() for item in originals]
        transcript.write_bytes(b''.join(raw_lines))
        hashes = [(i + 1, hashlib.sha256(raw).hexdigest()) for i, raw in enumerate(raw_lines)]
        records = [dict(item, line_number=i + 1, original_line_sha256=hashes[i][1])
                   for i, item in enumerate(originals)]
        self.records_path = self.root / 'output/original-records.jsonl'
        self.records_path.write_bytes(transcript.read_bytes())
        self.write(self.execution, dict(source_transcript=str(transcript), records=records))
        self.proof_path = self.root / 'output/proof.json'
        self.proof = dict(schema='camera-local-rejection-before-device-entry/1', binding=self.binding,
            session_id=self.session_id, stopped_event_sha256=self.journal.events[-1]['event_sha256'],
            workflow_directory=str(self.folder), plan_artifact=self.ref(self.plan),
            workflow_artifact=self.ref(self.folder / 'workflow.json'),
            window_intent_artifact=self.ref(self.folder / 'window-intent.json'),
            tool_execution_artifact=self.ref(self.execution),
            original_records_artifact=self.ref(self.records_path))
        self.write(self.proof_path, self.proof)
        self.claims = [self.root / 'output/menu-stock-window-offline-01/physical-attempt.json']
        for i, name in enumerate(('post_p1', 'post_cp', 'pre_ufp', 'pre_app', 'post_app')):
            job = self.root / 'output/firmware-file-capture-offline-03' / name / 'prod/job.json'
            job.parent.mkdir(parents=True)
            nonce = f'{i:032x}'
            self.write(job, dict(nonce=nonce))
            self.claims.append(self.root / 'output/firmware-file-capture-nonce-claims' / (nonce + '.json'))

    def patch(self, name, value):
        patcher = mock.patch.object(rejection, name, value)
        patcher.start()
        self.addCleanup(patcher.stop)

    def write(self, path, value):
        path.write_text(json.dumps(value))

    def ref(self, path):
        return dict(path=str(path), sha256=digest(path))

    def close(self):
        return self.journal.record_local_rejection(self.proof_path)

    def assert_rejected(self):
        with self.assertRaises(ledger.JournalError):
            self.close()
        self.assertEqual(self.journal.state, 'STOPPED_UNKNOWN')
        self.assertEqual(len(list(self.journal.session_dir.iterdir())), 4)

    def test_append_preserves_original_bytes_and_allows_fresh_session_only(self):
        paths = list(self.journal.session_dir.iterdir()) + [self.folder / 'window-intent.json']
        before = {path: path.read_bytes() for path in paths}
        event = self.close()
        self.assertEqual(event['details']['local_rejection_artifact'], self.ref(self.proof_path))
        self.assertEqual(event['state'], 'LOCAL_REJECTED_BEFORE_DEVICE_ENTRY')
        for path, raw in before.items():
            self.assertEqual(path.read_bytes(), raw)
        reopened = ledger.InstallJournal.open(self.journal.session_dir)
        ledger.assert_no_pending_installs(self.sessions)
        for state in ledger.STATES:
            with self.subTest(state=state), self.assertRaises(ledger.JournalError):
                reopened.advance(state)
        self.assertEqual(ledger.InstallJournal.create(self.sessions, 'fresh', **self.binding).state, 'PLANNED')

    def test_retained_records_survive_original_transcript_collection(self):
        self.close()
        execution = json.loads(self.execution.read_bytes())
        Path(execution['source_transcript']).unlink()
        ledger.assert_no_pending_installs(self.sessions)

    def test_other_historical_source_version_is_not_accepted(self):
        with mock.patch.object(rejection, 'SOURCE_SHAS', dict(rejection.SOURCE_SHAS,
                              **{'camera_workflow.py': '0' * 64})):
            self.assert_rejected()

    def test_generic_advance_cannot_bypass_specialized_proof(self):
        with self.assertRaisesRegex(ledger.JournalError, 'record_local_rejection'):
            self.journal.advance('LOCAL_REJECTED_BEFORE_DEVICE_ENTRY', details={'local_rejection_artifact':
                                 self.ref(self.proof_path)})

    def test_proof_and_original_inputs_tampering_reblock_replay(self):
        self.close()
        targets = [self.proof_path, self.plan, self.execution, self.records_path,
                   self.folder / 'workflow.json', self.folder / 'window-intent.json',
                   self.plan.with_suffix('.sources') / 'camera_workflow.py',
                   self.plan.with_suffix('.sources') / 'camera_menu_session.py']
        for target in targets:
            original = target.read_bytes()
            for action in ('tamper', 'delete'):
                with self.subTest(target=target, action=action):
                    if action == 'tamper':
                        target.write_bytes(b' ' + original)
                    else:
                        target.unlink()
                    with self.assertRaises(ledger.JournalError):
                        ledger.assert_no_pending_installs(self.sessions)
                    target.write_bytes(original)
        ledger.assert_no_pending_installs(self.sessions)

    def test_wrong_proof_binding_workflow_and_hardware_assertions_rejected(self):
        for field, value in [('binding', dict(self.binding, model='other')),
                             ('session_id', 'other'), ('stopped_event_sha256', 'a' * 64),
                             ('workflow_directory', str(self.root)), ('source_is_hardware', True),
                             ('RAM_original_state_verified', True)]:
            with self.subTest(field=field):
                self.write(self.proof_path, dict(self.proof, **{field: value}))
                self.assert_rejected()

    def test_rehashed_wrong_plan_workflow_intent_and_capture_rejected(self):
        for field in ('plan_artifact', 'workflow_artifact', 'window_intent_artifact', 'tool_execution_artifact'):
            path = Path(self.proof[field]['path'])
            original = path.read_bytes()
            changed = json.loads(original)
            changed.update(plan_sha256='a' * 64, action='restore', records=[], journal='other')
            self.write(path, changed)
            self.write(self.proof_path, dict(self.proof, **{field: self.ref(path)}))
            with self.subTest(field=field):
                self.assert_rejected()
            path.write_bytes(original)

    def test_different_call_workflow_and_error_site_even_with_rehashed_capture_rejected(self):
        original = json.loads(self.execution.read_bytes())
        for target in ('call', 'workflow', 'error-site'):
            execution = deepcopy(original)
            if target == 'call':
                execution['records'][0]['payload']['call_id'] = 'other'
            elif target == 'workflow':
                payload = execution['records'][0]['payload']
                payload['input'] = payload['input'].replace(self.session_id, 'other-workflow')
            else:
                payload = execution['records'][1]['payload']['output'][1]
                payload['text'] = payload['text'].replace('line 307', 'line 310')
            self.write(self.execution, execution)
            self.write(self.proof_path, dict(self.proof, tool_execution_artifact=self.ref(self.execution)))
            with self.subTest(target=target):
                self.assert_rejected()

    def test_any_may_history_is_rejected(self):
        for state in ('RAM_MAY_BE_ACTIVE', 'FLASH_MAY_HAVE_STARTED'):
            history = self.journal.events
            history.insert(3, dict(history[2], state=state))
            with self.subTest(state=state), self.assertRaises(ledger.JournalError):
                rejection.validate_local_rejection(self.ref(self.proof_path), self.binding, history,
                                                    self.journal.session_dir, check_current_claims=True)

    def test_old_entry_artifacts_and_claims_block_append(self):
        paths = [self.folder / name for name in ('menu', 'window-result.json', 'restoration',
                 'restore-intent.json', 'restore-result.json')]
        paths += self.claims
        for path in paths:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('entry evidence')
            with self.subTest(path=path):
                self.assert_rejected()
            path.unlink()

    def test_later_fresh_session_claims_do_not_invalidate_historical_terminal(self):
        self.close()
        for path in self.claims:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('later separately authorized fresh operation')
        ledger.assert_no_pending_installs(self.sessions)
        self.assertEqual(ledger.InstallJournal.open(self.journal.session_dir).state,
                         'LOCAL_REJECTED_BEFORE_DEVICE_ENTRY')

    def test_old_workflow_entry_evidence_still_reblocks_replay(self):
        self.close()
        (self.folder / 'menu').mkdir()
        with self.assertRaises(ledger.JournalError):
            ledger.assert_no_pending_installs(self.sessions)

    def test_symlink_artifact_parent_snapshot_and_claim_refused(self):
        for path in (self.proof_path, self.plan.with_suffix('.sources') / 'camera_menu_session.py'):
            raw = path.read_bytes()
            alternate = path.with_suffix('.real')
            path.rename(alternate)
            path.symlink_to(alternate)
            self.assert_rejected()
            path.unlink()
            alternate.rename(path)
            self.assertEqual(path.read_bytes(), raw)
        claim = self.claims[0]
        claim.parent.mkdir(parents=True)
        claim.symlink_to(self.root / 'absent')
        self.assert_rejected()


if __name__ == '__main__':
    unittest.main()
