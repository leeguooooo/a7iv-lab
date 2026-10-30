"""Post-completion transactions on local files and paired model transports."""
import copy
import hashlib
import json
from pathlib import Path
import shutil
import unittest
from unittest.mock import Mock, patch

import camera_install_post_session as post
import camera_install_post_plan as plan
from camera_device_lease import CameraDeviceLease
from camera_install_journal import InstallJournal
from camera_stream_execution import durable_new
import test_camera_postinstall_verify as capture_fixture


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class PostSessionTests(unittest.TestCase):
    def setUp(self):
        self.fixture = capture_fixture.PostinstallTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root, self.group = self.fixture.host, self.fixture.group
        self.plan_path = self.root / 'original-plan.json'
        self.plan_path.write_text(json.dumps(dict(schema='camera-offline-toolchain-plan/1',model='ILCE-7M4',
            reference_body_sha256='b' * 64, package_sha256=post.PACKAGE_SHA, plaintext_sha256=post.PLAIN_SHA,
            local_checks_passed=True, prepared_offline_only=True, execution_approval_received=False)))
        self.binding = dict(body_sha256='b' * 64, plan_sha256=sha(self.plan_path.read_bytes()), model='ILCE-7M4')
        self.fixture.binding = self.binding
        self.enterContext(patch.object(post.verifier, 'PLAIN', self.fixture.plain))
        self.enterContext(patch.object(post.verifier, 'FACTORY_P1', self.fixture.factory))
        self.session_dir = self.root / 'sessions' / 'post-attempt'
        self.session_dir.mkdir(parents=True)
        self.completion_path = self.root / 'completion.json'
        self.completion_path.write_text(json.dumps(dict(schema='camera-install-device-completion/1',
            **self.binding, state='DEVICE_COMPLETION_REPORTED', session_id=self.session_dir.name, model_fixture_only=True,
            reported_complete=True, updater_stopped_confirmed=True, normal_service_reentry_authorized=True)))
        self.completion_reference = dict(path=str(self.completion_path), sha256=sha(self.completion_path.read_bytes()))
        events = [dict(state='FLASH_MAY_HAVE_STARTED', event_sha256='1' * 64, details={}, binding=self.binding,
                       session_id=self.session_dir.name),
                  dict(state='DEVICE_COMPLETION_REPORTED', event_sha256='2' * 64,
                       details=dict(device_completion_artifact=self.completion_reference), binding=self.binding,
                       session_id=self.session_dir.name)]
        self.journal = InstallJournal(self.session_dir, events)
        self.enterContext(patch.object(post.InstallJournal, 'open', return_value=self.journal))
        self.enterContext(patch.object(post, 'assert_operation_allowed'))
        self.journal.advance = Mock()
        self.lease = self.enterContext(CameraDeviceLease('post-model', lock_path=self.root / 'lease'))
        self.enterContext(patch.object(post, 'DEFAULT_SESSIONS', self.root / 'global-sessions'))
        self.enterContext(patch.object(post, 'ATTEMPTS', self.root / 'attempts'))
        before = self.fixture.run['critical_settings']['before'] | self.binding
        (self.group / 'before-reference.json').write_text(json.dumps(before))
        descriptor = dict(schema='camera-capture-group/1', **self.binding, group_nonce=self.fixture.nonce,
                          journal_session=str(self.session_dir), acquisition_phase='PRE_INSTALL')
        (self.group / 'group.json').write_text(json.dumps(descriptor))
        files = [post._file_reference(self.group, self.group / name) for name in
                 ('before.bk4', 'before-reference.json', 'group.json')]
        terminal = dict(schema='camera-install-runtime-session-receipt/1',
            state='PRE_INSTALL_RUNTIME_TERMINAL_BEFORE_STOP', **self.binding,
            group_nonce=self.fixture.nonce, before_reference=before, evidence_files=files,
            source_is_hardware=False, normal_body_verified=True, service_exit_completed=False)
        terminal_path = self.group / 'runtime-terminal.json'
        terminal_path.write_text(json.dumps(terminal))
        runtime_exit = terminal | dict(state='PRE_INSTALL_RUNTIME_KNOWN_SERVICE_EXIT', service_exit_completed=True,
            original_journal_unchanged=True, service_events=[dict(event='STOP_RESPONSE', mode='service', success=True)],
            terminal_artifact=dict(path=str(terminal_path), sha256=sha(terminal_path.read_bytes()),
                                   payload_sha256=post.canonical_sha256(terminal)))
        (self.group / 'runtime-session-exit.json').write_text(json.dumps(runtime_exit))
        completion = json.loads(self.completion_path.read_text())
        completion['runtime_reference'] = post._reference(self.group / 'runtime-session-exit.json')
        self.completion_path.write_text(json.dumps(completion))
        self.completion_reference = post._reference(self.completion_path)
        self.journal._events[-1]['details']['device_completion_artifact'] = self.completion_reference
        for name in ('after.bk4', 'capture-run.json'):
            (self.group / name).unlink()
        for name in post.PROFILES:
            shutil.rmtree(self.group / name)
        self.enterContext(patch.object(post, 'PDT_BYTES', len((self.group / 'before.bk4').read_bytes())))
        native_rows = {name: dict(nonce=f'{index:02x}' * 16, module_sha256=f'{index}' * 64,
                                  manifest_sha256='f' * 64) for index, name in enumerate(post.PROFILES, 2)}
        self.assets = post.PostAssets(self.root / 'assets', *('f' * 64 for _ in post.PROFILES))
        reference = dict(schema='camera-install-post-assets/1', directory=str(self.assets.directory), profiles=native_rows)
        self.prepared = post.PreparedPostAssets(self.assets, post._canonical(reference), post._canonical(dict(sources={})))
        self.preflight = Mock(return_value=self.prepared)
        workspace = self.root / 'source-fixture';workspace.mkdir()
        source_names = ('camera_install_post_session.py', 'camera_install_post_plan.py')
        for name in source_names:
            (workspace / name).write_bytes((post.ROOT / name).read_bytes())
        self.enterContext(patch.object(post, 'ROOT', workspace))
        self.enterContext(patch.object(post, 'review_source_paths', return_value=source_names))
        self.enterContext(patch.object(plan, 'review_source_paths', return_value=source_names))
        self.enterContext(patch.object(plan, '_local', side_effect=lambda p, **kw: Path(p).absolute()))
        self.review_dir = self.root / 'review'
        result = plan.seal(self.review_dir, assets=self.assets, before_group=self.group,
            original_plan_reference=dict(path=str(self.plan_path), sha256=self.binding['plan_sha256']),
            completion_reference=self.completion_reference, body_sha256=self.binding['body_sha256'], preflight_fn=self.preflight)
        self.review_path, self.review_sha = Path(result['review_path']), result['review_sha256']
        self.calls = []
        def capture(device, name, folder, **kwargs):
            self.calls.append(name)
            self.assertIs(kwargs['source_is_hardware'], False)
            self.fixture.make_capture(name, self.fixture.payloads[name], native_rows[name]['nonce'])
            path = self.group / name / 'firmware-capture.json'
            report = json.loads(path.read_text())
            report['module_sha256'] = native_rows[name]['module_sha256']
            path.write_text(json.dumps(report))
            return report
        self.capture = Mock(side_effect=capture)
        self.pdt = Mock(return_value=self.fixture.template)
        def run(expected, work, **kwargs):
            self.calls.append('entry')
            kwargs['record_event'](dict(model='ILCE-7M4', body_matched=True))
            result = work(object())
            self.assertTrue((self.group / 'post-terminal.json').is_file())
            self.assertFalse((self.group / 'capture-run.json').exists())
            self.calls.append('STOP')
            kwargs['record_event'](dict(event='STOP_RESPONSE', mode='service', success=True))
            return result
        self.run = Mock(side_effect=run)

    def invoke(self, **changes):
        options = dict(plan_sha256=self.binding['plan_sha256'], review_path=self.review_path,
            review_sha256=self.review_sha, completion_reference=self.completion_reference,
            journal=self.journal, lease=self.lease, assets=self.assets, post_capture_authorized=True,
            run_session=self.run, capture_fn=self.capture, pdt_reader=self.pdt, preflight_fn=self.preflight)
        options.update(changes)
        return post.run_post_session(self.binding['body_sha256'], self.group, **options)

    def test_complete_group_is_durable_before_stop_and_verifies_without_transition(self):
        result = self.invoke()
        self.assertEqual(self.calls, ['entry', 'post_app', 'post_cp', 'post_p1', 'STOP'])
        self.assertTrue(result['verification']['all_passed'], result['verification']['pending'])
        self.assertFalse(result['verification']['source_is_hardware'])
        self.assertFalse(result['CONTENT_VERIFIED_recorded'])
        self.journal.advance.assert_not_called()
        for flag in post.FALSE_CLAIMS:
            self.assertIs(result[flag], False)
        run = json.loads((self.group / 'capture-run.json').read_text())
        self.assertEqual(run['critical_settings']['before']['nonce'], self.fixture.run['critical_settings']['before']['nonce'])
        self.assertTrue(run['known_service_STOP'])

    def test_missing_consent_or_partial_injection_performs_no_session(self):
        for changes in (dict(post_capture_authorized=False), dict(pdt_reader=None), dict(run_session=None)):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.invoke(**changes)
            self.run.assert_not_called()

    def test_before_completion_and_changed_completion_proof_are_rejected_before_entry(self):
        self.journal._events[-1]['state'] = 'FLASH_MAY_HAVE_STARTED'
        with self.assertRaises(ValueError):self.invoke()
        self.journal._events[-1]['state'] = 'DEVICE_COMPLETION_REPORTED'
        self.completion_path.write_text('{}')
        with self.assertRaises(ValueError):self.invoke()
        self.run.assert_not_called()

    def test_before_bytes_source_and_nonce_reuse_rejected_before_entry(self):
        path = self.group / 'before.bk4'
        path.write_bytes(b'changed')
        with self.assertRaises(ValueError):self.invoke()
        self.run.assert_not_called()

    def test_capture_failure_no_later_capture_or_stop(self):
        self.capture.side_effect = OSError('unknown capture')
        with self.assertRaises(OSError):self.invoke()
        self.assertEqual(self.calls, ['entry'])
        self.pdt.assert_not_called()
        self.journal.advance.assert_called_once()
        self.assertEqual(self.journal.advance.call_args.args[0], 'STOPPED_UNKNOWN')

    def test_terminal_fsync_failure_prevents_success_stop(self):
        def save(path, value):
            if Path(path).name == 'post-terminal.json':raise OSError('fsync unknown')
            durable_new(path, value)
        with patch.object(post, 'durable_new', side_effect=save), self.assertRaises(OSError):self.invoke()
        self.assertNotIn('STOP', self.calls)
        self.assertFalse((self.group / 'capture-run.json').exists())

    def test_unknown_stop_preserves_terminal_but_not_known_exit_or_capture_run(self):
        def unknown(expected, work, **kwargs):
            kwargs['record_event'](dict(model='ILCE-7M4', body_matched=True))
            work(object())
            raise OSError('STOP unknown')
        self.run.side_effect = unknown
        with self.assertRaises(OSError):self.invoke()
        self.assertTrue((self.group / 'post-terminal.json').exists())
        self.assertFalse((self.group / 'capture-run.json').exists())

    def test_bad_pdt_prevents_terminal_and_stop(self):
        self.pdt.return_value = b'x' * post.PDT_BYTES
        with self.assertRaises(ValueError):self.invoke()
        self.assertNotIn('STOP', self.calls)

    def test_used_nonce_and_source_tamper_are_zero_entry(self):
        row = self.prepared.reference['profiles']['post_cp']
        root = post.ROOT / 'output/install-patch-read-nonce-claims';root.mkdir(parents=True)
        (root / (row['nonce'] + '.json')).write_text('{}')
        with self.assertRaises(ValueError):self.invoke()
        self.run.assert_not_called()

    def test_changed_source_is_rejected_before_session(self):
        (post.ROOT / 'camera_install_post_session.py').write_text('changed')
        with self.assertRaises(ValueError):self.invoke()
        self.run.assert_not_called()

    def test_native_nonce_mismatch_stops_before_next_capture(self):
        original = self.capture.side_effect
        def changed(*args, **kwargs):
            report = original(*args, **kwargs)
            report['nonce'] = 'f' * 32
            (self.group / args[1] / 'firmware-capture.json').write_text(json.dumps(report))
            return report
        self.capture.side_effect = changed
        with self.assertRaises(ValueError):self.invoke()
        self.assertEqual(self.calls, ['entry', 'post_app'])
        self.pdt.assert_not_called()

    def test_lease_drift_during_capture_stops_before_next_request(self):
        original = self.capture.side_effect
        def changed(*args, **kwargs):
            report = original(*args, **kwargs)
            self.lease.__exit__(None, None, None)
            self.lease.__enter__()
            return report
        self.capture.side_effect = changed
        with self.assertRaises(ValueError):self.invoke()
        self.assertEqual(self.calls, ['entry', 'post_app'])
        self.pdt.assert_not_called()

    def test_unknown_after_stop_never_clears_or_records_content(self):
        def changed(expected, work, **kwargs):
            kwargs['record_event'](dict(model='ILCE-7M4', body_matched=True))
            result = work(object())
            (self.group / 'after.bk4').write_bytes(b'changed')
            kwargs['record_event'](dict(event='STOP_RESPONSE', mode='service', success=True))
            return result
        self.run.side_effect = changed
        with self.assertRaises(ValueError):self.invoke()
        self.assertFalse((self.group / 'verification.json').exists())
        self.journal.advance.assert_called_once()

    def test_completion_for_another_runtime_group_cannot_be_sealed(self):
        completion = json.loads(self.completion_path.read_text())
        completion['runtime_reference'] = dict(path=str(self.root / 'another-runtime.json'), sha256='f' * 64)
        self.completion_path.write_text(json.dumps(completion))
        reference = post._reference(self.completion_path)
        self.journal._events[-1]['details']['device_completion_artifact'] = reference
        with self.assertRaisesRegex(ValueError, 'does not bind original runtime group'):
            plan.seal(self.root / 'wrong-runtime-review', assets=self.assets, before_group=self.group,
                original_plan_reference=post._reference(self.plan_path), completion_reference=reference,
                body_sha256=self.binding['body_sha256'], preflight_fn=self.preflight)
        self.assertFalse((self.root / 'wrong-runtime-review').exists())
        self.run.assert_not_called()

    def test_known_settings_mismatch_does_not_record_content_or_claim_success(self):
        changed = dict(self.fixture.values)
        changed[capture_fixture.SLOTS[0]] = b'\xff'
        self.pdt.return_value = capture_fixture.bk4(changed)
        result = self.invoke()
        self.assertIn('STOP', self.calls)
        self.assertFalse(result['content_checks_passed'])
        self.assertFalse(result['verification']['all_passed'])
        self.assertFalse(result['CONTENT_VERIFIED_recorded'])
        self.journal.advance.assert_not_called()

    def test_replay_cannot_enter_again(self):
        self.invoke()
        with self.assertRaises(ValueError):self.invoke()
        self.assertEqual(self.run.call_count, 1)

    def test_no_default_io_from_model_context(self):
        with self.assertRaises(ValueError):
            self.invoke(run_session=None, capture_fn=None, pdt_reader=None, preflight_fn=None)
        self.run.assert_not_called()


if __name__ == '__main__':unittest.main()
