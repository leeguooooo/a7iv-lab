from copy import deepcopy
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

import camera_install_cancel_session as session
import test_camera_install_cancel as fixtures
from camera_install_journal import InstallJournal


class CancellationSessionTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.CancellationAssessmentTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        f = self.fixture
        self.folder = f.session.root / 'cancel-evidence'
        self.folder.mkdir()
        self.history = f.session.journal.events
        self.card_calls = []
        self.read = Mock(side_effect=self.complete_read)
        self.proof = dict(observation='ORIGINAL', targets={k: dict(observation='ORIGINAL') for k in ('lib','app')})
        self.validated = None
        self.enterContext(patch.object(session, 'validate_completed_current_read', side_effect=self.validate_read))
        self.enterContext(patch.object(session, 'DEFAULT_SESSIONS', f.session.root / 'absent-global'))

    def complete_read(self, body, folder, **kwargs):
        value = dict(schema='fixture-completed-read', state='CURRENT_READ_KNOWN_SERVICE_EXIT',
            source_is_hardware=True, service_exit_completed=True,
            lease_identity=session._held_lease(self.fixture.session.lease),
            current_review=dict(path=str(Path(kwargs['review_path']).absolute()),sha256=kwargs['review_sha256']),raw_publications={'ready':'fixture','result':'fixture'})
        path = Path(folder) / 'current-read-session-exit.json'
        path.write_text(json.dumps(value))
        self.validated = deepcopy(value)
        return value

    def validate_read(self, reference, **kwargs):
        raw = Path(reference['path']).read_bytes()
        if hashlib.sha256(raw).hexdigest() != reference['sha256']:
            raise ValueError('Completed receipt changed')
        value = json.loads(raw)
        if value != self.validated:
            raise ValueError('Completed read differs')
        return dict(receipt=value, reference=reference, proof=deepcopy(self.proof), source_is_hardware=value['source_is_hardware'])

    def invoke(self, **changes):
        f = self.fixture
        options = dict(plan_sha256=f.session.plan, pending_reference=f.pending_reference,
            stage_reference=f.reference, read_assets=object(), read_review_path='fixture-review',
            read_review_sha256='a'*64, journal=f.session.journal, lease=f.session.lease,
            cancellation_authorized=True, card_read_authorized=True,
            operator_health_confirmed=True, operator_never_started_confirmed=True,
            read_session=self.read, discover=f.discover)
        options.update(changes)
        return session.run_cancellation_session(f.body, self.folder, **options)

    def test_injection_source_true_remains_assessment_and_journal_pending(self):
        result = self.invoke()
        self.assertEqual(result['state'], 'CANCELLATION_ASSESSED_ONLY')
        self.assertFalse(result['source_is_hardware'])
        self.assertFalse(result['cancellation_recorded'])
        self.assertEqual(self.fixture.session.journal.events, self.history)
        self.assertTrue((self.folder/'cancellation-assessment.json').is_file())
        self.assertTrue(result['both_targets_currently_original'])
        self.assertFalse(result['RAM_restoration_proven'])
        self.assertFalse(result['original_mm_continuity_proven'])

    def test_mixed_injection_and_missing_consent_precede_read(self):
        for changes in (dict(read_session=None),dict(discover=None),dict(cancellation_authorized=False),
                        dict(card_read_authorized=False),dict(operator_health_confirmed=False),
                        dict(operator_never_started_confirmed=False)):
            with self.subTest(changes=changes), self.assertRaises(ValueError):self.invoke(**changes)
        self.read.assert_not_called()

    def test_nonoriginal_is_durable_blocked_without_card_reads(self):
        self.proof['observation']='PATCHED'
        self.proof['targets']['lib']['observation']='PATCHED'
        result=self.invoke()
        self.assertEqual(result['state'],'CANCELLATION_BLOCKED_CURRENT_OBSERVATION')
        self.assertTrue(result['separately_authorized_cleanup_required'])
        self.fixture.discover.assert_not_called()
        self.assertEqual(self.fixture.session.journal.events,self.history)

    def test_unknown_read_never_observes_card_or_closes(self):
        self.read.side_effect=OSError('unknown STOP')
        with self.assertRaises(OSError):self.invoke()
        self.fixture.discover.assert_not_called()
        self.assertEqual(self.fixture.session.journal.events,self.history)
        self.assertTrue((self.folder/'cancellation-unknown.json').is_file())

    def test_changed_lease_after_read_blocks_card_and_close(self):
        def changed(*args,**kwargs):
            value=self.complete_read(*args,**kwargs)
            self.fixture.session.lease.__exit__(None,None,None)
            self.fixture.session.lease.__enter__()
            return value
        self.read.side_effect=changed
        with self.assertRaisesRegex(ValueError,'lease'):self.invoke()
        self.fixture.discover.assert_not_called()

    def test_active_candidate_refused_without_card_writes(self):
        self.fixture.root_update.write_bytes(self.fixture.payload)
        with self.assertRaises(ValueError):self.invoke()
        self.assertEqual(self.fixture.root_update.read_bytes(),self.fixture.payload)
        self.assertEqual(self.fixture.session.journal.events,self.history)

    def test_completed_receipt_mutation_refused_before_card(self):
        def forged(*args,**kwargs):
            value=self.complete_read(*args,**kwargs)
            value['extra']='different from saved'
            return value
        self.read.side_effect=forged
        with self.assertRaises(ValueError):self.invoke()
        self.fixture.discover.assert_not_called()

    def test_stale_journal_refused_before_read(self):
        self.fixture.session.journal.advance('STOPPED_UNKNOWN')
        with self.assertRaises(ValueError):self.invoke()
        self.read.assert_not_called()

    def terminal_fixture(self):
        report=self.invoke()
        report.update(state=session.TERMINAL,producer_kind=session.DEFAULT_PRODUCER,
            source_is_hardware=True,injected_execution=False,card_collector_kind='DEFAULT_FILESYSTEM_DISCOVERY')
        path=self.folder/'fixture-terminal.json'
        path.write_text(json.dumps(report))
        return path,report

    def validate(self,path):
        return session.validate_cancellation_receipt(session._reference(path),self.fixture.session.journal.binding,
            self.history,self.fixture.session.journal.session_dir)

    def test_historical_validator_replays_complete_read_card_bindings(self):
        path,report=self.terminal_fixture()
        self.assertEqual(self.validate(path),report)
        self.fixture.discover.assert_called()
        self.assertFalse(report['original_mm_continuity_proven'])

    def test_historical_validator_rejects_injected_assessment(self):
        self.invoke()
        with self.assertRaises(ValueError):self.validate(self.folder/'cancellation-assessment.json')

    def test_historical_validator_rejects_each_scope_assertion_and_binding_change(self):
        path,report=self.terminal_fixture()
        changes=[dict(source_is_hardware=False),dict(synthetic=True),dict(injected_execution=True),dict(producer_kind='INJECTED_ASSESSMENT'),
            dict(operator_health_confirmed=False),dict(operator_never_started_confirmed=False),
            dict(RAM_restoration_proven=True),dict(installation_authorized=True),
            dict(history_sha256='0'*64),dict(body_sha256='0'*64),dict(cancellation_recorded=True),
            dict(completed_read_payload_sha256='0'*64),dict(card_collector_kind='INJECTED_FILESYSTEM_DISCOVERY')]
        for change in changes:
            with self.subTest(change=change):
                path.write_text(json.dumps(report|change))
                with self.assertRaises(ValueError):self.validate(path)

    def test_historical_validator_rejects_changed_candidate_or_original_even_rehashed(self):
        path,report=self.terminal_fixture()
        for target in ('candidate','root_update'):
            changed=deepcopy(report)
            card=changed['card_evidence']
            card[target]['sha256']='0'*64
            card['evidence_sha256']=hashlib.sha256(session.assessment._canonical(
                {k:v for k,v in card.items() if k!='evidence_sha256'})).hexdigest()
            changed['card_evidence_sha256']=session.canonical_sha256(card)
            path.write_text(json.dumps(changed))
            with self.subTest(target=target), self.assertRaises(ValueError):self.validate(path)

    def test_changed_handles_during_card_read_refused(self):
        f=self.fixture
        f.discover.side_effect=[dict(f.volume),dict(f.volume),dict(f.volume,registry_id=999)]
        with self.assertRaisesRegex(ValueError,'handles changed'):self.invoke()
        self.assertEqual(f.session.journal.events,self.history)

    def test_changed_stage_after_read_refused(self):
        def changed(*args,**kwargs):
            value=self.complete_read(*args,**kwargs)
            self.fixture.stage_path.write_text('{}')
            return value
        self.read.side_effect=changed
        with self.assertRaises(ValueError):self.invoke()
        self.fixture.discover.assert_not_called()

    def test_default_route_rejects_noncanonical_before_read_or_assets(self):
        with self.assertRaisesRegex(ValueError,'canonical'):
            self.invoke(read_session=None,discover=None)
        self.read.assert_not_called()

    def test_failed_cancellation_persistence_never_closes(self):
        actual=session.durable_new
        def fail(path,value):
            if Path(path).name=='cancellation-assessment.json':raise OSError('fsync failed')
            return actual(path,value)
        with patch.object(session,'durable_new',side_effect=fail), self.assertRaises(OSError):self.invoke()
        self.assertEqual(self.fixture.session.journal.events,self.history)

    def invoke_default_control_path(self, record):
        f=self.fixture
        import camera_install_patch_read_execution as execution
        import camera_install_patch_read_session as reader
        import camera_sd_stage
        with patch.object(session,'DEFAULT_LOCK',f.session.lease.path), \
             patch.object(session,'DEFAULT_SESSIONS',f.session.journal.session_dir.parent), \
             patch.object(session,'_source_only_runtime'), \
             patch.object(execution,'preflight_assets',return_value=object()), \
             patch.object(reader,'validate_review',return_value={'review':'offline boundary fixture'}), \
             patch.object(reader,'run_current_read_session',side_effect=self.read), \
             patch.object(camera_sd_stage,'discover',side_effect=f.discover), \
             patch.object(InstallJournal,'record_install_preparation_cancelled',side_effect=record,create=True):
            return self.invoke(read_session=None,discover=None)

    def test_default_control_path_persists_and_revalidates_before_journal_method(self):
        calls=[]
        def record(path,**options):
            self.assertIs(options['explicit_user_approval'],True)
            self.assertTrue(Path(path).is_file())
            report=self.validate(path)
            self.assertEqual(report['state'],session.TERMINAL)
            self.assertFalse(report['cancellation_recorded'])
            calls.append(str(path))
            return dict(state=session.TERMINAL)
        result=self.invoke_default_control_path(record)
        self.assertEqual(len(calls),1)
        self.assertTrue(result['cancellation_recorded'])
        self.assertEqual(self.fixture.session.journal.events,self.history)

    def test_uncertain_journal_append_leaves_durable_evidence_and_no_retry(self):
        calls=[]
        def fail(path,**options):
            calls.append(path)
            self.validate(path)
            target=self.fixture.session.journal.session_dir/f'{len(self.history)+1:08d}.json'
            target.write_bytes(b'{\"partial\":')
            raise OSError('append fsync unknown')
        with self.assertRaises(OSError):self.invoke_default_control_path(fail)
        self.assertEqual(len(calls),1)
        self.assertTrue((self.folder/'preparation-cancellation.json').is_file())
        self.assertTrue((self.folder/'cancellation-unknown.json').is_file())
        unknown=json.loads((self.folder/'cancellation-unknown.json').read_text())
        self.assertTrue(unknown['journal_append_attempted'])
        self.assertTrue(unknown['journal_may_have_changed'])
        self.assertFalse(unknown['journal_not_automatically_changed'])

    def test_real_frame_and_completed_terminal_validators_on_injected_session(self):
        import camera_install_receipts as receipts
        import camera_install_patch_read as contract
        import test_camera_install_patch_read as frames
        f=self.fixture
        spec=contract.derive_target_spec(Path(f.pending_reference['path']).read_bytes(),
            body_sha256=f.body,plan_sha256=f.session.plan)
        nonce=b'r'*16
        ready,result=frames.rows(spec,('ORIGINAL','ORIGINAL'))
        raws={name:frames.pack(row,spec,nonce).hex() for name,row in (('ready',ready),('result',result))}
        proof=contract.validate_publications(bytes.fromhex(raws['ready']),bytes.fromhex(raws['result']),
            nonce=nonce,loader_pid=678,spec=spec)
        def completed(body,folder,**kwargs):
            ref=dict(nonce=nonce.hex(),pending_reference=f.pending_reference,body_sha256=f.body,
                plan_sha256=f.session.plan,target_spec_sha256=contract.spec_sha256(spec))
            self.raw_read_reference=ref
            native=deepcopy(proof)|dict(asset_reference=ref,reservation={'fixture':'owned'},source_is_hardware=False)
            terminal=dict(schema='camera-install-patch-read-session-receipt/1',
                state='CURRENT_READ_TERMINAL_DURABLE_BEFORE_STOP',body_sha256=f.body,
                original_plan_sha256=f.session.plan,original_session_id=f.session.journal.session_dir.name,
                original_pending_reference=f.pending_reference,original_pending_event_sha256=self.history[-1]['event_sha256'],
                original_history_sha256=session.canonical_sha256(self.history),asset_reference=ref,
                reservation=native['reservation'],native_receipt=native,
                native_receipt_sha256=session.canonical_sha256(native),source_is_hardware=False,original_source_declaration=False,
                service_exit_completed=False,lease_identity=session._held_lease(f.session.lease),
                current_review=dict(path=str(Path(kwargs['review_path']).absolute()),sha256=kwargs['review_sha256']))
            terminal_path=Path(folder)/'current-read-session-terminal.json'
            terminal_path.write_text(json.dumps(terminal))
            terminal_ref=session._reference(terminal_path)|dict(payload_sha256=session.canonical_sha256(terminal))
            value=terminal|dict(state='CURRENT_READ_KNOWN_SERVICE_EXIT',service_exit_completed=True,
                terminal_artifact=terminal_ref,original_journal_unchanged=True,
                service_events=[dict(event='STOP_RESPONSE',mode='service',success=True)])
            (Path(folder)/'current-read-session-exit.json').write_text(json.dumps(value))
            return value
        def reviewed(reference,**kwargs):
            if 'camera_install_patch.py' in kwargs['required_sources']:
                return json.loads(f.session.review.read_text())
            return dict(schema='camera-install-patch-read-session-plan/1',asset_reference=self.raw_read_reference,
                pending_reference=f.pending_reference,body_sha256=f.body,original_plan_sha256=f.session.plan)
        with patch.object(session,'validate_completed_current_read',side_effect=receipts.validate_completed_current_read), \
             patch.object(receipts,'historical_native',return_value={'sources':{}}), \
             patch.object(receipts,'historical_review',side_effect=reviewed):
            self.read.side_effect=completed
            observed=self.invoke()
            self.folder=self.folder.parent/'corrupt-frame-evidence'
            self.folder.mkdir()
            def corrupt(*args,**kwargs):
                value=completed(*args,**kwargs)
                value['native_receipt']['raw_publications']['ready']='00'
                value['native_receipt_sha256']=session.canonical_sha256(value['native_receipt'])
                terminal=deepcopy(value)
                for key in ('terminal_artifact','service_events','original_journal_unchanged'):terminal.pop(key)
                terminal.update(state='CURRENT_READ_TERMINAL_DURABLE_BEFORE_STOP',service_exit_completed=False)
                path=Path(args[1])/'current-read-session-terminal.json'
                path.write_text(json.dumps(terminal))
                value['terminal_artifact']=session._reference(path)|dict(payload_sha256=session.canonical_sha256(terminal))
                (Path(args[1])/'current-read-session-exit.json').write_text(json.dumps(value))
                return value
            self.read.side_effect=corrupt
            f.discover.reset_mock()
            with self.assertRaises(ValueError):self.invoke()
            f.discover.assert_not_called()
        self.assertTrue(observed['both_targets_currently_original'])
        self.assertFalse(observed['source_is_hardware'])
        self.assertFalse(observed['cancellation_recorded'])
        self.assertEqual(observed['current_read_proof'],proof)

    def test_real_journal_append_reopen_and_terminal_barrier(self):
        from camera_install_journal import JournalError,assert_no_pending_installs
        path,report=self.terminal_fixture()
        journal=self.fixture.session.journal
        with self.assertRaises(JournalError):journal.advance(session.TERMINAL)
        with self.assertRaises(JournalError):journal.record_install_preparation_cancelled(path)
        event=journal.record_install_preparation_cancelled(path,explicit_user_approval=True)
        self.assertEqual(event['state'],session.TERMINAL)
        self.assertEqual(event['details']['complete_receipt_sha256'],session.canonical_sha256(report))
        reopened=InstallJournal.open(journal.session_dir)
        self.assertEqual(reopened.events,journal.events)
        self.assertEqual(reopened.state,session.TERMINAL)
        assert_no_pending_installs(journal.session_dir.parent)
        for state in ('INSTALL_READY_FOR_OPERATOR_START','FLASH_MAY_HAVE_STARTED','RAM_RESTORATION_VERIFIED'):
            with self.subTest(state=state),self.assertRaises(JournalError):reopened.advance(state)
        path.write_text('{}')
        with self.assertRaises((ValueError,JournalError)):InstallJournal.open(journal.session_dir)

    def test_real_journal_rejects_injected_assessment_and_stale_history(self):
        from camera_install_journal import JournalError
        self.invoke()
        journal=self.fixture.session.journal
        with self.assertRaises((ValueError,JournalError)):
            journal.record_install_preparation_cancelled(self.folder/'cancellation-assessment.json',explicit_user_approval=True)
        self.assertEqual(journal.events,self.history)
