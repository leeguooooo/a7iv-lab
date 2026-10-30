"""Filesystem protocol integration tests use temporary host files only."""
import copy
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

import camera_sd_stage as stage
import camera_install_bundle as bundle
import camera_install_flow as flow
from tools import card_backup_replace as replacement
from tools import card_protocol_probe as probe
import test_camera_sd_stage as fixture
import test_camera_install_flow as flow_fixture
import test_camera_install_card_withdraw as withdraw_fixture


class ReplacementActivationTests(unittest.TestCase):
    setUp = fixture.StageTests.setUp
    folder = fixture.StageTests.folder

    def prepare(self):
        stage.stage()
        self.model_flow=self.root/'model-flow'
        self.actual_flow_producer=probe._flow_producer
        self.stack.enter_context(patch.object(probe,'_flow_producer',return_value={'flow_directory':str(self.model_flow)}))
        self.probe_ref = probe.probe(self.mount, self.root/'probe-evidence',
            expected_card_identity=self.volume, identity_reader=lambda: self.volume,
            scratch_authorized=True, single_writer_acknowledged=True)

    def activate(self, **changes):
        options=dict(activation_authorized=True, slot1_confirmed=True,
            protocol=stage.BACKUP_COPY_ATOMIC_REPLACE, single_writer_acknowledged=True,
            compatibility_probe_reference=self.probe_ref,flow_directory=getattr(self,'model_flow',self.root/'model-flow'))
        options.update(changes)
        return stage.activate_staged(**options)

    def test_round_trip_probe_changes_only_owned_scratch_files(self):
        self.prepare()
        self.assertEqual(self.body.read_bytes(),self.original)
        self.assertEqual((self.folder/'candidate.staged').read_bytes(),self.payload)
        proof=probe.validate_probe(self.probe_ref,self.volume,flow_directory=self.model_flow)
        self.assertFalse(proof['business_filenames_modified'])
        forward=probe.read_reference(proof['forward_reference'])
        reverse=probe.read_reference(proof['reverse_reference'])
        self.assertEqual(forward['operation'],'ACTIVATE')
        self.assertEqual(reverse['operation'],'WITHDRAW')
        self.assertTrue(reverse['original_backup_source_absent'])

    def test_new_activation_preserves_old_bytes_and_publishes_complete_candidate(self):
        self.prepare()
        result=self.activate()
        self.assertEqual(self.body.read_bytes(),self.payload)
        self.assertEqual((self.folder/'original-BODYDATA.DAT').read_bytes(),self.original)
        self.assertFalse((self.folder/'candidate.staged').exists())
        self.assertFalse(result['updater_invoked'])
        ref=probe.reference(self.report/'activated-preview-only.json')
        self.assertEqual(stage.validate_activation_receipt_protocol(result,ref),stage.BACKUP_COPY_ATOMIC_REPLACE)

    def test_new_protocol_requires_ack_before_discovery_or_card_changes(self):
        self.probe_ref=None
        for value in (False,1,'yes',None):
            with self.subTest(value=value),self.assertRaises(ValueError):
                self.activate(single_writer_acknowledged=value)
        self.discover.assert_not_called()
        self.assertEqual(self.body.read_bytes(),self.original)

    def test_missing_real_filesystem_probe_prevents_business_write(self):
        stage.stage();self.probe_ref=None
        with self.assertRaises(ValueError):self.activate()
        self.assertEqual(self.body.read_bytes(),self.original)
        self.assertFalse((self.folder/'original-BODYDATA.DAT').exists())
        self.assertFalse((self.report/'activation-intent.json').exists())

    def test_default_unsupported_exclusive_mode_never_falls_back(self):
        stage.stage()
        capability={'interfaces':{'RENAME_EXCL':{'valid':True,'declared_supported':False}}}
        with patch('tools.volume_capabilities.inspect',return_value=capability), \
             patch.object(stage,'rename_exclusive') as rename, \
             patch.object(replacement,'replace_with_backup') as replace:
            with self.assertRaisesRegex(ValueError,'exclusive rename support'):
                stage.activate_staged(activation_authorized=True,slot1_confirmed=True)
        rename.assert_not_called();replace.assert_not_called()
        self.assertFalse((self.report/'activation-intent.json').exists())
        self.assertEqual(self.body.read_bytes(),self.original)

    def test_unknown_protocol_refused_before_discovery(self):
        self.probe_ref=None
        for value in ('automatic-fallback',False,None):
            with self.subTest(value=value),self.assertRaises(ValueError):self.activate(protocol=value)
        self.discover.assert_not_called()

    def test_probe_reconnect_uses_stable_body_card_identity(self):
        self.prepare()
        changed=dict(self.volume,device='disk901s1',parent='disk901',registry_id=901,mount='/unavailable/old-metadata-only')
        probe.validate_probe(self.probe_ref,changed,flow_directory=self.model_flow)
        for key in probe.STABLE_KEYS:
            changed=dict(self.volume,**{key:'different'})
            with self.subTest(key=key),self.assertRaises(ValueError):probe.validate_probe(self.probe_ref,changed,flow_directory=self.model_flow)

    def test_missing_enclosing_actor_completion_cannot_validate_inner_completed(self):
        self.prepare();result=self.activate()
        with self.assertRaises(ValueError):stage.validate_activation_receipt_protocol(result)
        actor=self.report/'activated-preview-only.json'
        ref=probe.reference(actor);actor.unlink()
        with self.assertRaises(ValueError):stage.validate_activation_receipt_protocol(result,ref)

    def test_contradictory_inner_stopped_evidence_rejects_enclosing_success(self):
        self.prepare();result=self.activate()
        (self.report/'replacement-evidence/stopped.json').write_text('{"state":"UNKNOWN"}')
        with self.assertRaisesRegex(ValueError,'Contradictory stopped'):
            stage.validate_activation_receipt_protocol(result,probe.reference(self.report/'activated-preview-only.json'))

    def test_completion_file_without_outer_success_is_not_published_on_exception(self):
        self.prepare();actual=replacement.replace_with_backup
        def completed_then_failed(*args,**kwargs):
            actual(*args,**kwargs)
            raise replacement.ReplacementError('COMPLETED_DIRECTORY_SYNC_FAILED',args[1])
        with patch.object(replacement,'replace_with_backup',side_effect=completed_then_failed):
            with self.assertRaises(replacement.ReplacementError):self.activate()
        self.assertTrue((self.report/'replacement-evidence/completed.json').is_file())
        self.assertFalse((self.report/'replacement-evidence/stopped.json').exists())
        self.assertFalse((self.report/'activated-preview-only.json').exists())
        self.assertTrue((self.report/'activation-stopped.json').is_file())
        self.assertEqual(self.body.read_bytes(),self.payload)
        self.assertEqual((self.folder/'original-BODYDATA.DAT').read_bytes(),self.original)

    def test_probe_does_not_publish_outer_completion_after_inner_completed_exception(self):
        actual=replacement.withdraw_with_backup
        def completed_then_failed(*args,**kwargs):
            actual(*args,**kwargs)
            raise replacement.ReplacementError('COMPLETED_DIRECTORY_SYNC_FAILED',args[1])
        with patch.object(replacement,'withdraw_with_backup',side_effect=completed_then_failed):
            with self.assertRaises(replacement.ReplacementError):probe.probe(self.mount,self.root/'failed-probe',
                expected_card_identity=self.volume,identity_reader=lambda:self.volume,
                scratch_authorized=True,single_writer_acknowledged=True)
        self.assertTrue((self.root/'failed-probe/withdraw/completed.json').is_file())
        self.assertFalse((self.root/'failed-probe/completed.json').exists())
        self.assertEqual(self.body.read_bytes(),self.original)

    def test_nested_replace_intent_hash_is_required(self):
        self.prepare();result=self.activate()
        intent=self.report/'replacement-evidence/replace-intent.json'
        value=json.loads(intent.read_text());value['extra']='tampered';intent.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError,'SHA256'):
            stage.validate_activation_receipt_protocol(result,probe.reference(self.report/'activated-preview-only.json'))

    def test_orphan_outer_probe_completed_file_is_rejected_by_unknown_controller(self):
        from types import SimpleNamespace
        evidence=self.root/'outer-probe-failure'
        actual=probe._sync
        def failed(path):
            actual(path)
            if path==evidence and (path/'completed.json').exists():raise OSError('outer directory sync failed')
        with patch.object(probe,'_sync',side_effect=failed):
            with self.assertRaises(OSError):probe.probe(self.mount,evidence,
                expected_card_identity=self.volume,identity_reader=lambda:self.volume,
                scratch_authorized=True,single_writer_acknowledged=True)
        ref=probe.reference(evidence/'completed.json')
        unknown=[{'step':'probe','phase':'UNKNOWN','source_is_hardware':False}]
        context=(self.root/'flow',{'injected_execution':False},
                 {'card_activation_protocol':stage.BACKUP_COPY_ATOMIC_REPLACE,'body_sha256':self.volume['body_sha256']},
                 unknown,SimpleNamespace(binding={}))
        with patch.object(flow,'_open',return_value=context):
            with self.assertRaisesRegex(ValueError,'Successful enclosing actor flow'):
                probe.validate_probe(ref,self.volume,flow_directory=self.root/'flow')

    def test_config_protocol_is_validated_before_other_config_fields(self):
        with patch.object(flow,'_load',return_value={'card_activation_protocol':'UNKNOWN'}):
            with self.assertRaisesRegex(ValueError,'Unknown card activation protocol'):flow.validate_config({})

    def test_bundle_unknown_protocol_is_rejected_before_creating_output(self):
        with self.assertRaisesRegex(ValueError,'Unknown card activation protocol'):
            bundle.seal_bundle(self.root,self.root/'new-output',body_reference=self.root/'unused',card_activation_protocol='UNKNOWN')
        self.assertFalse((self.root/'new-output').exists())


class ReplacementWithdrawalTests(unittest.TestCase):
    setUp = fixture.StageTests.setUp
    folder = fixture.StageTests.folder
    prepare = ReplacementActivationTests.prepare
    activate = ReplacementActivationTests.activate

    def context(self):
        import camera_install_card_withdraw as withdraw
        from camera_install_journal import InstallJournal
        from camera_device_lease import CameraDeviceLease
        self.prepare();self.activation=self.activate()
        self.stage_ref=probe.reference(self.report/'completed.json')
        self.activation_ref=probe.reference(self.report/'activated-preview-only.json')
        sessions=self.root/'sessions';sessions.mkdir()
        self.journal=InstallJournal.create(sessions,'staged',plan_sha256='b'*64,
            body_sha256=self.volume['body_sha256'],model='ILCE-7M4')
        self.journal.advance('SD_STAGE_INTENT')
        self.journal.advance('SD_STAGED',details={'stage_report':self.stage_ref['path'],'stage_report_sha256':self.stage_ref['sha256']})
        self.host_lease=self.stack.enter_context(CameraDeviceLease('model-withdraw',lock_path=self.root/'model.lock'))
        self.stack.enter_context(patch.object(withdraw,'DEFAULT_SESSIONS',sessions))
        self.stack.enter_context(patch.object(withdraw.card,'CANDIDATE_SHA256',self.sha))
        self.stack.enter_context(patch.object(withdraw.card,'CANDIDATE_BYTES',len(self.payload)))
        self.withdraw_evidence=self.root/'withdraw';self.withdraw_evidence.mkdir()
        return withdraw

    def invoke(self,module,**changes):
        values=dict(body_sha256=self.volume['body_sha256'],plan_sha256='b'*64,
            lease=self.host_lease,journal=self.journal,withdrawal_authorized=True,
            operator_never_started_confirmed=True,operator_health_confirmed=True,
            discover=self.discover,replacement_fn=replacement.withdraw_with_backup,
            single_writer_acknowledged=True,compatibility_probe_reference=self.probe_ref,flow_directory=self.model_flow)
        values.update(changes)
        return module.withdraw_staged_card(self.stage_ref,self.activation_ref,self.withdraw_evidence,**values)

    def test_inverse_restores_old_root_retains_candidate_and_validates_full_history(self):
        module=self.context();before=self.journal.events;result=self.invoke(module)
        self.assertEqual(self.body.read_bytes(),self.original)
        self.assertEqual((self.folder/'candidate.staged').read_bytes(),self.payload)
        self.assertFalse((self.folder/'original-BODYDATA.DAT').exists())
        self.assertEqual(result['renames'],[dict(source=str(self.folder/'original-BODYDATA.DAT'),target=str(self.body))])
        self.assertTrue(result['card_contents_modified']);self.assertTrue(result['candidate_copy_created'])
        self.assertFalse(result['source_is_hardware']);self.assertFalse(result['updater_invoked'])
        proof=module.validate_staged_withdrawal_receipt(probe.reference(self.withdraw_evidence/'withdrawal-completed.json'),
            binding=self.journal.binding,history=self.journal.events,session_dir=self.journal.session_dir,stage_reference=self.stage_ref)
        self.assertEqual(proof['receipt'],result);self.assertEqual(self.journal.events,before)

    def test_inverse_needs_new_single_writer_acknowledgement(self):
        module=self.context()
        with self.assertRaisesRegex(ValueError,'single-writer withdrawal'):
            self.invoke(module,single_writer_acknowledged=False)
        self.assertEqual(self.body.read_bytes(),self.payload)
        self.assertFalse((self.folder/'candidate.staged').exists())

    def test_inverse_exception_after_inner_completed_never_publishes_outer_success(self):
        module=self.context();actual=replacement.withdraw_with_backup
        def failed(*args,**kwargs):
            actual(*args,**kwargs)
            raise replacement.ReplacementError('COMPLETED_DIRECTORY_SYNC_FAILED',args[1])
        with self.assertRaises(replacement.ReplacementError):self.invoke(module,replacement_fn=failed)
        self.assertTrue((self.withdraw_evidence/'replacement-evidence/completed.json').exists())
        self.assertFalse((self.withdraw_evidence/'withdrawal-completed.json').exists())
        self.assertTrue((self.withdraw_evidence/'withdrawal-unknown.json').exists())
        self.assertEqual(self.journal.state,'SD_STAGED')

    def test_inverse_outer_completion_publication_failure_is_rejected(self):
        module=self.context();actual=module.durable_new
        def failed(path,value):
            actual(path,value)
            if path.name=='withdrawal-completed.json':raise OSError('completion directory sync failed')
        with patch.object(module,'durable_new',side_effect=failed):
            with self.assertRaises(OSError):self.invoke(module)
        self.assertTrue((self.withdraw_evidence/'withdrawal-completed.json').is_file())
        with self.assertRaisesRegex(ValueError,'Contradictory unknown'):
            module.validate_staged_withdrawal_receipt(probe.reference(self.withdraw_evidence/'withdrawal-completed.json'),
                binding=self.journal.binding,history=self.journal.events,session_dir=self.journal.session_dir,stage_reference=self.stage_ref)

    def test_inverse_orphan_outer_completion_without_unknown_needs_actual_flow_success(self):
        module=self.context();actual=module.durable_new
        def failed(path,value):
            if path.name=='withdrawal-unknown.json':raise OSError('no space for unknown record')
            actual(path,value)
            if path.name=='withdrawal-completed.json':raise OSError('completion directory sync failed')
        with patch.object(module,'durable_new',side_effect=failed):
            with self.assertRaises(OSError):self.invoke(module)
        self.assertTrue((self.withdraw_evidence/'withdrawal-completed.json').is_file())
        self.assertFalse((self.withdraw_evidence/'withdrawal-unknown.json').exists())
        with patch.object(probe,'_flow_producer',self.actual_flow_producer):
            with self.assertRaises(ValueError):
                module.validate_staged_withdrawal_receipt(probe.reference(self.withdraw_evidence/'withdrawal-completed.json'),
                    binding=self.journal.binding,history=self.journal.events,session_dir=self.journal.session_dir,stage_reference=self.stage_ref)


class ProbeControllerTests(unittest.TestCase):
    setUp=flow_fixture.FlowTests.setUp
    step=flow_fixture.FlowTests.step

    def test_orphan_probe_completion_after_exception_is_not_a_completed_flow_step(self):
        self.step('runtime')
        def failed(step,context):
            (context['evidence']/'completed.json').write_text('{"state":"ROUND_TRIP_COMPLETED"}')
            raise OSError('outer probe publication failed')
        with self.assertRaises(OSError):self.step('probe',injector=failed)
        status=flow.status(self.folder)
        self.assertEqual(status['unresolved_steps'],['probe'])
        self.assertNotIn('probe',status['completed_steps'])
        _,_,_,events,_=flow._open(self.folder)
        with self.assertRaises(ValueError):flow._artifact(events,'probe')

    def test_new_activation_ignores_operator_supplied_orphan_probe_reference(self):
        config=dict(body_sha256='b'*64,original_plan_reference={'sha256':'c'*64},
                    card_activation_protocol=stage.BACKUP_COPY_ATOMIC_REPLACE)
        def artifact(events,name):
            if name=='probe':raise ValueError('Required completed flow step missing: probe')
            return {'path':'/MODEL'}
        with patch.object(flow,'_artifact',side_effect=artifact),patch.object(stage,'activate_staged') as activate:
            with self.assertRaisesRegex(ValueError,'probe'):
                flow._dispatch('activate',self.root/'target',config,[],None,None,
                    {'slot1_confirmed':True,'single_writer_acknowledged':True,
                     'compatibility_probe_reference':{'path':'/orphan/completed.json','sha256':'d'*64}})
        activate.assert_not_called()


class LegacyWithdrawalUnknownTests(unittest.TestCase):
    setUp=withdraw_fixture.WithdrawTests.setUp
    exclusive=withdraw_fixture.WithdrawTests.exclusive
    invoke=withdraw_fixture.WithdrawTests.invoke
    validate_completed=withdraw_fixture.WithdrawTests.validate_completed

    def test_legacy_completed_file_and_unknown_outcome_are_contradictory(self):
        import camera_install_card_withdraw as withdraw
        actual=withdraw.durable_new
        def failed(path,value):
            actual(path,value)
            if path.name=='withdrawal-completed.json':raise OSError('completion directory sync failed')
        with patch.object(withdraw,'durable_new',side_effect=failed):
            with self.assertRaises(OSError):self.invoke()
        self.assertTrue((self.folder/'withdrawal-completed.json').exists())
        self.assertTrue((self.folder/'withdrawal-unknown.json').exists())
        with self.assertRaisesRegex(ValueError,'Contradictory unknown'):self.validate_completed()


class ProducerPrefixTests(unittest.TestCase):
    setUp=flow_fixture.FlowTests.setUp

    def prefix_with_later_block(self):
        self.config['model_fixture_only']=False
        self.config['card_activation_protocol']=stage.BACKUP_COPY_ATOMIC_REPLACE
        config_ref=flow_fixture.write(self.root/'production-shape-model.json',self.config)
        header=json.loads((self.folder/'flow.json').read_bytes())
        header['config_reference']=config_ref;header['injected_execution']=False
        (self.folder/'flow.json').write_text(json.dumps(header))
        journal=flow.InstallJournal.open(header['journal_session'])
        self.enterContext(patch.object(flow,'DEFAULT_SESSIONS',journal.session_dir.parent))
        self.enterContext(patch.object(flow,'source_paths',return_value=('camera_install_flow.py',)))
        result_dir=self.folder/'steps/probe';result_dir.mkdir()
        self.probe_artifact=flow_fixture.write(result_dir/'probe-model.json',{'model_only':True})
        result_ref=flow_fixture.write(result_dir/'flow-step-result.json',{'artifact_reference':self.probe_artifact})
        events=[]
        flow._append(self.folder,events,'probe','INTENT',journal_event_sha256=journal.events[-1]['event_sha256'])
        flow._append(self.folder,events,'probe','COMPLETED',receipt_reference=result_ref,source_is_hardware=True)
        cancel_dir=self.folder/'steps/cancel';cancel_dir.mkdir()
        self.block_ref=flow_fixture.write(cancel_dir/'block.json',{'model_only':True})
        cancel_ref=flow_fixture.write(cancel_dir/'flow-step-result.json',{'blocked_read_only':True,'artifact_reference':self.block_ref})
        flow._append(self.folder,events,'cancel','INTENT',journal_event_sha256=journal.events[-1]['event_sha256'])
        flow._append(self.folder,events,'cancel','BLOCKED_READ_ONLY',receipt_reference=cancel_ref,
            journal_unchanged=True,cancellation_recorded=False,automatic_retry=False)
        return journal

    def test_producer_prefix_does_not_replay_unrelated_later_block_but_operational_open_does(self):
        journal=self.prefix_with_later_block()
        with patch.object(flow,'_validate_blocked_cancel',side_effect=AssertionError('later native block replay')) as blocked:
            value=probe._flow_producer(self.probe_artifact,'probe',self.folder,{'body_sha256':self.body,
                'volume_uuid':'model','filesystem':'exfat','volume_bytes':1,'device':'model','parent':'model',
                'mount':'/model','registry_id':1})
            self.assertEqual(value['binding'],journal.binding);blocked.assert_not_called()
            with self.assertRaisesRegex(AssertionError,'later native block replay'):flow._open(self.folder)
            self.assertEqual(blocked.call_count,1)

    def test_producer_prefix_still_rejects_corrupted_earlier_event(self):
        self.prefix_with_later_block()
        path=self.folder/'events/00000001.json';value=json.loads(path.read_bytes());value['extra']='tampered';path.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError,'event chain'):flow._open(self.folder,_producer_step='probe')

    def test_producer_prefix_still_rejects_source_snapshot_change(self):
        self.prefix_with_later_block()
        (Path(self.config['source_snapshot_directory'])/'camera_install_flow.py').write_bytes(b'tampered')
        with self.assertRaisesRegex(ValueError,'source or snapshot'):flow._open(self.folder,_producer_step='probe')

    def test_producer_prefix_still_checks_hash_bound_journal_ancestor(self):
        journal=self.prefix_with_later_block()
        path=journal.session_dir/'00000001.json';value=json.loads(path.read_bytes());value['details']['tampered']=True;path.write_text(json.dumps(value))
        with self.assertRaises(ValueError):flow._open(self.folder,_producer_step='probe')


if __name__=='__main__':unittest.main()
