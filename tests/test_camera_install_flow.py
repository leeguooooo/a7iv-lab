from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock,patch

import camera_install_flow as flow
from camera_stream_execution import durable_new


def write(path,value):
    path.write_text(json.dumps(value));return flow.reference(path)


class FlowTests(unittest.TestCase):
    def setUp(self):
        self.tmp=self.enterContext(tempfile.TemporaryDirectory(dir=flow.ROOT/'output'));self.root=Path(self.tmp).resolve()
        self.body='b'*64;patch_ref={'schema':'MODEL_PATCH_ASSETS','model_fixture_only':True}
        original=dict(schema='camera-install-patch-session-plan/1',scope='INSTALL_PREPARATION_VOLATILE_PATCH_ONLY',model='ILCE-7M4',body_sha256=self.body,
            package_sha256=flow.DIGEST,plaintext_sha256=flow.PLAIN_SHA,local_checks_passed=True,prepared_offline_only=True,execution_approval_received=False,
            installation_authorized=False,hardware_admission_proven=False,flash_authorized=False,asset_reference=patch_ref)
        original_ref=write(self.root/'original.json',original)
        runtime_ref={'schema':'MODEL_RUNTIME_ASSETS','model_fixture_only':True}
        review_ref=write(self.root/'runtime-review.json',dict(asset_reference=runtime_ref,body_sha256=self.body,original_plan_sha256=original_ref['sha256']))
        snapshots=self.root/'sources';snapshots.mkdir();source=(flow.ROOT/'camera_install_flow.py').read_bytes();(snapshots/'camera_install_flow.py').write_bytes(source)
        post=self.root/'post-assets';post.mkdir()
        self.config=dict(schema=flow.CONFIG_SCHEMA,model_fixture_only=True,body_sha256=self.body,candidate_sha256=flow.DIGEST,
            original_plan_reference=original_ref,patch=dict(review_reference=original_ref,asset_reference=patch_ref),
            runtime=dict(review_reference=review_ref,asset_reference=runtime_ref),post=dict(directory=str(post),asset_reference={}),
            sources={'camera_install_flow.py':flow.sha(source)},source_snapshot_directory=str(snapshots))
        self.config_ref=write(self.root/'config.json',self.config);self.folder=self.root/'flow'
        flow.init_flow(self.config_ref,self.folder,injected_execution=True)
    def step(self,name='runtime',injector=None,**changes):
        values=dict(step_authorized=True,camera_ready=True,step_injector=injector or Mock(return_value=dict(source_is_hardware=False)))
        values.update(changes);return flow.run_step(self.folder,name,**values)
    def test_init_binds_one_journal_to_patch_review_not_an_unrelated_base_plan(self):
        first=flow.status(self.folder);header=json.loads((self.folder/'flow.json').read_bytes())
        journal=flow.InstallJournal.open(header['journal_session'])
        self.assertEqual(journal.binding['plan_sha256'],self.config['patch']['review_reference']['sha256'])
        self.assertEqual(first['state'],'PLANNED');self.assertTrue(first['injected_execution'])
        self.assertEqual(len(list((self.folder/'model-sessions').iterdir())),1)
    def test_injected_runtime_is_nonhardware_and_never_calls_production_actor(self):
        callback=Mock(return_value=dict(source_is_hardware=False,installation_authorized=False))
        with patch.object(flow,'_dispatch',side_effect=AssertionError('production actor forbidden')):
            result=self.step(injector=callback)
        self.assertEqual(callback.call_count,1);self.assertIn('runtime',result['completed_steps']);self.assertFalse(result['installation_proven'])
        event=json.loads((self.folder/'events/00000002.json').read_bytes());self.assertFalse(event['source_is_hardware'])
        self.assertEqual(flow.InstallJournal.open(result['journal_session']).state,'PLANNED')
    def test_consent_and_camera_ready_are_checked_before_intent_or_lower_IO(self):
        callback=Mock()
        for changes in (dict(step_authorized=False),dict(camera_ready=False)):
            with self.subTest(changes=changes),self.assertRaises(ValueError):self.step(injector=callback,**changes)
        callback.assert_not_called();self.assertEqual(list((self.folder/'events').iterdir()),[])
    def test_missing_or_noncallable_injector_cannot_fall_through(self):
        for injector in (None,False):
            with self.subTest(injector=injector),patch.object(flow,'_dispatch') as actual:
                with self.assertRaises(ValueError):flow.run_step(self.folder,'runtime',step_authorized=True,camera_ready=True,step_injector=injector)
                actual.assert_not_called()
    def test_falsey_callable_injector_is_used_without_default_fallback(self):
        class Callback:
            def __init__(self):self.calls=0
            def __bool__(self):return False
            def __call__(self,*args):self.calls+=1;return {'source_is_hardware':False}
        callback=Callback()
        flow.run_step(self.folder,'runtime',step_authorized=True,camera_ready=True,step_injector=callback)
        self.assertEqual(callback.calls,1)
    def test_all_formal_permission_and_acceptance_steps_are_rejected_for_DI(self):
        for name in flow.FORMAL:
            callback=Mock()
            with self.subTest(step=name),self.assertRaisesRegex(ValueError,'Injected flow'):self.step(name,injector=callback)
            callback.assert_not_called()
        self.assertEqual(list((self.folder/'events').iterdir()),[])
    def test_wrong_source_or_permission_return_is_unknown_and_never_promoted(self):
        callback=Mock(return_value=dict(source_is_hardware=True))
        with self.assertRaises(ValueError):self.step(injector=callback)
        self.assertTrue(flow.status(self.folder)['blocked']);self.assertEqual(callback.call_count,1)
    def test_unknown_outcome_retains_intent_and_never_retries_or_reconnects(self):
        callback=Mock(side_effect=OSError('unknown transport'))
        with self.assertRaises(OSError):self.step(injector=callback)
        result=flow.status(self.folder);self.assertTrue(result['blocked']);self.assertEqual(result['unresolved_steps'],['runtime'])
        retry=Mock()
        with self.assertRaisesRegex(ValueError,'Unresolved'):self.step(injector=retry)
        retry.assert_not_called();self.assertEqual(callback.call_count,1)
    def test_successful_once_step_cannot_be_replayed(self):
        self.step();callback=Mock()
        with self.assertRaisesRegex(ValueError,'Single-use'):self.step(injector=callback)
        callback.assert_not_called()
    def test_snapshot_mutation_rejected_before_callback(self):
        (Path(self.config['source_snapshot_directory'])/'camera_install_flow.py').write_bytes(b'changed')
        callback=Mock()
        with self.assertRaises(ValueError):self.step(injector=callback)
        callback.assert_not_called();self.assertEqual(list((self.folder/'events').iterdir()),[])
    def test_original_ref_must_equal_patch_review_ref(self):
        changed=deepcopy(self.config);changed['original_plan_reference']=self.config['runtime']['review_reference']
        ref=write(self.root/'wrong-config.json',changed)
        with self.assertRaises(ValueError):flow.validate_config(ref,injected=True)
    def test_any_output_path_outside_canonical_workspace_output_is_rejected(self):
        with self.assertRaises(ValueError):flow.local('/tmp/not-a-flow')
        alias=self.root/'alias';alias.symlink_to(self.root/'flow')
        with self.assertRaises(ValueError):flow.status(alias)
    def test_state_mismatch_rejects_before_actor(self):
        callback=Mock()
        with self.assertRaisesRegex(ValueError,'Journal state'):self.step('patch',injector=callback)
        callback.assert_not_called()
    def test_completed_withdrawal_invalidates_old_install_path_before_any_callback(self):
        _,_,_,events,journal=flow._open(self.folder);journal.advance('SD_STAGE_INTENT');journal.advance('SD_STAGED')
        result=self.folder/'withdraw-result.json';durable_new(result,{'source_is_hardware':False})
        flow._append(self.folder,events,'withdraw','INTENT',source_is_hardware=False)
        flow._append(self.folder,events,'withdraw','COMPLETED',source_is_hardware=False,receipt_reference=flow.reference(result))
        callback=Mock()
        with self.assertRaisesRegex(ValueError,'Withdrawn candidate'):self.step('patch',injector=callback)
        callback.assert_not_called()
    def test_damaged_completed_result_cannot_be_reported_as_valid_status(self):
        self.step();(self.folder/'steps/runtime/flow-step-result.json').write_text('{}')
        with self.assertRaises(ValueError):flow.status(self.folder)
    def test_production_init_checks_source_only_before_actor_preflight_or_journal_creation(self):
        changed=deepcopy(self.config);changed['model_fixture_only']=False;ref=write(self.root/'production-config.json',changed)
        with patch.object(flow,'source_paths',return_value=('camera_install_flow.py',)),patch.object(flow,'_system',side_effect=ValueError('source-only startup missing')),patch.object(flow,'_preflight') as assets:
            with self.assertRaisesRegex(ValueError,'source-only'):flow.init_flow(ref,self.root/'real-flow')
            assets.assert_not_called();self.assertFalse((self.root/'real-flow').exists())


class LocalRejectionTests(unittest.TestCase):
    def setUp(self):
        fixture=FlowTests();fixture.setUp();self.addCleanup(fixture.doCleanups)
        self.fixture=fixture;self.root=fixture.root;self.folder=fixture.folder
        # Exercise default host-only branches on a local model journal. No
        # camera actor or real default device route is enabled by these hooks.
        config=deepcopy(fixture.config);config['model_fixture_only']=False
        config_ref=write(self.root/'host-config.json',config)
        header=json.loads((self.folder/'flow.json').read_bytes());header.update(config_reference=config_ref,injected_execution=False)
        (self.folder/'flow.json').write_text(json.dumps(header))
        self.enterContext(patch.object(flow,'DEFAULT_LOCK',self.root/'host-model-lock'))
        self.enterContext(patch.object(flow,'DEFAULT_SESSIONS',self.folder/'model-sessions'))
        self.enterContext(patch.object(flow,'source_paths',return_value=('camera_install_flow.py',)))
        self.enterContext(patch.object(flow,'_system'))
        self.enterContext(patch.dict(flow.STATES,{'admit':('PLANNED',),'start':('PLANNED',),'complete':('PLANNED',),'prepare-read':('PLANNED',)}))
    def invoke(self,step='admit',**values):
        return flow.run_step(self.folder,step,step_authorized=True,**values)
    def events(self):
        return [json.loads(p.read_bytes()) for p in sorted((self.folder/'events').iterdir())]
    def test_missing_operator_rejects_locally_then_separate_explicit_call_uses_new_directory(self):
        with self.assertRaisesRegex(ValueError,'complete admission references'):self.invoke()
        first=flow.status(self.folder);self.assertFalse(first['blocked']);self.assertEqual(first['locally_rejected_steps'],['admit'])
        rejected=self.events()[-1];self.assertEqual(rejected['phase'],'REJECTED_LOCAL')
        self.assertFalse(rejected['SDK_requests_attempted']);self.assertFalse(rejected['manual_instruction_released'])
        self.assertEqual(first['state'],'PLANNED');self.assertTrue((self.folder/'steps/admit').is_dir())
        # Only the retry mechanism is exercised here, never a fake admission.
        with patch.object(flow,'_dispatch',return_value={'source_is_hardware':False}) as local:
            second=self.invoke()
        self.assertEqual(local.call_count,1);self.assertEqual(second['state'],'PLANNED')
        self.assertTrue((self.folder/'steps/admit-attempt-0002').is_dir())
        self.assertEqual([e['attempt'] for e in self.events()],[1,1,2,2])
        with self.assertRaisesRegex(ValueError,'already completed'):self.invoke()
    def test_local_rejection_does_not_prevent_explicit_known_safe_planned_cancellation(self):
        with self.assertRaises(ValueError):self.invoke()
        operator=write(self.root/'cancel-input.json',dict(operator_never_started_confirmed=True,operator_health_confirmed=True))
        result=self.invoke('cancel',operator_reference=operator)
        self.assertEqual(result['state'],'CANCELLED_BEFORE_DEVICE_WRITE');self.assertFalse(result['blocked'])
        self.assertFalse(self.events()[-1]['source_is_hardware'])
    def test_start_journal_append_failure_remains_unknown_even_if_no_new_file_is_visible(self):
        import camera_install_admission as admission
        ref=write(self.root/'intent.json',dict(source_is_hardware=False))
        with patch.object(flow,'_artifact',return_value=ref),patch.object(admission,'seal_start_intent',return_value=ref),patch.object(flow.InstallJournal,'record_flash_may_have_started',side_effect=OSError('append fsync unknown')) as record:
            with self.assertRaises(OSError):self.invoke('start')
        self.assertEqual(record.call_count,1);self.assertEqual(self.events()[-1]['phase'],'UNKNOWN')
        self.assertTrue(flow.status(self.folder)['blocked'])
        with self.assertRaisesRegex(ValueError,'Unresolved'):self.invoke('start')
        self.assertFalse(any('manual_instruction' in e for e in self.events()))
    def test_untracked_journal_append_after_host_failure_is_never_downgraded(self):
        def changed(step,folder,config,events,journal,lease,operator,**kwargs):
            journal.advance('SD_STAGE_INTENT');raise ValueError('local failure after journal mutation')
        with patch.object(flow,'_dispatch',side_effect=changed):
            with self.assertRaises(ValueError):self.invoke('prepare-read')
        self.assertEqual(self.events()[-1]['phase'],'UNKNOWN');self.assertTrue(flow.status(self.folder)['blocked'])
    def test_partial_journal_bytes_are_preserved_and_never_classified_local(self):
        def changed(step,folder,config,events,journal,lease,operator,**kwargs):
            (journal.session_dir/'00000001.json').write_bytes(b'{');raise ValueError('partial journal')
        with patch.object(flow,'_dispatch',side_effect=changed):
            with self.assertRaises(ValueError):self.invoke('prepare-read')
        self.assertEqual(self.events()[-1]['phase'],'UNKNOWN')
        journal_dir=Path(json.loads((self.folder/'flow.json').read_bytes())['journal_session'])
        self.assertEqual((journal_dir/'00000001.json').read_bytes(),b'{')
    def test_flow_intent_publication_failure_closes_the_local_snapshot_pin(self):
        pin=Mock()
        with patch.object(flow,'JournalSnapshotPin',return_value=pin),patch.object(flow,'_append',side_effect=OSError('flow intent fsync failed')),patch.object(flow,'_dispatch') as actor:
            with self.assertRaises(OSError):self.invoke('prepare-read')
        pin.close.assert_called_once();actor.assert_not_called()
    def test_locally_failed_build_has_no_automatic_second_invocation(self):
        actor=Mock(side_effect=OSError('compiler failed before any SDK'))
        with patch.object(flow,'_dispatch',actor):
            with self.assertRaises(OSError):self.invoke('prepare-read')
        self.assertEqual(actor.call_count,1);self.assertEqual(self.events()[-1]['phase'],'REJECTED_LOCAL')
        self.assertFalse(flow.status(self.folder)['blocked'])
    def test_physical_phase_cannot_be_relabelled_as_local_rejection(self):
        events=[];flow._append(self.folder,events,'runtime','INTENT',source_is_hardware=False)
        event=dict(step='runtime',attempt=1,phase='REJECTED_LOCAL',prev_sha256=events[-1]['event_sha256'],journal_unchanged=True,SDK_requests_attempted=False,manual_instruction_released=False,automatic_retry=False)
        event['event_sha256']=flow.sha(flow.canonical(event));durable_new(self.folder/'events/00000002.json',event)
        with self.assertRaisesRegex(ValueError,'local-only'):flow.status(self.folder)
    def test_unknown_phase_and_inconsistent_attempt_number_are_rejected(self):
        events=[];flow._append(self.folder,events,'prepare-read','INTENT',source_is_hardware=False)
        event=events[0];event['phase']='UNRECOGNIZED';event['event_sha256']=flow.sha(flow.canonical({k:v for k,v in event.items() if k!='event_sha256'}))
        (self.folder/'events/00000001.json').write_text(json.dumps(event))
        with self.assertRaisesRegex(ValueError,'step/phase/attempt'):flow.status(self.folder)


class BlockedCancellationTests(unittest.TestCase):
    def setUp(self):
        base=LocalRejectionTests();base.setUp();self.addCleanup(base.doCleanups)
        self.base=base;self.root=base.root;self.folder=base.folder
        _,_,_,_,self.journal=flow._open(self.folder)
        event=self.journal._events[0];event['state']='INSTALL_PATCH_AWAITING_OPERATOR_RECONNECT'
        event['event_sha256']=flow.sha(flow.canonical({k:v for k,v in event.items() if k!='event_sha256'})+b'\n')
        (self.journal.session_dir/'00000001.json').write_bytes(flow.canonical(event)+b'\n')
        self.enterContext(patch.object(flow.InstallJournal,'open',return_value=self.journal))
        self.real_artifact=flow._artifact
        self.prior=write(self.root/'prior.json',{'source_is_hardware':False})
        self.prepared=dict(review_path=str(self.root/'epoch-review.json'),review_sha256='e'*64,
            metadata_assets=dict(job_dir=str(self.root/'epoch-job1'),manifest_sha256='1'*64,module_sha256='2'*64,native_model_sha256='3'*64,bootstrap_model_sha256='4'*64))
        self.prep_ref=write(self.root/'epoch-prepared.json',self.prepared)
        self.enterContext(patch.object(flow,'_artifact',side_effect=lambda events,name:self.prep_ref if name=='prepare-epoch' else self.prior))
        self.enterContext(patch.object(flow,'_prepare_read',return_value=dict(asset_reference={},review_reference={'path':str(self.root/'read-review.json'),'sha256':'e'*64})))
        self.enterContext(patch.object(flow,'_read_assets',return_value=object()))
        import camera_install_cancel_session as cancel
        import camera_install_receipts as receipts
        import camera_install_epoch_session as epoch
        self.cancel=cancel;self.calls=[];self.omit=False;self.drift=False
        self.enterContext(patch.object(cancel,'_history'))
        self.enterContext(patch.object(cancel,'run_cancellation_session',side_effect=self.current))
        self.enterContext(patch.object(cancel,'run_epoch_cancellation_session',side_effect=self.epoch))
        self.enterContext(patch.object(receipts,'validate_completed_current_read',side_effect=self.current_proof))
        self.enterContext(patch.object(epoch,'validate_completed_pending_epoch',side_effect=self.epoch_proof))
        self.fresh=Mock(side_effect=self.prepare_epoch)
        self.enterContext(patch.object(flow,'_prepare_epoch',self.fresh))
    def operator(self,strategy):
        return write(self.root/('operator-'+strategy+'.json'),dict(strategy=strategy,operator_health_confirmed=True,operator_never_started_confirmed=True,
            manual_AP_reboot_confirmed=True,withdrawal_preceded_manual_AP_reboot_confirmed=True))
    def report(self,lease,state):
        c=self.cancel
        return dict(schema=c.SCHEMA,**self.journal.binding,session_id=self.journal.session_dir.name,
            state=state,source_is_hardware=True,injected_execution=False,cancellation_recorded=False,no_FLASH_history=True,
            separately_authorized_cleanup_required=True,pending_event_sha256=self.journal.events[-1]['event_sha256'],
            history_sha256=flow.sha(flow.canonical(self.journal.events)),lease_identity=flow._held_lease(lease),
            pending_reference=self.prior,stage_reference=self.prior,**dict.fromkeys(c.FALSE_CLAIMS,False))
    def current(self,body,folder,**kwargs):
        self.calls.append('current');folder=Path(folder)
        proof={'observation':'PATCHED'};raw={'lease_identity':flow._held_lease(kwargs['lease'])}
        report=self.report(kwargs['lease'],'CANCELLATION_BLOCKED_CURRENT_OBSERVATION')
        report.update(scope=self.cancel.SCOPE,producer_kind=self.cancel.DEFAULT_PRODUCER,both_targets_currently_original=False,
            current_read_proof=proof,completed_read_reference=write(folder/'completed-read.json',raw),completed_read_payload_sha256=flow.sha(flow.canonical(raw)))
        if not self.omit:write(folder/'cancellation-blocked.json',report)
        if self.drift:self.journal.advance('STOPPED_UNKNOWN')
        return report
    def current_proof(self,ref,**kwargs):
        return dict(source_is_hardware=True,receipt=flow._load(ref),proof={'observation':'PATCHED'})
    def epoch(self,body,folder,**kwargs):
        self.calls.append(str(kwargs['epoch_assets'].job_dir));folder=Path(folder)
        raw={'lease_identity':flow._held_lease(kwargs['lease'])};report=self.report(kwargs['lease'],'CANCELLATION_BLOCKED_SAME_AP_BOOT_EPOCH')
        report.update(scope=self.cancel.EPOCH_CANCEL_SCOPE,producer_kind='DEFAULT_OWNED_PENDING_EPOCH_AND_INACTIVE_CARD',
            AP_boot_epoch_change_observed=False,previous_AP_process_contexts_ended=False,initial_boot_id='same',current_boot_id='same',
            initial_runtime_reference=self.prior,withdrawal_reference=self.prior,
            completed_epoch_reference=write(folder/'completed-epoch.json',raw),completed_epoch_payload_sha256=flow.sha(flow.canonical(raw)))
        write(folder/'cancellation-blocked.json',report);return report
    def epoch_proof(self,ref,**kwargs):
        return dict(source_is_hardware=True,receipt=flow._load(ref),boot_id_differs=False,initial_boot_id='same',current_boot_id='same')
    def prepare_epoch(self,folder,*args):
        data=deepcopy(self.prepared);data['metadata_assets']['job_dir']=str(folder/'new-fresh-epoch-job')
        return {'artifact_reference':write(folder/'epoch-preparation.json',data)}
    def run_cancel(self,strategy):
        return flow.run_step(self.folder,'cancel',step_authorized=True,camera_ready=True,operator_reference=self.operator(strategy))
    def test_default_leaf_known_PATCHED_then_same_epoch_is_nonterminal_and_later_AP_uses_fresh_job(self):
        # Default dispatcher leaf contracts are modeled; no SDK or hardware runs.
        first=self.run_cancel('current_original')
        self.assertFalse(first['blocked']);self.assertEqual(first['blocked_read_only_steps'],['cancel'])
        self.assertNotIn('cancel',first['completed_steps']);self.assertFalse(first['cancellation_recorded'])
        with self.assertRaises(ValueError):self.real_artifact(self.base.events(),'cancel')
        prepared=flow.run_step(self.folder,'prepare-epoch',step_authorized=True)
        self.assertIn('prepare-epoch',prepared['completed_steps'])
        second=self.run_cancel('AP_epoch');self.assertNotIn('cancel',second['completed_steps'])
        third=self.run_cancel('AP_epoch');self.assertNotIn('cancel',third['completed_steps'])
        self.assertFalse(third['cancellation_recorded']);self.assertEqual(self.journal.state,'INSTALL_PATCH_AWAITING_OPERATOR_RECONNECT')
        self.assertNotEqual(self.calls[1],self.calls[2]);self.assertEqual(self.fresh.call_count,2)
        phases=[e['phase'] for e in self.base.events() if e['step']=='cancel']
        self.assertEqual(phases,['INTENT','BLOCKED_READ_ONLY']*3)
        self.assertTrue((self.folder/'steps/cancel-attempt-0003').is_dir())
    def test_missing_saved_blocked_receipt_is_unknown_not_a_retry_permission(self):
        self.omit=True
        with self.assertRaisesRegex(ValueError,'Regular flow artifact'):self.run_cancel('current_original')
        self.assertEqual(self.base.events()[-1]['phase'],'UNKNOWN');self.assertTrue(flow.status(self.folder)['blocked'])
    def test_journal_drift_after_completed_read_is_unknown_without_clearing(self):
        self.drift=True
        with self.assertRaises(ValueError):self.run_cancel('current_original')
        self.assertEqual(self.base.events()[-1]['phase'],'UNKNOWN');self.assertEqual(self.journal.state,'STOPPED_UNKNOWN')
    def test_unexpected_nonterminal_helper_result_never_completes_cancel(self):
        with patch.object(self.cancel,'run_cancellation_session',return_value={'state':'UNEXPECTED','cancellation_recorded':False}):
            with self.assertRaises(ValueError):self.run_cancel('current_original')
        self.assertEqual(self.base.events()[-1]['phase'],'UNKNOWN')


class WiringTests(unittest.TestCase):
    def setUp(self):
        self.tmp=self.enterContext(tempfile.TemporaryDirectory(dir=flow.ROOT/'output'));self.root=Path(self.tmp).resolve()
        self.config=dict(body_sha256='b'*64,original_plan_reference=dict(path=str(self.root/'plan.json'),sha256='a'*64),runtime=dict(review_reference=dict(path=str(self.root/'review.json'),sha256='c'*64)))
        self.journal=flow.InstallJournal.create(self.root/'sessions','model-wiring',body_sha256='b'*64,plan_sha256='a'*64,model='ILCE-7M4')
    def test_staged_cancel_cannot_clear_journal_if_discovery_replaces_lease(self):
        import camera_install_cancel as cancel
        import camera_sd_stage as sd
        self.journal.advance('SD_STAGE_INTENT');self.journal.advance('SD_STAGED')
        lease=self.enterContext(flow.CameraDeviceLease('staged-cancel-model',lock_path=self.root/'lease'))
        ref=write(self.root/'stage.json',{'source_is_hardware':False});folder=self.root/'cancel';folder.mkdir()
        def discover():
            lease.__exit__(None,None,None);lease.__enter__();return {}
        def observe(*args,**kwargs):return kwargs['discover']()
        with patch.object(flow,'_artifact',return_value=ref),patch.object(cancel,'observe_inactive_card',side_effect=observe),patch.object(sd,'discover',side_effect=discover):
            with self.assertRaisesRegex(ValueError,'context changed'):
                flow._dispatch('cancel',folder,self.config,[],self.journal,lease,dict(operator_never_started_confirmed=True,operator_health_confirmed=True))
        self.assertEqual(self.journal.state,'SD_STAGED')
    def test_post_uses_the_sealed_runtime_before_group_and_content_rechecks_that_group(self):
        import camera_install_post_plan as post_plan
        import camera_install_post_session as post_session
        import camera_postinstall_verify as verifier
        before=self.root/'runtime-before';before.mkdir();(before/'before.bk4').write_bytes(b'MODEL_BEFORE')
        runtime_ref=write(before/'runtime-session-exit.json',dict(source_is_hardware=False))
        write(before/'group.json',dict(group_nonce='1'*32))
        completion=write(self.root/'completion.json',dict(source_kind='MODEL_TEST_ONLY'))
        prepdir=self.root/'prepare-post';prepdir.mkdir();postdir=self.root/'post-step';postdir.mkdir()
        mapping={'runtime':runtime_ref,'complete':completion}
        def artifact(_events,name):return mapping[name]
        def seal(output,**kwargs):
            self.assertEqual(kwargs['before_group'],before)
            return dict(review_path=str(self.root/'review.json'),review_sha256='e'*64)
        saved=dict(source_is_hardware=False,all_passed=False)
        def collect(body,group,**kwargs):
            self.assertEqual(group,before);self.assertTrue((group/'before.bk4').exists())
            self.assertIs(kwargs['journal'],self.journal);self.assertTrue(kwargs['post_capture_authorized'])
            write(group/'verification.json',saved)
            return dict(source_is_hardware=False,verification=saved)
        with patch.object(flow,'_artifact',side_effect=artifact),patch.object(flow,'_post_assets',return_value=object()),patch.object(post_plan,'seal',side_effect=seal):
            prepared=flow._dispatch('prepare-post',prepdir,self.config,[],self.journal,object(),{})
        mapping['prepare-post']=prepared['artifact_reference']
        with patch.object(flow,'_artifact',side_effect=artifact),patch.object(flow,'_post_assets',return_value=object()),patch.object(post_session,'run_post_session',side_effect=collect) as actor:
            post=flow._dispatch('post',postdir,self.config,[],self.journal,object(),{})
        self.assertEqual(actor.call_count,1);self.assertEqual(post['artifact_reference']['path'],str(before/'verification.json'))
        self.assertFalse((postdir/'verification.json').exists());mapping['post']=post['artifact_reference']
        with patch.object(flow,'_artifact',side_effect=artifact),patch.object(verifier,'verify_capture_run',return_value=saved) as verify:
            with self.assertRaisesRegex(ValueError,'Actual complete content'):
                flow._dispatch('content',self.root,self.config,[],Mock(),object(),{})
        self.assertEqual(verify.call_args.args[0],before/'capture-run.json')
        self.assertEqual(verify.call_args.kwargs['group_nonce'],'1'*32)
    def test_features_consumes_real_public_return_path_and_sha_shape(self):
        import camera_install_features as features
        ref=write(self.root/'functional-acceptance.json',dict(source_is_hardware=False))
        operator=dict(operator_report={'statement':'MODEL_ONLY'},media_references={})
        with patch.object(flow,'_artifact',return_value=ref),patch.object(features,'record_functional_acceptance',return_value=dict(ref,report={'source_is_hardware':False},journal_changed=False)) as actor:
            result=flow._dispatch('features',self.root,self.config,[],Mock(),object(),operator)
        self.assertEqual(result['artifact_reference'],ref)
        self.assertEqual(actor.call_args.kwargs['operator_report'],operator['operator_report'])
        self.assertEqual(actor.call_args.kwargs['candidate_sha256'],flow.DIGEST)
    def test_prepare_epoch_persists_canonical_verification_before_the_model_tool(self):
        import camera_install_epoch_plan as epoch_plan
        import tools.verify_install_runtime_metadata_offline as verifier
        folder=self.root/'prepare-epoch';folder.mkdir();proof=dict(all_passed=True,hardware_operations=0,ordered={'z':1,'a':2})
        expected=flow.canonical(proof);calls=[]
        ref=write(self.root/'prior.json',dict(source_is_hardware=False))
        def tool(script,*arguments):
            calls.append((script,arguments));job=folder/'job'
            if script=='build_install_runtime_metadata_offline.py':
                self.assertEqual(arguments,('--output',job));job.mkdir();(job/'manifest.json').write_text(json.dumps({'nonce':'f'*32}));(job/'libJit.so').write_bytes(b'MODEL_MODULE')
            else:
                self.assertEqual(script,'emulate_install_runtime_metadata_offline.py');self.assertEqual(arguments,('--job',job))
                self.assertEqual((job/'verification.json').read_bytes(),expected)
                (job/'native-model-report.json').write_bytes(b'{"source_is_hardware":false}')
                (job/'bootstrap-model-report.json').write_bytes(b'{"source_is_hardware":false}')
        def seal(output,**kwargs):
            self.assertEqual(output,folder/'review');self.assertIs(kwargs['journal'],self.journal)
            self.assertEqual(kwargs['pending_reference'],ref);self.assertEqual(kwargs['initial_runtime_reference'],ref)
            return dict(review_path=str(folder/'review/review.json'),review_sha256='e'*64)
        with patch.object(flow,'_tool',side_effect=tool),patch.object(flow,'_artifact',return_value=ref),patch.object(flow,'configured_nonces',return_value={'1'*32}),patch.object(verifier,'verify',return_value=proof),patch.object(epoch_plan,'seal',side_effect=seal):
            result=flow._dispatch('prepare-epoch',folder,self.config,[],self.journal,object(),{})
        self.assertEqual(flow.reference(folder/'job/verification.json')['sha256'],flow.sha(expected))
        self.assertFalse(expected.endswith(b'\n'));self.assertEqual(len(calls),2)
        self.assertEqual(result['artifact_reference'],flow.reference(folder/'epoch-preparation.json'))
    def test_fixed_generator_command_uses_source_only_flags_and_no_shell(self):
        target=self.root/'new-job'
        with patch.object(flow,'_source_only_runtime'),patch.object(flow.subprocess,'run') as execute:
            flow._tool('build_install_patch_read_offline.py','--output',target,'--pending-receipt',self.root/'pending.json','--body-sha256','b'*64,'--plan-sha256','a'*64)
        argv=execute.call_args.args[0]
        self.assertEqual(argv[:5],[flow.sys.executable,'-B','-E','-s','-X'])
        self.assertEqual(argv[5],'pycache_prefix='+str(flow.ROOT/flow.SOURCE_ONLY_RUNTIME['pycache_prefix']))
        self.assertEqual(argv[6],str(flow.ROOT/'tools/build_install_patch_read_offline.py'))
        self.assertTrue(execute.call_args.kwargs['check']);self.assertNotIn('shell',execute.call_args.kwargs)
    def test_runtime_delegates_to_existing_session_with_the_same_original_journal(self):
        import camera_install_runtime_session as runtime
        folder=self.root/'runtime';folder.mkdir();review=write(self.root/'review.json',dict(required_partition_sizes={'nflasha1':1024}))
        self.config['runtime']['review_reference']=review
        def execute(body,group,**kwargs):
            self.assertIs(kwargs['journal'],self.journal);self.assertEqual(kwargs['plan_sha256'],'a'*64)
            durable_new(group/'runtime-session-exit.json',dict(source_is_hardware=False,state='MODEL_RUNTIME_EXIT'))
        with patch.object(flow,'_runtime_assets',return_value=object()),patch.object(runtime,'run_runtime_session',side_effect=execute) as actor:
            result=flow._dispatch('runtime',folder,self.config,[],self.journal,object(),{})
        self.assertEqual(actor.call_count,1);self.assertEqual(result['artifact_reference'],flow.reference(folder/'runtime-session-exit.json'))
        self.assertEqual(self.journal.state,'PLANNED')
    def test_failed_or_nonhardware_post_verification_cannot_record_content(self):
        import camera_postinstall_verify as verify
        group=self.root/'post';group.mkdir();saved=dict(source_is_hardware=False,all_passed=False)
        ref=write(group/'verification.json',saved);write(group/'group.json',dict(group_nonce='1'*32));journal=Mock()
        with patch.object(flow,'_artifact',return_value=ref),patch.object(verify,'verify_capture_run',return_value=saved):
            with self.assertRaisesRegex(ValueError,'Actual complete content'):flow._dispatch('content',group,self.config,[],journal,object(),{})
        journal.record_content_verified.assert_not_called()
    def test_stage_journal_intent_is_written_before_card_discovery_or_copy(self):
        import camera_sd_stage as sd
        folder=self.root/'stage';artifact=write(self.root/'runtime.json',dict(source_is_hardware=False))
        def discover():self.assertEqual(self.journal.state,'SD_STAGE_INTENT');return {'body_sha256':'b'*64}
        def stage(**kwargs):
            self.assertEqual(self.journal.state,'SD_STAGE_INTENT');folder.mkdir();durable_new(folder/'completed.json',dict(state='MODEL_STAGE',source_is_hardware=False))
        with patch.object(flow,'_artifact',return_value=artifact),patch.object(sd,'discover',side_effect=discover),patch.object(sd,'stage',side_effect=stage) as actor:
            result=flow._dispatch('stage',folder,self.config,[],self.journal,object(),{})
        self.assertEqual(self.journal.state,'SD_STAGED');actor.assert_called_once();self.assertEqual(result['artifact_reference'],flow.reference(folder/'completed.json'))
    def test_start_records_MAY_before_returning_any_manual_start_instruction(self):
        import camera_install_admission as admission
        ref=write(self.root/'intent.json',dict(schema='MODEL_UNIT_INTENT',automatic_device_action=False));calls=[]
        journal=Mock();journal.binding=self.journal.binding;journal.events=[];journal.session_dir=self.journal.session_dir
        journal.record_flash_may_have_started.side_effect=lambda path:calls.append('MAY')
        with patch.object(flow,'_artifact',return_value=ref),patch.object(admission,'seal_start_intent',return_value=ref):
            result=flow._dispatch('start',self.root,self.config,[],journal,object(),{})
        self.assertEqual(calls,['MAY']);self.assertIn('Only now',result['manual_instruction'])
    def test_failed_MAY_record_cannot_return_manual_instruction(self):
        import camera_install_admission as admission
        ref=write(self.root/'intent.json',dict(schema='MODEL_UNIT_INTENT'));journal=Mock();journal.record_flash_may_have_started.side_effect=OSError('journal publication unknown')
        with patch.object(flow,'_artifact',return_value=ref),patch.object(admission,'seal_start_intent',return_value=ref):
            with self.assertRaises(OSError):flow._dispatch('start',self.root,self.config,[],journal,object(),{})
    def test_dynamic_read_preparation_never_accepts_an_arbitrary_target_or_command(self):
        with self.assertRaises(ValueError):flow._tool('arbitrary.py','--pid','1')
        self.assertNotIn('flash-sdk',flow.STEPS);self.assertNotIn('reboot',flow.STEPS)


if __name__=='__main__':unittest.main()
