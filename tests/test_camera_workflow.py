import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import camera_workflow as workflow
from camera_install_journal import InstallJournal
from camera_toolchain import PACKAGE_SHA,PLAIN_SHA


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve()
        self.enterContext(patch.object(workflow,'ROOT',self.root))
        self.plan_path=self.root/'output/offline-toolchain/plan.json';self.plan_path.parent.mkdir(parents=True)
        names=('camera_workflow.py','camera_workflow_spec.py','camera_workflow_simulator.py',
               'camera_menu_session.py','camera_sd_stage.py','camera_install_journal.py')
        sources={}
        for name in names:
            p=self.root/name;p.write_bytes(b'synthetic source\n');sources[name]=workflow.digest(p)
        ref=self.root/'output/backup-01/execution/run.json';ref.parent.mkdir(parents=True)
        ref.write_text(json.dumps({'body':{'usb_serial_sha256':'b'*64}}))
        self.plan=dict(schema='camera-offline-toolchain-plan/1',local_checks_passed=True,
            prepared_offline_only=True,model='ILCE-7M4',reference_body_sha256='b'*64,
            package_sha256=PACKAGE_SHA,plaintext_sha256=PLAIN_SHA,sources=sources,
            reference_body_record_sha256=workflow.digest(ref))
        self.plan_path.write_text(json.dumps(self.plan));self.sha=workflow.digest(self.plan_path)
        self.folder=self.root/'output/camera-workflows/one'

    def init(self):
        return workflow.initialize(self.folder,self.plan_path,self.sha,root=self.root)

    def call(self,action,**extra):
        options=dict(authorize_step=True,camera_ready=True,firmware_never_started=True,root=self.root)
        options.update(extra)
        return workflow.device_action(self.folder,action,**options)

    def receipt(self):
        return dict(plan_sha256=self.sha,body_sha256='b'*64,model='ILCE-7M4',source_is_hardware=True)

    def settings(self):
        with patch('camera_capture_session.capture_settings_before',side_effect=lambda *a,**k:self.settings_receipt()) as function:
            result=self.call('settings')
            function.assert_called_once()
        return result

    def settings_receipt(self):
        from test_camera_capture_session import RAW
        folder=self.folder/'settings';folder.mkdir()
        (folder/'before.bk4').write_bytes(RAW)
        before=dict(self.receipt(),path='before.bk4',sha256=workflow.digest(folder/'before.bk4'),
            group_nonce='c'*32,nonce='d'*32,acquisition_phase='PRE_INSTALL')
        workflow.save_new(folder/'before-reference.json',before)
        return dict(self.receipt(),group=str(folder),group_nonce='c'*32,before=before,normal_body_verified=True)

    def stage_receipt(self):
        folder=self.folder/'card-stage';folder.mkdir()
        result=dict(state='STAGED_UNRECOGNIZED_FILE_VERIFIED_NOT_ACTIVATED',source_sha256=PACKAGE_SHA,
            bytes=757480856,volume_identity={'body_sha256':'b'*64},BODYDATA_DAT_created_or_replaced=False,
            updater_invoked=False,existing_root_update_unchanged=True,camera_internal_firmware_modified=False)
        workflow.save_new(folder/'completed.json',result)
        return result

    def test_init_and_status_host_only_and_install_locked(self):
        with patch('subprocess.Popen',side_effect=AssertionError('no external process')):
            record=self.init();r=workflow.status(self.folder,root=self.root)
        self.assertFalse(record['installation_authorized']);self.assertTrue(r['formal_install_entry_locked'])
        self.assertEqual(r['state'],'PLANNED');self.assertEqual(r['hardware_operations_by_status'],0)

    def test_wrong_plan_sha_and_changed_source_rejected_before_journal(self):
        with self.assertRaisesRegex(ValueError,'plan changed'):
            workflow.initialize(self.folder,self.plan_path,'f'*64,root=self.root)
        (self.root/'camera_workflow.py').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError,'source changed'):self.init()
        self.assertFalse((self.root/'output/full-install-sessions').exists())

    def test_old_plan_missing_workflow_binding_rejected(self):
        self.plan['sources'].pop('camera_workflow.py');self.plan_path.write_text(json.dumps(self.plan))
        with self.assertRaisesRegex(ValueError,'predates'):
            workflow.checked_plan(self.plan_path,workflow.digest(self.plan_path),root=self.root)

    def test_reference_camera_evidence_change_rejected(self):
        (self.root/'output/backup-01/execution/run.json').write_text('{}')
        with self.assertRaisesRegex(ValueError,'camera evidence'):self.init()

    def test_symlink_and_outside_output_rejected(self):
        alias=self.root/'output/alias';alias.symlink_to(self.plan_path)
        with self.assertRaisesRegex(ValueError,'Symlink'):workflow.checked_plan(alias,self.sha,root=self.root)
        with self.assertRaisesRegex(ValueError,'project output'):workflow.local_path(self.root/'escape',self.root,exists=False)

    def test_each_device_flag_required_and_no_intent_on_refusal(self):
        self.init()
        for options in ({'authorize_step':False},{'camera_ready':False},{'firmware_never_started':False}):
            with self.subTest(options=options),self.assertRaises(ValueError):self.call('settings',**options)
        self.assertFalse((self.folder/'settings-intent.json').exists())
        self.assertEqual(workflow.status(self.folder,root=self.root)['state'],'PLANNED')

    def test_formal_install_and_activation_cannot_be_called(self):
        for action in ('install','activation','menu-update','flash','unknown'):
            with self.subTest(action=action),self.assertRaisesRegex(ValueError,'no formal'):
                self.call(action)
        self.assertFalse(self.folder.exists())

    def test_settings_intent_precedes_call_and_no_replay(self):
        self.init()
        def capture(*args,**kwargs):
            self.assertTrue((self.folder/'settings-intent.json').is_file())
            return self.settings_receipt()
        with patch('camera_capture_session.capture_settings_before',side_effect=capture) as function:
            self.call('settings')
            with self.assertRaises(FileExistsError):self.call('settings')
            self.assertEqual(function.call_count,1)

    def test_unknown_settings_marks_journal_and_blocks_stage(self):
        self.init()
        with patch('camera_capture_session.capture_settings_before',side_effect=OSError('unknown USB')):
            with self.assertRaises(OSError):self.call('settings')
        self.assertEqual(workflow.status(self.folder,root=self.root)['state'],'STOPPED_UNKNOWN')
        with patch('camera_sd_stage.stage',side_effect=AssertionError('must not run')):
            with self.assertRaises(ValueError):self.call('stage',slot1_confirmed=True)

    def test_stage_requires_current_hardware_settings(self):
        self.init()
        with patch('camera_sd_stage.stage',side_effect=AssertionError('must not run')):
            with self.assertRaises(ValueError):self.call('stage',slot1_confirmed=True)
        receipt=self.receipt();receipt['source_is_hardware']=False
        workflow.save_new(self.folder/'settings-result.json',receipt)
        with self.assertRaisesRegex(ValueError,'settings acquisition'):self.call('stage',slot1_confirmed=True)
        self.assertFalse((self.folder/'stage-intent.json').exists())

    def test_stage_unique_report_and_journal_transition(self):
        self.init();self.settings()
        def stage(**kwargs):
            self.assertEqual(kwargs['journal'].state,'SD_STAGE_INTENT')
            self.assertEqual(kwargs['report_path'],self.folder/'card-stage')
            return self.stage_receipt()
        with patch('camera_sd_stage.stage',side_effect=stage) as function:
            response=self.call('stage',slot1_confirmed=True)
            self.assertEqual(response['state'],'SD_STAGED');function.assert_called_once()
        self.assertFalse(response['installation_authorized'])

    def test_actual_backup_bytes_and_original_stage_report_cannot_change(self):
        self.init();self.settings()
        with patch('camera_sd_stage.stage',side_effect=lambda **k:self.stage_receipt()):
            self.call('stage',slot1_confirmed=True)
        original=self.folder/'card-stage/completed.json';data=json.loads(original.read_text())
        data['source_sha256']='f'*64;original.write_text(json.dumps(data))
        with patch.object(workflow,'check_current_staged_card',side_effect=AssertionError('no card access')):
            with self.assertRaisesRegex(ValueError,'stage report changed'):self.call('window')
        self.assertFalse((self.folder/'window-intent.json').exists())

    def test_corrupt_settings_payload_rejected_before_stage_intent(self):
        self.init();self.settings();(self.folder/'settings/before.bk4').write_bytes(b'corrupt')
        with self.assertRaisesRegex(ValueError,'backup changed'):self.call('stage',slot1_confirmed=True)
        self.assertFalse((self.folder/'stage-intent.json').exists())

    def test_foreign_root_cannot_reach_device_backend(self):
        with patch.object(workflow,'ROOT',self.root/'actual-project'):
            with self.assertRaisesRegex(ValueError,'actual sealed project root'):self.call('settings')
        self.assertFalse(self.folder.exists())

    def test_failed_init_remains_inspectable_and_can_cancel_host_only(self):
        original=workflow.save_new
        def fail(path,value):
            if Path(path).name=='workflow.json':raise OSError('simulated workflow record failure')
            return original(path,value)
        with patch.object(workflow,'save_new',side_effect=fail):
            with self.assertRaises(OSError):self.init()
        status=workflow.status(self.folder,root=self.root)
        self.assertTrue(status['initialization_incomplete']);self.assertEqual(status['state'],'PLANNED')
        r=workflow.cancel_initialization(self.folder,confirmed=True,root=self.root)
        self.assertEqual(r['hardware_operations'],0)
        workflow.initialize(self.folder.with_name('two'),self.plan_path,self.sha,root=self.root)

    def test_initialization_cannot_cancel_after_any_device_intent(self):
        self.init();self.settings()
        with self.assertRaisesRegex(ValueError,'Device attempt intent'):
            workflow.cancel_initialization(self.folder,confirmed=True,root=self.root)

    def test_nested_model_handoff_cannot_reach_real_collection(self):
        self.init()
        _,record,j=workflow.open_workflow(self.folder,root=self.root)
        for state in ('SD_STAGE_INTENT','SD_STAGED','RAM_MAY_BE_ACTIVE','READY_FOR_CONFIRMATION'):
            j.advance(state)
        handoff=dict(self.receipt(),state='VOLATILE_WINDOW_HANDOFF',
                     patch_observation=dict(source_is_hardware=False))
        (self.folder/'menu').mkdir()
        workflow.save_new(self.folder/'window-result.json',handoff)
        workflow.save_new(self.folder/'menu/session-handoff.json',handoff)
        with patch('camera_menu_session.collect_menu_restoration',side_effect=AssertionError('must not connect')):
            with self.assertRaisesRegex(ValueError,'nested hardware'):self.call('restore')
        self.assertFalse((self.folder/'restore-intent.json').exists())

    def test_slot_confirmation_is_not_inferred(self):
        self.init();self.settings()
        with self.assertRaisesRegex(ValueError,'Slot 1'):self.call('stage')
        self.assertFalse((self.folder/'stage-intent.json').exists())

    def test_other_pending_session_blocks_new_init(self):
        self.init()
        with self.assertRaises(ValueError):
            workflow.initialize(self.folder.with_name('two'),self.plan_path,self.sha,root=self.root)

    def test_duplicate_json_and_tampered_binding_rejected(self):
        self.init();p=self.folder/'workflow.json';r=json.loads(p.read_text());r['body_sha256']='c'*64;p.write_text(json.dumps(r))
        with self.assertRaisesRegex(ValueError,'binding changed'):workflow.status(self.folder,root=self.root)
        p.write_text('{"a":1,"a":2}')
        with self.assertRaisesRegex(ValueError,'Duplicate JSON'):workflow.status(self.folder,root=self.root)

    def test_interactive_simulation_can_exit_without_device_operations(self):
        import camera_workflow_simulator as simulator
        with patch('builtins.input',return_value='q'),contextlib.redirect_stdout(io.StringIO()) as output:
            r=simulator.main(['--interactive'])
        self.assertIn('已退出模拟',output.getvalue());self.assertEqual(r['hardware_operations'],0)
        self.assertEqual(r['terminal_state'],'SIMULATION_ABORTED')
        self.assertFalse(r['interactive_walkthrough_completed'])


if __name__=='__main__':unittest.main()
