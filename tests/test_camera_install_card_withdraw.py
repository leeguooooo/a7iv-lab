import copy
import hashlib
import json
import os
from pathlib import Path
import unittest
from unittest.mock import Mock,patch

import camera_install_card_withdraw as withdraw
import test_camera_install_cancel as fixtures


class WithdrawTests(unittest.TestCase):
    def setUp(self):
        self.f=fixtures.CancellationAssessmentTests();self.f.setUp();self.addCleanup(self.f.doCleanups)
        f=self.f
        self.backup=f.candidate.parent/'original-BODYDATA.DAT'
        f.root_update.rename(self.backup);f.candidate.rename(f.root_update)
        self.activation=dict(state='ACTIVATED_PREVIEW_ONLY',source_sha256=hashlib.sha256(f.payload).hexdigest(),
            bytes=len(f.payload),target=str(f.root_update),backup=str(self.backup),
            volume_identity=copy.deepcopy(f.volume),slot1_manually_confirmed=True,
            original_root_update=copy.deepcopy(f.stage['existing_root_update']),updater_invoked=False,
            installation_authorized=False,camera_internal_firmware_modified=False)
        self.activation_path=f.root/'activation.json';self.activation_path.write_text(json.dumps(self.activation))
        self.activation_ref=dict(path=str(self.activation_path),sha256=hashlib.sha256(self.activation_path.read_bytes()).hexdigest())
        self.folder=f.session.root/'withdraw';self.folder.mkdir()
        self.renames=[]
        self.rename=Mock(side_effect=self.exclusive)
        self.enterContext(patch.object(withdraw,'DEFAULT_SESSIONS',f.session.root/'global-sessions'))
        self.enterContext(patch.object(withdraw,'validate_completed_pending',return_value={'source_is_hardware':False}))

    def exclusive(self,source,target,*,source_dir_fd,target_dir_fd):
        self.renames.append((source,target))
        os.link(source,target,src_dir_fd=source_dir_fd,dst_dir_fd=target_dir_fd,follow_symlinks=False)
        os.unlink(source,dir_fd=source_dir_fd)

    def invoke(self,**changes):
        f=self.f
        options=dict(body_sha256=f.body,plan_sha256=f.session.plan,lease=f.session.lease,journal=f.session.journal,
            pending_reference=f.pending_reference,withdrawal_authorized=True,operator_never_started_confirmed=True,
            operator_health_confirmed=True,discover=f.discover,rename_fn=self.rename)
        options.update(changes)
        return withdraw.withdraw_active_card(f.reference,self.activation_ref,self.folder,**options)

    def test_two_reverse_exclusive_renames_preserve_candidate_and_restore_root_only(self):
        before=self.f.session.journal.events
        result=self.invoke()
        self.assertEqual(len(self.renames),2)
        self.assertEqual(self.f.candidate.read_bytes(),self.f.payload)
        self.assertEqual(self.f.root_update.read_bytes(),self.f.original)
        self.assertFalse(self.backup.exists())
        self.assertEqual(result['state'],'CARD_CANDIDATE_WITHDRAWN_ORIGINAL_ROOT_OBSERVED')
        self.assertFalse(result['source_is_hardware'])
        self.assertFalse(result['RAM_restoration_proven'])
        self.assertFalse(result['cancellation_recorded'])
        self.assertEqual(self.f.session.journal.events,before)
        self.assertTrue((self.folder/'before-first-rename.json').is_file())
        self.assertTrue((self.folder/'before-original-root-rename.json').is_file())
        proof=self.validate_completed()
        self.assertEqual(proof['receipt'],result);self.assertFalse(proof['source_is_hardware'])

    def validate_completed(self):
        f=self.f
        return withdraw.validate_withdrawal_receipt(withdraw._reference(self.folder/'withdrawal-completed.json'),
            binding=f.session.journal.binding,history=f.session.journal.events,session_dir=f.session.journal.session_dir,
            pending_reference=f.pending_reference,stage_reference=f.reference)

    def test_second_rename_failure_leaves_first_result_without_rollback(self):
        def fail(source,target,**kwargs):
            if len(self.renames)==1:raise OSError('second rename failed')
            return self.exclusive(source,target,**kwargs)
        self.rename.side_effect=fail
        with self.assertRaises(OSError):self.invoke()
        self.assertTrue(self.f.candidate.is_file());self.assertFalse(self.f.root_update.exists())
        self.assertEqual(self.backup.read_bytes(),self.f.original)
        self.assertEqual(len(self.renames),1)
        self.assertTrue((self.folder/'withdrawal-unknown.json').exists())

    def test_missing_authorization_or_mixed_injection_precedes_reads_and_renames(self):
        for options in (dict(withdrawal_authorized=False),dict(operator_never_started_confirmed=False),
                        dict(operator_health_confirmed=False),dict(discover=None),dict(rename_fn=None)):
            with self.subTest(options=options),self.assertRaises(ValueError):self.invoke(**options)
        self.f.discover.assert_not_called();self.rename.assert_not_called()

    def test_bad_original_or_candidate_never_renames(self):
        for path in (self.f.root_update,self.backup):
            original=path.read_bytes();path.write_bytes(b'x'*len(original))
            with self.subTest(path=path),self.assertRaises(ValueError):self.invoke()
            path.write_bytes(original)
        self.rename.assert_not_called()

    def test_preexisting_staged_destination_is_never_overwritten(self):
        self.f.candidate.write_bytes(b'keep')
        with self.assertRaises(ValueError):self.invoke()
        self.assertEqual(self.f.candidate.read_bytes(),b'keep');self.rename.assert_not_called()

    def test_absent_original_uses_one_rename_and_keeps_root_absent(self):
        from camera_install_journal import InstallJournal
        f=self.f
        self.backup.unlink();f.stage['existing_root_update']={'exists':False};f.write_stage()
        f.session.journal=InstallJournal.create(f.session.root/'absent-sessions','pending',
            plan_sha256=f.session.plan,body_sha256=f.body,model='ILCE-7M4')
        f.session.journal.advance('SD_STAGE_INTENT')
        f.session.journal.advance('SD_STAGED',details=dict(stage_report=f.reference['path'],stage_report_sha256=f.reference['sha256']))
        f.session.evidence=f.session.root/'absent-evidence';f.session.evidence.mkdir();f.session.invoke()
        path=f.session.evidence/'install-patch-awaiting-reconnect.json'
        f.pending_reference=dict(path=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest())
        self.activation['original_root_update']={'exists':False}
        self.activation_path.write_text(json.dumps(self.activation))
        self.activation_ref['sha256']=hashlib.sha256(self.activation_path.read_bytes()).hexdigest()
        result=self.invoke()
        self.assertEqual(len(self.renames),1);self.assertFalse(f.root_update.exists())
        self.assertEqual(f.candidate.read_bytes(),f.payload);self.assertFalse(result['original_after']['exists'])
        self.assertEqual(self.validate_completed()['receipt'],result)

    def test_destination_creation_at_atomic_boundary_is_not_overwritten(self):
        def compete(source,target,**kwargs):
            self.f.candidate.write_bytes(b'keep')
            return self.exclusive(source,target,**kwargs)
        self.rename.side_effect=compete
        with self.assertRaises(FileExistsError):self.invoke()
        self.assertEqual(self.f.candidate.read_bytes(),b'keep')
        self.assertEqual(self.f.root_update.read_bytes(),self.f.payload)
        self.assertEqual(self.backup.read_bytes(),self.f.original)

    def test_lease_replaced_after_first_rename_prevents_second(self):
        def replace(source,target,**kwargs):
            self.exclusive(source,target,**kwargs)
            self.f.session.lease.__exit__(None,None,None);self.f.session.lease.__enter__()
        self.rename.side_effect=replace
        with self.assertRaisesRegex(ValueError,'lease'):self.invoke()
        self.assertEqual(len(self.renames),1);self.assertFalse(self.f.root_update.exists())
        self.assertEqual(self.backup.read_bytes(),self.f.original)

    def test_backup_tampered_after_first_rename_prevents_second(self):
        def replace(source,target,**kwargs):
            self.exclusive(source,target,**kwargs)
            self.backup.write_bytes(b'x'*len(self.f.original))
        self.rename.side_effect=replace
        with self.assertRaises(ValueError):self.invoke()
        self.assertEqual(len(self.renames),1);self.assertFalse(self.f.root_update.exists())
        self.assertEqual(self.f.candidate.read_bytes(),self.f.payload)

    def test_intent_fsync_failure_prevents_first_rename(self):
        actual=withdraw.durable_new
        def fail(path,value):
            if Path(path).name=='before-first-rename.json':raise OSError('intent fsync unknown')
            return actual(path,value)
        with patch.object(withdraw,'durable_new',side_effect=fail),self.assertRaises(OSError):self.invoke()
        self.rename.assert_not_called()
        self.assertEqual(self.f.root_update.read_bytes(),self.f.payload)

    def test_default_custom_context_and_falsey_injection_cannot_execute(self):
        for values in (dict(discover=None,rename_fn=None),dict(discover=False,rename_fn=False)):
            with self.subTest(values=values),self.assertRaises(ValueError):self.invoke(**values)
        self.f.discover.assert_not_called();self.rename.assert_not_called()


class StagedWithdrawTests(unittest.TestCase):
    def setUp(self):
        import test_camera_install_card as fixtures
        self.f=fixtures.ActiveCardTests();self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.folder=self.f.root/'withdraw-staged';self.folder.mkdir();self.renames=[]
        self.rename=Mock(side_effect=self.exclusive)
        self.enterContext(patch.object(withdraw,'DEFAULT_SESSIONS',self.f.root/'sessions'))
        self.pending= self.enterContext(patch.object(withdraw,'validate_completed_pending',side_effect=AssertionError('No pending proof in pre-RAM API')))

    def exclusive(self,source,target,*,source_dir_fd,target_dir_fd):
        self.renames.append((source,target))
        os.link(source,target,src_dir_fd=source_dir_fd,dst_dir_fd=target_dir_fd,follow_symlinks=False)
        os.unlink(source,dir_fd=source_dir_fd)

    def invoke(self,**changes):
        f=self.f
        options=dict(body_sha256=f.base.body,plan_sha256=f.journal.binding['plan_sha256'],lease=f.lease,journal=f.journal,
            withdrawal_authorized=True,operator_never_started_confirmed=True,operator_health_confirmed=True,
            discover=f.base.discover,rename_fn=self.rename)
        options.update(changes)
        return withdraw.withdraw_staged_card(f.base.reference,f.activation_ref,self.folder,**options)

    def test_distinct_preRAM_route_withdraws_without_pending_proof_or_RAM_claim(self):
        f=self.f;history=f.journal.events
        result=self.invoke()
        self.assertEqual(result['withdrawal_scope'],'STAGED_BEFORE_RAM')
        self.assertIsNone(result['pending_reference']);self.assertFalse(result['source_is_hardware'])
        self.assertEqual(f.base.root_update.read_bytes(),f.base.original)
        self.assertEqual(f.base.candidate.read_bytes(),f.base.payload)
        self.assertEqual(f.journal.events,history);self.pending.assert_not_called()
        proof=withdraw.validate_staged_withdrawal_receipt(withdraw._reference(self.folder/'withdrawal-completed.json'),
            binding=f.journal.binding,history=history,session_dir=f.journal.session_dir,stage_reference=f.base.reference)
        self.assertEqual(proof['receipt'],result)
        f.journal.advance('CANCELLED_BEFORE_DEVICE_WRITE')
        self.assertEqual(f.journal.state,'CANCELLED_BEFORE_DEVICE_WRITE')

    def test_pending_route_cannot_be_selected_by_staged_receipt(self):
        f=self.f
        with self.assertRaises(ValueError):withdraw.withdraw_active_card(f.base.reference,f.activation_ref,self.folder,
            body_sha256=f.base.body,plan_sha256=f.journal.binding['plan_sha256'],pending_reference={},lease=f.lease,journal=f.journal,
            withdrawal_authorized=True,operator_never_started_confirmed=True,operator_health_confirmed=True,
            discover=f.base.discover,rename_fn=self.rename)
        self.rename.assert_not_called();self.pending.assert_not_called()

    def test_preRAM_route_rejects_pending_journal_before_discovery(self):
        f=self.f
        f.journal.advance('INSTALL_PATCH_MAY_BE_ACTIVE')
        with self.assertRaises(ValueError):self.invoke()
        f.base.discover.assert_not_called();self.rename.assert_not_called()

    def test_preRAM_second_rename_failure_does_not_reactivate_candidate(self):
        def fail(source,target,**kwargs):
            if self.renames:raise OSError('second rename uncertain')
            return self.exclusive(source,target,**kwargs)
        self.rename.side_effect=fail
        with self.assertRaises(OSError):self.invoke()
        self.assertEqual(len(self.renames),1);self.assertTrue(self.f.base.candidate.exists())
        self.assertFalse(self.f.base.root_update.exists());self.assertEqual(self.f.backup.read_bytes(),self.f.base.original)
        self.assertEqual(self.f.journal.state,'SD_STAGED')
