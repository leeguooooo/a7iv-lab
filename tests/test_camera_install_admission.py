from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import camera_install_admission as admission
import camera_install_receipts as receipts


def write(path, value):
    path.write_text(json.dumps(value))
    return dict(path=str(path),sha256=receipts.sha(path.read_bytes()))


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.tmp=self.enterContext(tempfile.TemporaryDirectory());self.root=Path(self.tmp).resolve()
        self.binding=dict(body_sha256='b'*64,plan_sha256='a'*64,model='ILCE-7M4')
        event=dict(schema=1,session_id='attempt',seq=1,prev_sha256='0'*64,binding=self.binding,state='PLANNED',details={})
        event['event_sha256']=receipts.sha(receipts.canonical(event)+b'\n');self.history=[event];self.session=self.root/'attempt';self.session.mkdir()
        self.refs={key:dict(path=str(self.root/(key+'.json')),sha256='1'*64) for key in admission.REF_KEYS}
    def base(self,schema):return dict(schema=schema,**self.binding,candidate_sha256=admission.DIGEST)
    def test_missing_or_placeholder_evidence_never_seals(self):
        output=self.root/'admission.json'
        with self.assertRaises((ValueError,FileNotFoundError)):
            admission.seal_admission(output,binding=self.binding,history=self.history,session_dir=self.session,references=self.refs)
        self.assertFalse(output.exists())
        with self.assertRaises(ValueError):admission._admit({},self.binding,self.history,self.session)
    def test_model_completed_receipts_never_promote_to_admission(self):
        observed=dict(source_is_hardware=False,receipt=dict(source_is_hardware=False,model_fixture_only=True),ancestor_index=0)
        with patch.object(admission,'validate_completed_runtime',return_value=observed),patch.object(admission,'validate_completed_pending',return_value=observed),patch.object(admission,'validate_completed_current_read',return_value=observed),patch.object(admission,'validate_completed_card',return_value=observed):
            with self.assertRaisesRegex(ValueError,'injected/model'):
                admission._admit(self.refs,self.binding,self.history,self.session)
    def test_receiver_incompatibility_blocks_before_candidate_or_approval(self):
        # Boundary outputs only; this rejection creates no admissible artifact.
        observed=dict(source_is_hardware=True,receipt={'source_is_hardware':True},ancestor_index=0,
            receiver_compatible=False,receiver_proof=None)
        with patch.object(admission,'validate_completed_runtime',return_value=observed),patch.object(admission,'validate_completed_pending',return_value=observed),patch.object(admission,'validate_completed_current_read',return_value=observed),patch.object(admission,'validate_completed_card',return_value=observed),patch.object(admission,'validate_candidate') as candidate:
            with self.assertRaisesRegex(ValueError,'P1 receiver semantics'):
                admission._admit(self.refs,self.binding,self.history,self.session)
            candidate.assert_not_called()
    def test_operator_requires_exact_observations_and_bound_raw_evidence(self):
        evidence=self.root/'operator.txt';evidence.write_text('MODEL TEST OBSERVATION, NOT A CAMERA')
        report=self.base('camera-install-operator-observation/1')|dict(observation_kind='EXPLICIT_OPERATOR_OBSERVATION',
            observed=dict(model='ILCE-7M4',target_version='6.02',**dict.fromkeys(admission.OBSERVED,True)),
            evidence_references=[dict(path=str(evidence),sha256=receipts.sha(evidence.read_bytes()))],statement='Unit schema example only',
            **{key+'_reference':self.refs[key] for key in ('pending','current_read','card','runtime')})
        ref=write(self.root/'operator.json',report)
        # Schema acceptance is an operator assertion, never physical proof.
        self.assertEqual(admission.validate_operator(ref,self.binding,self.refs)['observation_kind'],'EXPLICIT_OPERATOR_OBSERVATION')
        for field in admission.OBSERVED:
            changed=deepcopy(report);changed['observed'][field]=False;ref=write(self.root/'operator.json',changed)
            with self.subTest(field=field),self.assertRaises(ValueError):admission.validate_operator(ref,self.binding,self.refs)
        changed=deepcopy(report);changed['observed']['slot1']=1
        with self.assertRaises(ValueError):admission.validate_operator(write(self.root/'operator.json',changed),self.binding,self.refs)
    def test_preparation_continue_or_generic_approval_is_not_full_install_approval(self):
        report=self.base('camera-install-full-approval/1')|dict(approval_kind='INSTALL_PREPARATION_VOLATILE_PATCH_ONLY',scope='FULL_INSTALL',
            write_scope='full_sd',approved=True,evidence_references={k:v for k,v in self.refs.items() if k!='approval'},statement='继续')
        ref=write(self.root/'approval.json',report)
        with self.assertRaises(ValueError):admission.validate_approval(ref,self.binding,self.refs)
        report['approval_kind']='EXPLICIT_FULL_INSTALL_APPROVAL';report['approved']=False
        with self.assertRaises(ValueError):admission.validate_approval(write(self.root/'approval.json',report),self.binding,self.refs)
    def test_six_images_are_not_complete_write_scope(self):
        audit=write(self.root/'audit.json',dict(model_fixture_only=True,summary='unit test'))
        report=self.base('camera-install-write-scope/1')|dict(write_scope='full_sd',mutation_domains=['six_partition_images'],audit_reference=audit)
        with self.assertRaises(ValueError):admission.validate_write_scope(write(self.root/'scope.json',report),self.binding)
    def test_start_intent_revalidates_the_recorded_ready_ancestor_after_later_events(self):
        # Schema-only journal fixture: completed evidence validation is separate.
        ready=dict(schema=1,session_id=self.session.name,seq=2,prev_sha256=self.history[0]['event_sha256'],binding=self.binding,
            state=admission.READY,details={'admission_artifact':self.refs['candidate']})
        ready['event_sha256']=receipts.sha(receipts.canonical(ready)+b'\n')
        intent=dict(schema=admission.START_SCHEMA,state='MANUAL_START_MAY_FOLLOW',**self.binding,session_id=self.session.name,
            candidate_sha256=admission.DIGEST,write_scope='full_sd',ready_event_sha256=ready['event_sha256'],
            admission_reference=self.refs['candidate'],approval_reference=self.refs['approval'],manual_start_not_yet_instructed=True,automatic_device_action=False)
        ref=write(self.root/'start.json',intent)
        later=dict(schema=1,session_id=self.session.name,seq=3,prev_sha256=ready['event_sha256'],binding=self.binding,state='FLASH_MAY_HAVE_STARTED',details={})
        later['event_sha256']=receipts.sha(receipts.canonical(later)+b'\n')
        with patch.object(admission,'validate_admission_receipt',return_value={'references':{'approval':self.refs['approval']}}) as validate:
            self.assertEqual(admission.validate_start_intent(ref,self.binding,self.history+[ready,later],self.session),intent)
            self.assertEqual(validate.call_args.args[2],self.history)
    def test_no_legacy_ready_or_missing_formal_approval_can_create_start_intent(self):
        self.history[-1]['state']='READY_FOR_CONFIRMATION'
        with self.assertRaises(ValueError):admission.seal_start_intent(self.root/'start.json',admission_reference=self.refs['approval'],binding=self.binding,history=self.history,session_dir=self.session)
        self.assertFalse((self.root/'start.json').exists())


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=self.enterContext(tempfile.TemporaryDirectory());self.root=Path(self.tmp).resolve()
        self.binding=dict(body_sha256='b'*64,plan_sha256='a'*64,model='ILCE-7M4')
        # Small files exercise actual hashing/inode checks, not production geometry.
        baseline=[];backups=[]
        for n in range(14):
            path=self.root/('part'+str(n));path.write_bytes(bytes([n+1])*8);name='unit'+str(n);digest=receipts.sha(path.read_bytes())
            baseline.append(dict(partition=name,bytes=8,sha256=digest));backups.append(dict(partition=name,bytes=8,primary=dict(path=str(path),sha256=digest),independent_copy=None))
        self.baseline=write(self.root/'baseline.json',dict(partitions=baseline))
        self.enterContext(patch.object(admission,'RECOVERY_BASELINE',Path(self.baseline['path'])))
        self.enterContext(patch.object(admission,'RECOVERY_BASELINE_SHA',self.baseline['sha256']))
        self.report=dict(schema='camera-install-recovery/1',**self.binding,candidate_sha256=admission.DIGEST,write_scope='full_sd',backup_references=backups,
            physical_nor_reference=None,recovery_entry_verified=False,backup_epoch_current=False,informed_exception_reference=None)
    def validate(self):return admission.validate_recovery(write(self.root/'recovery.json',self.report),self.binding)
    def exception(self):
        gaps=sorted(['independent_medium_missing:unit'+str(n) for n in range(14)]+['physical_NOR_backup_missing','backup_epoch_current_false','recovery_entry_verified_false'])
        report=dict(schema='camera-install-recovery-exception/1',**self.binding,candidate_sha256=admission.DIGEST,approval_kind='EXPLICIT_USER_INFORMED_RECOVERY_EXCEPTION',
            write_scope='full_sd',approved=True,accepted_gaps=gaps,statement='Unit schema test only; no user approval or device operation')
        return write(self.root/'exception.json',report)
    def test_assessment_reports_gaps_without_loading_or_granting_any_exception(self):
        self.report['informed_exception_reference']={'path':'/not/a/file','sha256':'0'*64}
        ref=write(self.root/'recovery.json',self.report)
        raw,assessment=admission.assess_recovery(ref,self.binding)
        self.assertEqual(assessment['policy_status'],'POLICY_BLOCK');self.assertEqual(len(assessment['known_gaps']),17)
        self.assertEqual(len(assessment['copy_filesystem_facts']),14);self.assertFalse(assessment['physical_recovery_guaranteed'])
        self.assertEqual(raw,self.report)
    def test_null_copies_and_NOR_report_known_gaps_without_inventing_files(self):
        with self.assertRaisesRegex(ValueError,'POLICY_BLOCK'):self.validate()
        self.report['informed_exception_reference']=self.exception()
        _,proof=self.validate();self.assertEqual(len(proof['known_gaps']),17);self.assertFalse(proof['physical_recovery_guaranteed'])
    def test_different_filesystem_is_not_proof_of_independent_physical_media(self):
        item=self.report['backup_references'][0];primary=Path(item['primary']['path']);copy=self.root/'copy';copy.write_bytes(primary.read_bytes())
        item['independent_copy']=dict(path=str(copy),sha256=receipts.sha(copy.read_bytes()))
        original=admission.file_proof
        def different_filesystem(reference,**kwargs):
            result=original(reference,**kwargs)
            if reference['path']==str(copy):result['device']+=1000
            return result
        exception=self.exception();value=json.loads(Path(exception['path']).read_bytes())
        value['accepted_gaps'].remove('independent_medium_missing:unit0');value['accepted_gaps'].append('independent_medium_unverified:unit0');value['accepted_gaps'].sort()
        self.report['informed_exception_reference']=write(Path(exception['path']),value)
        with patch.object(admission,'file_proof',side_effect=different_filesystem):
            _,proof=self.validate()
        self.assertIn('independent_medium_unverified:unit0',proof['known_gaps'])
        fact=proof['copy_filesystem_facts'][0]
        self.assertFalse(fact['same_filesystem']);self.assertTrue(fact['copy_bytes_match']);self.assertFalse(fact['physical_media_independence_proven'])
    def test_byte_identical_same_filesystem_copy_retains_missing_independent_medium_gap(self):
        item=self.report['backup_references'][0];primary=Path(item['primary']['path']);copy=self.root/'copy';copy.write_bytes(primary.read_bytes())
        item['independent_copy']=dict(path=str(copy),sha256=receipts.sha(copy.read_bytes()));self.report['informed_exception_reference']=self.exception()
        _,proof=self.validate();self.assertIn('independent_medium_missing:unit0',proof['known_gaps'])
        self.assertTrue(proof['copy_filesystem_facts'][0]['same_filesystem']);self.assertFalse(proof['copy_filesystem_facts'][0]['physical_media_independence_proven'])
    def test_exception_does_not_hide_corrupt_primary(self):
        self.report['informed_exception_reference']=self.exception();Path(self.report['backup_references'][0]['primary']['path']).write_bytes(b'corrupt')
        with self.assertRaises(ValueError):self.validate()
    def test_duplicate_partition_or_same_file_copy_refused(self):
        self.report['informed_exception_reference']=self.exception();self.report['backup_references'][0]['independent_copy']=self.report['backup_references'][0]['primary'].copy()
        with self.assertRaises(ValueError):self.validate()
    def test_true_recovery_flags_are_not_accepted_without_supported_contract(self):
        for field in ('backup_epoch_current','recovery_entry_verified'):
            original=self.report[field];self.report[field]=True
            with self.subTest(field=field),self.assertRaises(ValueError):self.validate()
            self.report[field]=original
    def test_exception_binds_exact_candidate_and_gaps(self):
        ref=self.exception();value=json.loads(Path(ref['path']).read_bytes());value['accepted_gaps'].pop();self.report['informed_exception_reference']=write(Path(ref['path']),value)
        with self.assertRaises(ValueError):self.validate()


class AdmissionFilesystemReplayTests(unittest.TestCase):
    def check_receipt(self, stored, observed):
        binding=dict(body_sha256='b'*64,plan_sha256='a'*64,model='ILCE-7M4')
        report=dict(schema=admission.SCHEMA,state='FULL_INSTALL_ADMISSION_RECORDED',
            **binding,session_id='attempt',candidate_sha256=admission.DIGEST,
            write_scope='full_sd',installation_authorized=True,manual_start_required=True,
            **dict.fromkeys(admission.FALSE_CLAIMS,False),references={},proof=stored)
        with patch.object(admission,'load_reference',return_value=(b'',report)),patch.object(admission,'_admit',return_value=observed):
            return admission.validate_admission_receipt({},binding,[],Path('/attempt'))

    def proof(self, first, second):
        return dict(provenance='DECLARED_DEFAULT_COLLECTOR_NOT_CRYPTO_ATTESTED',
            recovery=dict(known_gaps=['independent_medium_missing:P1'],
                physical_recovery_guaranteed=False,copy_filesystem_facts=[dict(
                    partition='P1',primary_filesystem_device=first,copy_filesystem_device=second,
                    same_filesystem=first==second,copy_bytes_match=True,
                    physical_media_independence_proven=False)]))

    def test_remounted_device_numbers_preserve_receipt(self):
        old=self.proof(16777234,16777234);new=self.proof(16777232,16777232)
        self.assertEqual(self.check_receipt(old,new)['proof'],old)
        self.assertEqual(new,self.proof(16777232,16777232))

    def test_changed_filesystem_relationship_is_rejected(self):
        old=self.proof(10,10);new=self.proof(20,21)
        with self.assertRaisesRegex(ValueError,'Admission proof differs'):
            self.check_receipt(old,new)

    def test_cross_partition_filesystem_relationship_is_preserved(self):
        old=self.proof(10,10);new=self.proof(20,20)
        old['recovery']['copy_filesystem_facts'].append(dict(
            partition='P2',primary_filesystem_device=10,copy_filesystem_device=10))
        new['recovery']['copy_filesystem_facts'].append(dict(
            partition='P2',primary_filesystem_device=21,copy_filesystem_device=21))
        with self.assertRaisesRegex(ValueError,'Admission proof differs'):
            self.check_receipt(old,new)

    def test_changed_recovery_claim_and_other_evidence_are_rejected(self):
        old=self.proof(10,10)
        for field,value in [('known_gaps',[]),('physical_recovery_guaranteed',True)]:
            new=self.proof(20,20);new['recovery'][field]=value
            with self.subTest(field=field),self.assertRaisesRegex(ValueError,'Admission proof differs'):
                self.check_receipt(old,new)
        new=self.proof(20,20);new['provenance']='different'
        with self.assertRaisesRegex(ValueError,'Admission proof differs'):
            self.check_receipt(old,new)


if __name__=='__main__':unittest.main()
