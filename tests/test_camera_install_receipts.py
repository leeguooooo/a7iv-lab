import hashlib
import json
from pathlib import Path
import tempfile
import struct
import unittest
from unittest.mock import patch

import camera_install_receipts as receipts
from test_camera_postinstall_verify import fat_image
import test_camera_install_patch_read_session as read_fixture
import test_camera_install_runtime_session as runtime_fixture
import test_camera_install_card as card_fixture


def reference(path):
    return dict(path=str(Path(path).absolute()),sha256=receipts.sha(Path(path).read_bytes()))


class HistoricalHelpersTests(unittest.TestCase):
    def setUp(self):
        self.tmp=self.enterContext(tempfile.TemporaryDirectory());self.root=Path(self.tmp).resolve()
    def test_snapshot_validation_does_not_read_current_checkout_or_unused_claims(self):
        sources=self.root/'sources';(sources/'Sony-PMCA-RE/pmca').mkdir(parents=True)
        raw=b'historical source';path=sources/'Sony-PMCA-RE/pmca/__init__.py';path.write_bytes(raw)
        review=self.root/'review.json';review.write_text(json.dumps(dict(source_snapshot_directory=str(sources),sources={'Sony-PMCA-RE/pmca/__init__.py':receipts.sha(raw)})))
        result=receipts.historical_review(reference(review))
        self.assertEqual(len(result['sources']),1)
        path.write_bytes(b'changed')
        with self.assertRaises(ValueError):receipts.historical_review(reference(review))
    def test_existing_frozen_native_models_validate_historically_without_current_source_or_claim_checks(self):
        output=Path(__file__).resolve().parents[1]/'output'
        names=('install-volatile-production-offline-20261029-05','install-patch-read-offline-20261029-05','install-runtime-metadata-offline-20261030-07')
        for name in names:
            job=output/name
            if not (job/'manifest.json').is_file():self.skipTest('Local frozen offline model assets unavailable')
            h=lambda n:hashlib.sha256((job/n).read_bytes()).hexdigest()
            ref=dict(directory=str(job),nonce=json.loads((job/'manifest.json').read_bytes())['nonce'],manifest_sha256=h('manifest.json'),
                module_sha256=h('libJit.so'),native_model_sha256=h('native-model-report.json'),bootstrap_model_sha256=h('bootstrap-model-report.json'))
            manifest=receipts.historical_native(ref)
            self.assertEqual(manifest['hardware_operations'],0)
            self.assertFalse(manifest['hardware_acceptance'])
    def test_duplicate_JSON_and_symlink_evidence_refused(self):
        p=self.root/'value.json';p.write_bytes(b'{"x":1,"x":2}')
        with self.assertRaises(ValueError):receipts.load_reference(reference(p))
        alias=self.root/'alias';alias.symlink_to(p)
        with self.assertRaises(ValueError):receipts.load_reference(dict(path=str(alias),sha256=receipts.sha(p.read_bytes())))
    def test_model_source_declaration_cannot_be_promoted(self):
        self.assertFalse(receipts.source_declaration(dict(source_is_hardware=False,model_fixture_only=True)))
        for key,value in (('model_fixture_only',True),('source_kind','INJECTED'),('nested',{'synthetic':True})):
            with self.subTest(key=key),self.assertRaises(ValueError):
                receipts.source_declaration(dict(source_is_hardware=True,**{key:value}))


class CompletedCurrentReadTests(unittest.TestCase):
    def setUp(self):
        fixture=read_fixture.ReadSessionTests();fixture.setUp();self.addCleanup(fixture.doCleanups);self.fixture=fixture
        self.result=fixture.invoke();self.f=fixture.f
        self.ref=reference(self.f.evidence/'current-read-session-exit.json')
        self.context=dict(pending_reference=self.f.pending_ref,binding=self.f.journal.binding,
                          history=self.f.journal.events,session_dir=self.f.journal.session_dir)
        # Native ELF/model closure is tested separately; fixture transport remains DI.
        self.enterContext(patch.object(receipts,'historical_native',return_value={'sources':{}}))
    def validate(self):return receipts.validate_completed_current_read(self.ref,**self.context)
    def test_completed_raw_read_remains_nonhardware_after_jobs_are_consumed(self):
        observed=self.validate()
        self.assertFalse(observed['source_is_hardware'])
        self.assertFalse(observed['original_mm_continuity_proven'])
        self.assertEqual(observed['proof']['observation'],'ORIGINAL')
        self.assertTrue((self.f.job/'physical-attempt.json').exists())
    def test_extra_history_uses_original_pending_ancestor(self):
        history=self.context['history'];event=dict(schema=history[0]['schema'],session_id=history[0]['session_id'],seq=len(history)+1,
            prev_sha256=history[-1]['event_sha256'],binding=history[0]['binding'],state='INSTALL_READY_FOR_OPERATOR_START',details={})
        event['event_sha256']=receipts.sha(receipts.canonical(event)+b'\n');self.context['history']=history+[event]
        self.assertEqual(self.validate()['ancestor_index'],len(history)-1)
    def test_corrupt_raw_frame_rejected_even_with_outer_file_hash_updated(self):
        path=Path(self.ref['path']);value=json.loads(path.read_bytes());value['native_receipt']['raw_publications']['result']='00';path.write_text(json.dumps(value));self.ref=reference(path)
        with self.assertRaises(ValueError):self.validate()
    def test_wrong_session_or_pending_rejected(self):
        self.context['session_dir']=Path(self.context['session_dir']).parent/'other'
        with self.assertRaises(ValueError):self.validate()
    def test_current_hardware_flag_cannot_promote_model_original(self):
        path=Path(self.ref['path']);value=json.loads(path.read_bytes());value['source_is_hardware']=True;path.write_text(json.dumps(value));self.ref=reference(path)
        with self.assertRaises(ValueError):self.validate()


class CompletedRuntimeTests(unittest.TestCase):
    def setUp(self):
        fixture=runtime_fixture.RuntimeSessionTests();fixture.setUp();self.addCleanup(fixture.doCleanups);self.fixture=fixture
        fixture.invoke();self.ref=reference(fixture.group/'runtime-session-exit.json')
        self.context=dict(binding=fixture.journal.binding,history=fixture.journal.events,session_dir=fixture.journal.session_dir)
        review=json.loads(Path(fixture.review['review_path']).read_bytes());self.review=review
        self.enterContext(patch.object(receipts,'historical_review',return_value=review))
        self.enterContext(patch.object(receipts,'historical_native',return_value={'sources':{}}))
    def test_actual_small_FAT_BK4_and_native_raw_are_reparsed_without_hardware_promotion(self):
        result=receipts.validate_completed_runtime(self.ref,**self.context)
        self.assertFalse(result['source_is_hardware']);self.assertEqual(result['decoded']['values']['region'],0)
        self.assertFalse(result['receiver_compatible']);self.assertIsNone(result['receiver_proof'])
    def test_historical_review_nonce_cannot_be_replaced_by_another_runtime_group(self):
        self.review['group_nonce']='f'*32
        with self.assertRaisesRegex(ValueError,'review binding/nonces'):
            receipts.validate_completed_runtime(self.ref,**self.context)
    def test_metadata_artifact_cannot_point_outside_owned_runtime_group(self):
        path=Path(self.ref['path']);value=json.loads(path.read_bytes())
        terminal_path=Path(value['terminal_artifact']['path']);terminal=json.loads(terminal_path.read_bytes())
        other=self.fixture.root/'copied-metadata.json';other.write_bytes(Path(value['metadata_artifact']['path']).read_bytes())
        for record in (value,terminal):record['metadata_artifact']['path']=str(other)
        terminal_path.write_text(json.dumps(terminal));value['terminal_artifact']['sha256']=receipts.sha(terminal_path.read_bytes());value['terminal_artifact']['payload_sha256']=receipts.sha(receipts.canonical(terminal))
        path.write_text(json.dumps(value));self.ref=reference(path)
        with self.assertRaisesRegex(ValueError,'belong to this runtime group'):
            receipts.validate_completed_runtime(self.ref,**self.context)
    def test_raw_PDT_mutation_refused(self):
        (self.fixture.group/'before.bk4').write_bytes(b'bad')
        with self.assertRaises(ValueError):receipts.validate_completed_runtime(self.ref,**self.context)
    def test_missing_known_STOP_refused(self):
        path=Path(self.ref['path']);value=json.loads(path.read_bytes());value['service_events']=[];path.write_text(json.dumps(value));self.ref=reference(path)
        with self.assertRaises(ValueError):receipts.validate_completed_runtime(self.ref,**self.context)


class CurrentReceiverTests(unittest.TestCase):
    def setUp(self):
        self.initrd=b'receiver-initrd';self.kernel=b'factory-kernel'
        self.header=bytearray(512);struct.pack_into('<I',self.header,36,0x01030081)
        self.raw=fat_image(self.initrd,self.kernel,bytes(self.header[36:40]),bytes(4))
        fs=receipts.postinstall._fat(self.raw);boots={name:fs.read(name) for name in receipts.postinstall.BOOT_FILES}
        self.enterContext(patch.object(receipts.postinstall,'_reference_inputs',return_value=(bytes(self.header),b'template',self.kernel,boots)))
        self.enterContext(patch.object(receipts.postinstall,'INITRD_SHA',receipts.sha(self.initrd)))
    def test_current_semantic_check_uses_six_files_and_checksum_without_a_historical_digest(self):
        proof=receipts.verify_current_receiver(self.raw)
        self.assertEqual(proof['current_p1_sha256'],receipts.sha(self.raw));self.assertEqual(proof['initrd_sha256'],receipts.sha(self.initrd))
        self.assertEqual(len(proof['boot_files']),3);self.assertFalse(proof['nwu_branch_execution_proven'])
    def test_stock_or_wrong_initrd_with_correct_DAT_cannot_be_a_receiver(self):
        raw=fat_image(b'stock-initrd',self.kernel,bytes(self.header[36:40]),bytes(4))
        self.assertEqual(receipts.postinstall._fat(raw).read('DAT2'),bytes(self.header[36:40]))
        with self.assertRaisesRegex(ValueError,'initrd/kernel'):receipts.verify_current_receiver(raw)
    def test_corrupt_current_checksum_cannot_be_accepted_from_old_installed_report(self):
        raw=self.raw.replace(b'  ./boot/initrd.img',b'  ./boot/initrd.bad')
        with self.assertRaisesRegex(ValueError,'P1CHKSUM'):receipts.verify_current_receiver(raw)


class CompletedCardTests(unittest.TestCase):
    def setUp(self):
        fixture=card_fixture.ActiveCardTests();fixture.setUp();self.addCleanup(fixture.doCleanups);self.fixture=fixture
        self.receipt=fixture.observe();self.history=fixture.journal.events
        for state in ('INSTALL_PATCH_MAY_BE_ACTIVE','INSTALL_PATCH_AWAITING_OPERATOR_RECONNECT'):
            event=dict(schema=1,session_id=self.history[0]['session_id'],seq=len(self.history)+1,
                prev_sha256=self.history[-1]['event_sha256'],binding=self.history[0]['binding'],state=state,details={})
            event['event_sha256']=receipts.sha(receipts.canonical(event)+b'\n');self.history.append(event)
        self.receipt['journal_event_sha256']=self.history[-1]['event_sha256']
        self.enterContext(patch.object(receipts,'SIZE',len(fixture.base.payload)))
        self.enterContext(patch.object(receipts,'DIGEST',hashlib.sha256(fixture.base.payload).hexdigest()))
        self.context=dict(binding=fixture.journal.binding,history=self.history,session_dir=fixture.journal.session_dir)
    def save(self):
        self.receipt['evidence_sha256']=receipts.sha(receipts.canonical({k:v for k,v in self.receipt.items() if k!='evidence_sha256'}))
        path=self.fixture.root/'completed-card.json';path.write_text(json.dumps(self.receipt));return reference(path)
    def test_full_file_observer_receipt_revalidates_without_live_card_access_or_promotion(self):
        ref=self.save();self.fixture.base.root_update.unlink();self.fixture.backup.unlink()
        observed=receipts.validate_completed_card(ref,**self.context)
        self.assertFalse(observed['source_is_hardware']);self.assertFalse(observed['original_mm_continuity_proven'])
    def test_active_card_booleans_cannot_replace_descriptor_full_read_evidence(self):
        self.receipt['candidate'].pop('descriptor_identity')
        with self.assertRaises(ValueError):receipts.validate_completed_card(self.save(),**self.context)


if __name__=='__main__':unittest.main()
