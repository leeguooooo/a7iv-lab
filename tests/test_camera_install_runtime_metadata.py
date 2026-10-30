from dataclasses import replace
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import Mock,patch

import camera_install_runtime_metadata as meta
from camera_device_lease import CameraDeviceLease
from camera_install_journal import InstallJournal
from camera_stream_execution import LAUNCH,durable_new
from tools.emulate_install_runtime_metadata_offline import CASES,BOOTSTRAP_CASES


def digest(raw):return hashlib.sha256(raw).hexdigest()


class Channel:
    def __init__(self,nonce):
        self.nonce=nonce;self.calls=[];self.starts=0;self.uploads=0;self.healthy=True;self.fault=None
        self.proc=b'major minor #blocks name\n'+b''.join(f'252 {128+n} 16384 cnflasha{n}\n252 {n} 16384 pnflasha{n}\n'.encode() for n in meta.NUMBERS)
        aliases=[]
        for n in meta.NUMBERS:
            target=f'cnflasha{n}'.encode();st=bytearray(128);struct.pack_into('<I',st,16,0o60000);struct.pack_into('<Q',st,32,252*256+128+n)
            aliases.append(meta.ALIAS.pack(n,len(target),0o60000,252*256+128+n,target,st))
        self.boot_id='abcdefab-2222-4333-8444-555555555555'
        self.aliases=b''.join(aliases)+self.boot_id.encode()+bytes(4)
    def frame(self,phase):
        return meta.FRAME.pack(meta.MAGIC,self.nonce,meta.VERSION,phase,0,0,777,1,888,0,13 if phase==1 else 61,
            0 if phase==1 else len(self.proc),0 if phase==1 else len(self.aliases),bytes(32) if phase==1 else hashlib.sha256(self.proc).digest(),bytes(32) if phase==1 else hashlib.sha256(self.aliases).digest())
    def read_loader(self,path):self.calls.append(path);return None if path==meta.SLOT else b'library'
    def upload_once(self,module,sha,path):
        self.uploads+=1;durable_new(path,dict(model=True))
        if self.fault=='upload':raise OSError('upload uncertain')
    def start_once(self,folder):
        self.starts+=1
        if self.fault=='START':raise OSError('START uncertain')
    def read(self,name,missing=False):
        self.calls.append(name)
        if name=='exec_failure':return None
        if self.fault=='early_during_'+name and name in ('launch','ready'):return None
        if name=='launch':return LAUNCH.pack(b'M4BOOT01',self.nonce,1,3,0,0,888,0,999,999,0,100000000)
        if name=='result' and not self.starts and self.fault not in ('early_result','early_during_launch','early_during_ready'):return None
        if name=='result' and self.fault=='timeout':return None
        if name=='partitions.bin':return self.proc
        if name=='aliases.bin':return self.aliases
        raw=self.frame(1 if name=='ready' else 7)
        if self.fault=='wrong_ready' and name=='ready':return b'BADMAGIC'+raw[8:]
        if self.fault=='partial_result' and name=='result':return raw[:90]
        return raw


class MetadataTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=meta.ROOT/'output');self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.job=self.root/'job';self.job.mkdir();self.folder=self.root/'evidence';self.folder.mkdir();self.nonce=b'm'*16
        self.manifest=dict(nonce=self.nonce.hex(),sources={},artifacts={});(self.job/'manifest.json').write_text(json.dumps(self.manifest));(self.job/'libJit.so').write_bytes(b'module');(self.job/'worker.debug.elf').write_bytes(b'debug-worker')
        verification={'all_passed':True};vh=digest(meta._json(verification).encode());mh=digest((self.job/'manifest.json').read_bytes())
        for name,cases in (('native-model-report.json',CASES),('bootstrap-model-report.json',BOOTSTRAP_CASES)):
            (self.job/name).write_text(json.dumps(dict(all_passed=True,manifest_sha256=mh,verification_sha256=vh,debug_worker_sha256=digest(b'debug-worker'),emulator_sha256=digest((meta.ROOT/'tools/emulate_install_runtime_metadata_offline.py').read_bytes()),contract_sha256=digest((meta.ROOT/'camera_install_runtime_metadata.py').read_bytes()),profile_sha256=digest((meta.ROOT/'tools/install_runtime_metadata_profile.py').read_bytes()),source_bindings={},artifact_bindings={},cases=list(cases),declared_cases=list(cases),coverage_complete_for_declared_matrix=True,results=[dict(case=c,passed=True) for c in cases],hardware_operations=0,real_ARM_process=False)))
        self.assets=meta.MetadataAssets(self.job,mh,digest(b'module'),digest((self.job/'native-model-report.json').read_bytes()),digest((self.job/'bootstrap-model-report.json').read_bytes()))
        self.body='b'*64;self.plan='a'*64;self.journal=InstallJournal.create(self.root/'sessions','model',plan_sha256=self.plan,body_sha256=self.body,model='ILCE-7M4')
        self.lease=CameraDeviceLease('metadata-model',lock_path=self.root/'lock');self.lease.__enter__();self.addCleanup(self.lease.__exit__,None,None,None)
        self.channel=Channel(self.nonce);self.factory=Mock(return_value=self.channel);self.time=0
        for p in (patch('tools.verify_install_runtime_metadata_offline.verify',return_value=verification),patch.object(meta,'CLAIMS',self.root/'claims'),patch.object(meta,'DEFAULT_SESSIONS',self.root/'global-sessions'),patch.dict(meta.LIBRARIES,{'/lib/fixture':digest(b'library')},clear=True)):
            p.start();self.addCleanup(p.stop)
        self.reservation=None
    def reserve(self):
        prepared=meta.preflight_assets(self.assets);self.reservation=meta.reserve_assets(prepared,self.folder,lease=self.lease,journal=self.journal,body_sha256=self.body,plan_sha256=self.plan)
    def sleep(self,n):self.time+=n
    def invoke(self,**changes):
        if self.reservation is None:self.reserve()
        args=dict(assets=self.assets,reservation=self.reservation,lease=self.lease,journal=self.journal,body_sha256=self.body,plan_sha256=self.plan,metadata_read_authorized=True,source_is_hardware=True,channel_factory=self.factory,clock=lambda:self.time,sleep=self.sleep);args.update(changes)
        return meta.capture_authenticated(None,self.folder,**args)
    def test_success_raw_is_durable_and_injected_never_hardware(self):
        receipt=self.invoke();self.assertFalse(receipt['source_is_hardware']);parsed=meta.validate_receipt(receipt,reference=receipt['asset_reference'],reservation=self.reservation)
        self.assertEqual(parsed['alias_targets']['nflasha15'],'/dev/cnflasha15');self.assertEqual((self.channel.uploads,self.channel.starts),(1,1));self.assertTrue((self.folder/'metadata-receipt.json').exists());self.assertEqual(self.journal.state,'PLANNED')
        for name in ('installation_authorized','write_admission','restoration_proven'):self.assertIs(receipt[name],False)
    def test_v2_boot_uuid_is_hash_bound_and_legacy_requires_explicit_forensic_mode(self):
        receipt=self.invoke()
        parsed=meta.validate_receipt(receipt,reference=receipt['asset_reference'],reservation=self.reservation)
        self.assertEqual(parsed['boot_id'],self.channel.boot_id)
        self.assertEqual(parsed['metadata_version'],2)
        for suffix in (b'0'*40, self.channel.boot_id.upper().encode()+bytes(4), self.channel.boot_id.encode()+b'x'*4):
            changed=dict(receipt,aliases_raw_hex=(bytes.fromhex(receipt['aliases_raw_hex'])[:1728]+suffix).hex())
            with self.assertRaises(ValueError):meta.validate_receipt(changed,reference=changed['asset_reference'],reservation=self.reservation)
    def test_legacy_v1_is_explicit_forensic_only(self):
        receipt=self.invoke();legacy=dict(receipt)
        legacy['raw_publications']=dict(receipt['raw_publications'])
        payload=self.channel.aliases[:1728];legacy['aliases_raw_hex']=payload.hex()
        for name,phase in (('ready',1),('result',7)):
            values=list(meta.FRAME.unpack(bytes.fromhex(legacy['raw_publications'][name])))
            values[0]=meta.LEGACY_MAGIC;values[2]=1
            if phase==7:values[-3]=1728;values[-1]=hashlib.sha256(payload).digest()
            legacy['raw_publications'][name]=meta.FRAME.pack(*values).hex()
        with self.assertRaises(ValueError):meta.validate_receipt(legacy,reference=legacy['asset_reference'],reservation=self.reservation)
        observed=meta.validate_receipt(legacy,reference=legacy['asset_reference'],reservation=self.reservation,forensic_legacy=True)
        self.assertEqual(observed['metadata_version'],1);self.assertIsNone(observed['boot_id'])
        legacy['source_is_hardware']=True
        with self.assertRaises(ValueError):meta.validate_receipt(legacy,reference=legacy['asset_reference'],reservation=self.reservation,forensic_legacy=True)
    def test_bad_authorization_before_any_IO(self):
        with self.assertRaises(ValueError):self.invoke(metadata_read_authorized=False)
        self.factory.assert_not_called();self.assertFalse(self.channel.calls)
    def test_default_false_source_and_custom_context_rejected_before_IO(self):
        with self.assertRaises(ValueError):self.invoke(channel_factory=None,source_is_hardware=False)
        self.assertFalse(self.channel.calls)
    def test_noncallable_falsey_injection_cannot_fallthrough(self):
        with self.assertRaises(ValueError):self.invoke(channel_factory=False)
        self.assertFalse(self.channel.calls)
    def test_changed_module_preflight_zero_IO(self):
        self.reserve();(self.job/'libJit.so').write_bytes(b'swapped')
        with self.assertRaises(ValueError):self.invoke()
        self.assertFalse(self.channel.calls)
    def test_module_replaced_between_initial_hash_and_acquisition_zero_IO(self):
        self.reserve()
        def swap(_directory):
            (self.job/'libJit.so').write_bytes(b'swapped-after-hash')
            return {'all_passed':True}
        with patch('tools.verify_install_runtime_metadata_offline.verify',side_effect=swap):
            with self.assertRaises(ValueError):self.invoke()
        self.assertFalse(self.channel.calls)
    def test_forged_owned_claim_paths_rejected_zero_IO(self):
        self.reserve();self.reservation['job_claim']=self.reservation['global_claim'].copy()
        with self.assertRaises(ValueError):self.invoke()
        self.assertFalse(self.channel.calls)
    def test_claim_replay_before_IO(self):
        self.reserve()
        with self.assertRaises(ValueError):meta.preflight_assets(self.assets)
        self.assertFalse(self.channel.calls)
    def test_ready_and_early_result_never_START(self):
        self.channel.fault='wrong_ready'
        with self.assertRaises(ValueError):self.invoke()
        self.assertEqual(self.channel.starts,0);self.assertTrue((self.folder/'ready-received.json').exists())
    def test_early_terminal_never_START(self):
        self.channel.fault='early_result'
        with self.assertRaises(ValueError):self.invoke()
        self.assertEqual(self.channel.starts,0);self.assertTrue((self.folder/'result-received.json').exists())
    def test_explicit_model_bindings_tampered_with_reviewed_hash_still_reject(self):
        for name,field in (('native-model-report.json','debug_worker_sha256'),('native-model-report.json','emulator_sha256'),('bootstrap-model-report.json','contract_sha256'),('bootstrap-model-report.json','profile_sha256')):
            with self.subTest(field=field):
                path=self.job/name;original=path.read_bytes();report=json.loads(original);report[field]='0'*64;path.write_text(json.dumps(report))
                attr='native_model_sha256' if name.startswith('native') else 'bootstrap_model_sha256'
                changed=replace(self.assets,**{attr:digest(path.read_bytes())})
                with self.assertRaises(ValueError):meta.preflight_assets(changed)
                path.write_bytes(original)
        self.factory.assert_not_called();self.assertFalse(self.channel.calls)
    def _early_missing(self,name):
        self.channel.fault='early_during_'+name
        with self.assertRaisesRegex(ValueError,'Early native terminal'):self.invoke()
        self.assertEqual(self.channel.starts,0);self.assertEqual(self.time,0)
        saved=self.folder/('early-result-before-'+name+'-received.json')
        self.assertEqual(json.loads(saved.read_bytes())['bytes'],176)
    def test_missing_launch_with_early_terminal_is_immediate_and_durable(self):self._early_missing('launch')
    def test_missing_ready_with_early_terminal_is_immediate_and_durable(self):self._early_missing('ready')
    def test_upload_unknown_no_retry(self):
        self.channel.fault='upload'
        with self.assertRaises(OSError):self.invoke()
        self.assertEqual((self.channel.uploads,self.channel.starts),(1,0));self.assertFalse(self.channel.healthy)
    def test_START_unknown_no_retry(self):
        self.channel.fault='START'
        with self.assertRaises(OSError):self.invoke()
        self.assertEqual((self.channel.uploads,self.channel.starts),(1,1))
    def test_partial_result_durable_before_decode(self):
        self.channel.fault='partial_result'
        with self.assertRaises(ValueError):self.invoke()
        self.assertEqual(json.loads((self.folder/'result-received.json').read_text())['bytes'],90);self.assertTrue((self.folder/'metadata-unknown.json').exists())
    def test_timeout_no_reupload_or_restart(self):
        self.channel.fault='timeout'
        with self.assertRaises(ValueError):self.invoke()
        self.assertEqual((self.channel.uploads,self.channel.starts),(1,1))
    def test_lease_replaced_after_loader_no_more_requests(self):
        original=self.channel.read_loader
        def replace(path):
            raw=original(path);self.lease.__exit__(None,None,None);self.lease.__enter__();return raw
        self.channel.read_loader=replace
        with self.assertRaises(ValueError):self.invoke()
        self.assertEqual((len(self.channel.calls),self.channel.uploads,self.channel.starts),(1,0,0))
    def test_tampered_rdev_cannot_pass_native_payload_binding(self):
        receipt=self.invoke();raw=bytearray.fromhex(receipt['aliases_raw_hex']);raw[24]^=1;receipt['aliases_raw_hex']=raw.hex()
        with self.assertRaises(ValueError):meta.validate_receipt(receipt,reference=receipt['asset_reference'],reservation=self.reservation)


class PendingEpochMetadataTests(unittest.TestCase):
    def setUp(self):
        import test_camera_install_cancel as prior_fixture
        self.base=MetadataTests();self.base.setUp();self.addCleanup(self.base.doCleanups)
        self.prior=prior_fixture.CancellationAssessmentTests();self.prior.setUp();self.addCleanup(self.prior.doCleanups)
        f=self.prior
        self.initial=self.base.root/'before-runtime.json';self.initial.write_text('{}')
        self.withdrawal=self.base.root/'withdrawal.json';self.withdrawal.write_text('{}')
        self.initial_ref=dict(path=str(self.initial),sha256=digest(self.initial.read_bytes()))
        self.withdrawal_ref=dict(path=str(self.withdrawal),sha256=digest(self.withdrawal.read_bytes()))
        self.summary=dict(initial_boot_id='11111111-2222-4333-8444-555555555555',prior_nonces=['1'*32],sources_declared_hardware=False)
        self.enterContext(patch.object(meta,'_pending_epoch_sources',return_value=self.summary))
        self.reservation=None

    def options(self):
        f=self.prior
        return dict(lease=f.session.lease,journal=f.session.journal,body_sha256=f.body,plan_sha256=f.session.plan,
            pending_reference=f.pending_reference,initial_runtime_reference=self.initial_ref,
            withdrawal_reference=self.withdrawal_ref,operator_never_started_confirmed=True)

    def reserve(self):
        self.reservation=meta.reserve_pending_epoch_assets(meta.preflight_assets(self.base.assets),self.base.folder,**self.options())

    def invoke(self,**changes):
        if self.reservation is None:self.reserve()
        values=dict(assets=self.base.assets,reservation=self.reservation,metadata_read_authorized=True,
            source_is_hardware=True,channel_factory=self.base.factory,clock=lambda:self.base.time,sleep=self.base.sleep,
            **self.options());values.update(changes)
        return meta.capture_pending_epoch_authenticated(None,self.base.folder,**values)

    def test_dedicated_pending_epoch_scope_is_bound_and_injected_false(self):
        receipt=self.invoke()
        self.assertEqual(self.reservation['record']['context']['scope'],meta.EPOCH_SCOPE)
        self.assertEqual(self.reservation['record']['context']['pending_reference'],self.prior.pending_reference)
        self.assertFalse(receipt['source_is_hardware'])
        self.assertEqual(meta.validate_receipt(receipt,reference=receipt['asset_reference'],reservation=self.reservation)['metadata_version'],2)
        self.assertEqual(self.prior.session.journal.state,'INSTALL_PATCH_AWAITING_OPERATOR_RECONNECT')

    def test_original_generic_capture_cannot_use_pending_reservation(self):
        self.reserve()
        options=self.options()
        for key in ('pending_reference','initial_runtime_reference','withdrawal_reference','operator_never_started_confirmed'):options.pop(key)
        with self.assertRaises(ValueError):meta.capture_authenticated(None,self.base.folder,assets=self.base.assets,
            reservation=self.reservation,metadata_read_authorized=True,channel_factory=self.base.factory,**options)
        self.base.factory.assert_not_called()

    def test_mutated_original_runtime_reference_precedes_transport(self):
        self.reserve();self.initial.write_text('{"changed":true}')
        with self.assertRaises(ValueError):self.invoke()
        self.base.factory.assert_not_called()

    def test_default_transport_cannot_promote_synthetic_sources(self):
        self.reserve()
        with self.assertRaises(ValueError):self.invoke(channel_factory=None)
        self.base.factory.assert_not_called()

    def test_prior_job_nonce_cannot_be_reused_even_without_claimfile(self):
        self.summary['prior_nonces']=[self.base.nonce.hex()]
        with self.assertRaises(ValueError):self.reserve()
        self.base.factory.assert_not_called()

    def test_lease_replacement_after_loader_stops_before_upload(self):
        original=self.base.channel.read_loader
        def swap(path):
            raw=original(path);self.prior.session.lease.__exit__(None,None,None);self.prior.session.lease.__enter__();return raw
        self.base.channel.read_loader=swap
        with self.assertRaises(ValueError):self.invoke()
        self.assertEqual((self.base.channel.uploads,self.base.channel.starts),(0,0))


if __name__=='__main__':unittest.main()


class EpochSourceLineageTests(unittest.TestCase):
    def setUp(self):
        import test_camera_install_cancel as fixtures
        self.f=fixtures.CancellationAssessmentTests();self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.history=self.f.session.journal.events
        self.may=next(i for i,e in enumerate(self.history) if e['state']=='INSTALL_PATCH_MAY_BE_ACTIVE')
        pending=json.loads(Path(self.f.pending_reference['path']).read_text())
        self.prior=dict(receipt=pending,ancestor_index=len(self.history)-1,source_is_hardware=False)
        self.before=dict(metadata_version=2,boot_id='11111111-2222-4333-8444-555555555555',ancestor_index=self.may-1,
            source_is_hardware=False,receipt={'asset_reference':{'metadata':{'nonce':'7'*32}}})
        self.enterContext(patch('camera_install_receipts.validate_completed_pending',return_value=self.prior))
        self.enterContext(patch('camera_install_receipts.validate_completed_runtime',return_value=self.before))
        self.enterContext(patch('camera_install_card_withdraw.validate_withdrawal_receipt',return_value={'source_is_hardware':False}))
        self.enterContext(patch.object(meta,'withdrawal_stage_reference',return_value=self.f.reference))

    def invoke(self):
        return meta._pending_epoch_sources(self.f.pending_reference,{}, {},binding=self.f.session.journal.binding,
            history=self.history,session_dir=self.f.session.journal.session_dir)

    def test_before_epoch_must_precede_patch_intent_and_remain_v2(self):
        self.assertFalse(self.invoke()['sources_declared_hardware'])
        self.before['ancestor_index']=self.may
        with self.assertRaises(ValueError):self.invoke()
        self.before['ancestor_index']=self.may-1;self.before['metadata_version']=1
        with self.assertRaises(ValueError):self.invoke()

    def test_all_prior_job_nonces_are_reserved_from_epoch_reuse(self):
        summary=self.invoke()
        self.assertEqual(len(summary['prior_nonces']),4)
        self.assertIn('7'*32,summary['prior_nonces'])
