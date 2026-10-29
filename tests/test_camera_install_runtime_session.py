from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import struct
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

import camera_install_runtime as runtime
import camera_install_runtime_metadata as metadata
import camera_install_runtime_session as session
import camera_install_runtime_plan as plan
from camera_device_lease import CameraDeviceLease
from camera_install_journal import InstallJournal, JournalError
from camera_stream_execution import LAUNCH, durable_new
import camera_postinstall_verify as post
from test_camera_postinstall_verify import fat_image
from test_camera_install_runtime import pdt
from test_camera_install_runtime_metadata import Channel


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class Driver:
    def __init__(self):self.calls=[]
    def read(self, count):self.calls.append(('read',count));return b''
    def write(self, data):self.calls.append(('write',data));return len(data)
    def vendorRequestOut(self,*args):self.calls.append(('STOP',args))


class RuntimeSessionTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir=session.ROOT/'output');self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name).resolve();self.group=self.root/'runtime';self.group.mkdir()
        self.body,self.original_plan='b'*64,'a'*64
        self.journal=InstallJournal.create(self.root/'sessions','pre-runtime',
            plan_sha256=self.original_plan,body_sha256=self.body,model='ILCE-7M4')
        self.lease=self.enterContext(CameraDeviceLease('runtime-model',lock_path=self.root/'lease'))
        self.history=self.journal.events
        self.p1=fat_image(b'i',b'k',struct.pack('<I',0x01030081),bytes(4));self.pdt=pdt()
        self.enterContext(patch.object(runtime,'PDT_BYTES',len(self.pdt)))
        self.enterContext(patch.object(runtime,'P1_BYTES',len(self.p1)))
        self.enterContext(patch.dict(post.PROFILES,{'post_p1':(len(self.p1),None,'/dev/cnflasha1','BLOCK')}))
        self.enterContext(patch.object(session,'PDT_BYTES',len(self.pdt)))
        self.enterContext(patch.object(session,'P1_BYTES',len(self.p1)))
        self.enterContext(patch.object(session,'GLOBAL_SESSIONS',self.root/'global-sessions'))
        self.enterContext(patch.object(session,'ATTEMPTS',self.root/'attempts'))
        self.enterContext(patch.object(session,'CAPTURE_CLAIMS',self.root/'p1-claims'))
        self.meta_nonce=b'm'*16;self.p1_nonce=b'p'*16
        self.meta=types.SimpleNamespace(reference=dict(nonce=self.meta_nonce.hex(),module_sha256='4'*64),
                                        manifest={'sources':{}})
        self.assets=object()
        ref=dict(schema=session.ASSET_SCHEMA,p1=dict(directory='/MODEL_ONLY/p1',manifest_sha256='1'*64,
            module_sha256='2'*64,nonce=self.p1_nonce.hex(),technical_profile='post_p1',
            source_path='/dev/cnflasha1',source_kind='BLOCK',minor=129,bytes=len(self.p1)),
            metadata=deepcopy(self.meta.reference))
        self.prepared=session.PreparedRuntimeAssets(self.assets,json.dumps(ref),json.dumps({'sources':{}}),self.meta)
        self.preflight=Mock(return_value=self.prepared)
        self.reserve=Mock(side_effect=self.reserve_metadata)
        self.reservation=None
        self.required={f'nflasha{n}':1024 for n in metadata.NUMBERS}
        repository=session.ROOT
        source_root=self.root/'source-fixture';source_root.mkdir()
        self.enterContext(patch.object(session,'ROOT',source_root))
        self.enterContext(patch.object(session,'preparation_sources',return_value=('fixture.py',)))
        (source_root/'fixture.py').write_bytes(b'source fixture\n')
        for name in session.review_source_paths(self.prepared):
            if name=='fixture.py':continue
            target=source_root/name;target.parent.mkdir(parents=True,exist_ok=True)
            target.write_bytes((repository/name).read_bytes())
        self.review=plan.seal(self.root/'review',assets=self.assets,body_sha256=self.body,
            plan_sha256=self.original_plan,required_partition_sizes=self.required,preflight_fn=self.preflight)
        self.driver=Driver();self.device=types.SimpleNamespace(driver=self.driver)
        self.calls=[]
        self.capture=Mock(side_effect=self.capture_p1)
        self.pdt_reader=Mock(side_effect=self.read_pdt)
        self.metadata_reader=Mock(side_effect=self.read_metadata)
        self.run=Mock(side_effect=self.run_normal)

    def reserve_metadata(self, prepared, evidence, **context):
        self.assertFalse(self.calls)
        self.assertEqual(self.journal.events,self.history)
        self.assertTrue(Path(evidence).is_dir())
        self.assertEqual(list(Path(evidence).iterdir()),[])
        self.reservation=dict(record={'asset_reference':prepared.reference,'fixture':True})
        return self.reservation

    def capture_p1(self, device, name, folder, **options):
        self.assertEqual(name,'post_p1');self.calls.append('p1');device.driver.read(1)
        folder=Path(folder);(folder/'capture').mkdir(parents=True)
        target=folder/'capture/post_p1.bin';target.write_bytes(self.p1)
        digest=sha(self.p1);count=len(self.p1);source=options['source_is_hardware']
        native=dict(version=1,phase=6,error=0,euid=0,pid=30,ppid=1,loader_pid=20,cleanup=0,flags=63,
            offset=count,chunks=1,first_sha256=digest,second_sha256=digest)
        ready=native|dict(phase=1,flags=3)
        result=dict(profile=name,name=name,capture=str(target),bytes=count,sha256=digest,
            nonce=self.p1_nonce.hex(),source_is_hardware=source,native=native,module_sha256='2'*64,
            source_path='/dev/cnflasha1',targetpath='/dev/cnflasha1',source_kind='BLOCK',expected_sha256=None)
        durable_new(folder/'firmware-capture.json',result)
        durable_new(folder/'completed.json',dict(partition=name,bytes=count,backup=str(target),native=native))
        durable_new(folder/'launch-and-ready.json',dict(loader_pid=20,ready=ready))
        durable_new(folder/'capture/status.json',dict(nonce=self.p1_nonce.hex(),sha256=digest,
            partition=name,bytes=count,state='TWO_READS_MATCHED',source_is_hardware=source,
            source_reads_equal_at_capture=True,hardware_source_read_verified=source))
        return result

    def read_pdt(self, device, **options):
        self.calls.append('pdt');device.driver.read(1);return self.pdt

    def read_metadata(self, device, folder, **options):
        self.calls.append('metadata');device.driver.read(1)
        channel=Channel(self.meta_nonce)
        result=dict(state='RUNTIME_METADATA_OBSERVED',asset_reference=self.meta.reference,
            reservation=self.reservation,raw_publications=dict(
                launch=LAUNCH.pack(b'M4BOOT01',self.meta_nonce,1,3,0,0,888,0,999,999,0,100000000).hex(),
                ready=channel.frame(1).hex(),result=channel.frame(7).hex()),
            partitions_raw_hex=channel.proc.hex(),aliases_raw_hex=channel.aliases.hex(),
            source_is_hardware=options['source_is_hardware'],installation_authorized=False,
            write_admission=False,restoration_proven=False)
        durable_new(Path(folder)/'metadata-receipt.json',result)
        return result

    def run_normal(self, body, work, **options):
        self.calls.append('auth')
        options['record_event'](dict(model='ILCE-7M4',body_matched=True))
        value=work(self.device)
        self.assertIsNot(self.device.driver,self.driver)
        self.assertTrue((self.group/'runtime-terminal.json').is_file())
        self.device.driver.vendorRequestOut(1,2,3)
        self.calls.append('STOP')
        options['record_event'](dict(event='STOP_RESPONSE',mode='service',success=True))
        return value

    def invoke(self, **changes):
        options=dict(plan_sha256=self.original_plan,review_path=self.review['review_path'],
            review_sha256=self.review['review_sha256'],journal=self.journal,lease=self.lease,
            assets=self.assets,required_partition_sizes=self.required,runtime_read_authorized=True,
            run_session=self.run,capture_fn=self.capture,pdt_reader=self.pdt_reader,
            metadata_fn=self.metadata_reader,preflight_fn=self.preflight,reserve_fn=self.reserve)
        options.update(changes)
        return session.run_runtime_session(self.body,self.group,**options)

    def test_raw_terminal_precedes_STOP_and_PREenvelope_is_not_postinstall(self):
        result=self.invoke()
        self.assertEqual(self.calls,['auth','p1','pdt','metadata','STOP'])
        self.assertEqual(result['state'],'PRE_INSTALL_RUNTIME_KNOWN_SERVICE_EXIT')
        self.assertEqual(result['acquisition_phase'],'PRE_INSTALL')
        self.assertEqual(result['p1']['technical_profile'],'post_p1')
        self.assertFalse(result['post_installation_observed'])
        self.assertFalse(result['source_is_hardware'])
        self.assertFalse(result['decoded_values']['write_admission'])
        self.assertFalse(result['decoded_values']['hardware_origin_proven'])
        self.assertEqual(self.journal.events,self.history)
        self.assertIs(self.device.driver,self.driver)
        self.assertTrue((self.group/'runtime-pre-p1/firmware-capture.json').exists())
        self.assertFalse((self.group/'post_p1').exists())
        before=json.loads((self.group/'before-reference.json').read_text())
        self.assertEqual(before['acquisition_phase'],'PRE_INSTALL')
        self.assertEqual(before['group_nonce'],json.loads((self.group/'group.json').read_text())['group_nonce'])

    def test_falsey_callable_local_hooks_are_used_without_default_fallback(self):
        class Falsey:
            def __init__(self, function):self.function=function
            def __bool__(self):return False
            def __call__(self,*args,**kwargs):return self.function(*args,**kwargs)
        review=plan.seal(self.root/'falsey-review',assets=self.assets,body_sha256=self.body,
            plan_sha256=self.original_plan,required_partition_sizes=self.required,preflight_fn=Falsey(self.preflight))
        result=self.invoke(review_path=review['review_path'],review_sha256=review['review_sha256'],
                           preflight_fn=Falsey(self.preflight),reserve_fn=Falsey(self.reserve))
        self.assertFalse(result['source_is_hardware'])
        self.assertEqual(self.calls,['auth','p1','pdt','metadata','STOP'])

    def test_default_route_requires_global_context_before_asset_or_device_calls(self):
        with self.assertRaisesRegex(ValueError,'Canonical runtime'):
            self.invoke(run_session=None,capture_fn=None,pdt_reader=None,metadata_fn=None,
                        preflight_fn=None,reserve_fn=None)
        self.run.assert_not_called();self.capture.assert_not_called();self.reserve.assert_not_called()
        self.assertEqual(self.journal.events,self.history)

    def test_missing_consent_and_mixed_DI_fail_before_auth(self):
        for changes in (dict(runtime_read_authorized=False),dict(metadata_fn=None),dict(run_session=None)):
            with self.subTest(changes=changes),self.assertRaises(ValueError):self.invoke(**changes)
        self.run.assert_not_called();self.reserve.assert_not_called()
        self.assertEqual(self.journal.events,self.history)

    def test_changed_review_and_requirements_fail_before_claims(self):
        with self.assertRaises(ValueError):self.invoke(review_sha256='0'*64)
        self.reserve.assert_not_called();self.run.assert_not_called()
        fresh=self.root/'requirements-run';fresh.mkdir();self.group=fresh
        with self.assertRaises(ValueError):self.invoke(required_partition_sizes=self.required|{'nflasha1':2048})
        self.reserve.assert_not_called();self.run.assert_not_called()

    def test_used_P1_capture_nonce_is_rejected_before_attempt_or_auth(self):
        session.CAPTURE_CLAIMS.mkdir()
        (session.CAPTURE_CLAIMS/(self.p1_nonce.hex()+'.json')).write_text('{}')
        with self.assertRaisesRegex(ValueError,'P1 capture nonce'):
            self.invoke()
        self.reserve.assert_not_called();self.run.assert_not_called()
        self.assertFalse(session.ATTEMPTS.exists())
        self.assertEqual(self.journal.events,self.history)

    def test_metadata_asset_preflight_failure_has_no_reservation_or_auth(self):
        self.preflight.side_effect=ValueError('compiled metadata job consumed')
        with self.assertRaises(ValueError):self.invoke()
        self.reserve.assert_not_called();self.run.assert_not_called()
        self.assertEqual(self.journal.events,self.history)

    def test_collected_P1_mutation_during_metadata_blocks_terminal_and_STOP(self):
        real=self.read_metadata
        def changed(*args,**options):
            value=real(*args,**options)
            path=self.group/'runtime-pre-p1/capture/post_p1.bin'
            data=bytearray(path.read_bytes());data[-1]^=1;path.write_bytes(data)
            return value
        self.metadata_reader.side_effect=changed
        with self.assertRaisesRegex(ValueError,'evidence changed'):
            self.invoke()
        self.assertNotIn('STOP',self.calls)
        self.assertFalse((self.group/'runtime-terminal.json').exists())
        self.assertEqual(self.journal.state,'STOPPED_UNKNOWN')

    def test_collected_raw_mutation_after_callback_refuses_exit_receipt(self):
        def run(body,work,**options):
            options['record_event'](dict(model='ILCE-7M4',body_matched=True))
            value=work(self.device)
            (self.group/'before.bk4').write_bytes(b'changed')
            self.device.driver.vendorRequestOut(1,2,3)
            options['record_event'](dict(event='STOP_RESPONSE',mode='service',success=True))
            return value
        self.run.side_effect=run
        with self.assertRaisesRegex(ValueError,'evidence changed'):
            self.invoke()
        self.assertFalse((self.group/'runtime-session-exit.json').exists())
        self.assertEqual(self.journal.state,'STOPPED_UNKNOWN')

    def test_default_lengths_and_partition_keyset_are_not_inferred_from_fixture(self):
        with self.assertRaises(ValueError):self.invoke(required_partition_sizes={})
        with self.assertRaises(ValueError):self.invoke(required_partition_sizes=self.required|{'nflasha2':1024})
        self.run.assert_not_called();self.reserve.assert_not_called()

    def test_FAT_and_guard_dependencies_cannot_be_omitted_or_tampered(self):
        review_path=Path(self.review['review_path']);original_raw=review_path.read_bytes()
        original=json.loads(original_raw)
        self.assertEqual(len(session.REQUIRED_RUNTIME_SOURCES),4)
        for index,name in enumerate(sorted(session.REQUIRED_RUNTIME_SOURCES)):
            with self.subTest(dependency=name,mode='omit'):
                changed=deepcopy(original);changed['sources'].pop(name)
                raw=json.dumps(changed).encode();review_path.write_bytes(raw)
                self.group=self.root/('dependency-omit-'+str(index));self.group.mkdir()
                with self.assertRaisesRegex(ValueError,'source closure'):
                    self.invoke(review_sha256=sha(raw))
                self.run.assert_not_called();self.reserve.assert_not_called()
            review_path.write_bytes(original_raw)
            source=session.ROOT/name;before=source.read_bytes();source.write_bytes(before+b'\n')
            with self.subTest(dependency=name,mode='tamper'):
                self.group=self.root/('dependency-tamper-'+str(index));self.group.mkdir()
                with self.assertRaisesRegex(ValueError,'source changed'):
                    self.invoke()
                self.run.assert_not_called();self.reserve.assert_not_called()
            source.write_bytes(before)
        self.assertFalse(session.ATTEMPTS.exists())
        self.assertEqual(self.journal.events,self.history)

    def test_stale_or_post_RAM_journal_and_other_pending_global_fail_before_IO(self):
        stale=InstallJournal.open(self.journal.session_dir)
        self.journal.advance('SD_STAGE_INTENT')
        with self.assertRaises((ValueError,JournalError)):self.invoke(journal=stale)
        self.run.assert_not_called()

    def test_forged_P1_boolean_or_incomplete_bytes_never_reaches_PDT(self):
        real=self.capture_p1
        def forged(*args,**kwargs):
            result=real(*args,**kwargs);result['native']['first_sha256']='0'*64
            return result
        self.capture.side_effect=forged
        with self.assertRaises(ValueError):self.invoke()
        self.pdt_reader.assert_not_called();self.metadata_reader.assert_not_called()
        self.assertNotIn('STOP',self.calls)
        self.assertEqual(self.journal.state,'STOPPED_UNKNOWN')

    def test_metadata_native_hash_mismatch_blocks_STOP(self):
        real=self.read_metadata
        def forged(*args,**kwargs):
            result=real(*args,**kwargs);result['aliases_raw_hex']='00';return result
        self.metadata_reader.side_effect=forged
        with self.assertRaises(ValueError):self.invoke()
        self.assertNotIn('STOP',self.calls)
        self.assertEqual(self.journal.state,'STOPPED_UNKNOWN')

    def test_lease_change_in_P1_prevents_followup_PDT_and_STOP(self):
        real=self.capture_p1
        def changed(*args,**kwargs):
            value=real(*args,**kwargs);self.lease.__exit__(None,None,None);self.lease.__enter__();return value
        self.capture.side_effect=changed
        with self.assertRaises(ValueError):self.invoke()
        self.pdt_reader.assert_not_called();self.metadata_reader.assert_not_called()
        self.assertNotIn('STOP',self.calls)
        self.assertIs(self.device.driver,self.driver)

    def test_lease_change_after_callback_blocks_STOP_through_driver_proxy(self):
        def run(body,work,**options):
            options['record_event'](dict(model='ILCE-7M4',body_matched=True))
            result=work(self.device)
            self.lease.__exit__(None,None,None);self.lease.__enter__()
            self.device.driver.vendorRequestOut(1,2,3)
            return result
        self.run.side_effect=run
        with self.assertRaises(ValueError):self.invoke()
        self.assertTrue((self.group/'runtime-terminal.json').exists())
        self.assertFalse(any(name=='STOP' for name,_ in self.driver.calls))
        self.assertEqual(self.journal.state,'STOPPED_UNKNOWN')
        self.assertIs(self.device.driver,self.driver)

    def test_terminal_persistence_failure_never_returns_to_success_STOP(self):
        original=session.durable_new
        def failed(path,value):
            if Path(path).name=='runtime-terminal.json':raise OSError('terminal fsync unknown')
            return original(path,value)
        with patch.object(session,'durable_new',side_effect=failed):
            with self.assertRaises(OSError):self.invoke()
        self.assertNotIn('STOP',self.calls)
        self.assertEqual(self.journal.state,'STOPPED_UNKNOWN')

    def test_unknown_STOP_keeps_full_raw_and_blocks_journal(self):
        def run(body,work,**options):
            options['record_event'](dict(model='ILCE-7M4',body_matched=True));work(self.device)
            raise OSError('STOP outcome unknown')
        self.run.side_effect=run
        with self.assertRaises(OSError):self.invoke()
        self.assertTrue((self.group/'runtime-terminal.json').exists())
        self.assertEqual(self.journal.state,'STOPPED_UNKNOWN')
        self.assertIs(self.device.driver,self.driver)

    def test_successful_review_or_compiled_jobs_cannot_be_replayed(self):
        self.invoke();self.group=self.root/'second';self.group.mkdir()
        with self.assertRaises(ValueError):self.invoke()
        self.assertEqual(self.run.call_count,1)

    def test_sealer_contains_both_asset_refs_sources_and_no_admission(self):
        raw=json.loads(Path(self.review['review_path']).read_text())
        self.assertEqual(raw['asset_reference'],self.prepared.reference)
        self.assertEqual(raw['required_partition_sizes'],self.required)
        self.assertEqual(raw['scope'],session.SCOPE)
        self.assertFalse(raw['installation_authorized'])
        with self.assertRaises(ValueError):
            plan.seal(self.root/'review',assets=self.assets,body_sha256=self.body,
                plan_sha256=self.original_plan,required_partition_sizes=self.required,preflight_fn=self.preflight)


if __name__=='__main__':unittest.main()
