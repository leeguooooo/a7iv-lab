"""Host/record tests use CPU-model receipts and a synthetic channel, never USB."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock,patch

import camera_menu_window as menu
from camera_stream_execution import LAUNCH


def native_case(name):
    value=json.loads((Path('output/menu-stock-window-offline-01')/'native-model-report.json').read_text())
    return next(x for x in value['cases'] if x['case']==name)


def ready_row():
    r={k:0 for k in menu.FIELDS}
    r.update(version=1,phase=1,euid=0,pid=234,ppid=1,loader_pid=123,cleanup=0,flags=13,
             snapshot_before_status=-11,snapshot_end_status=-11)
    for phase in ('before','end'):
        for n in menu.OBSERVATIONS:r[f'{phase}_{n}']=-1
    return r


def encode(row,nonce):
    return menu.FRAME.pack(b'M4DWL002',nonce,*(row[n] for n in menu.FIELDS))


class RecordTests(unittest.TestCase):
    nonce=bytes(range(16))

    def test_original_native_success_receipt_decodes_and_proves_RAM_only(self):
        row=native_case('success')['native_terminal'];r=menu.decode(encode(row,self.nonce),self.nonce)
        proof=menu.terminal_proof(r,ready_row())
        self.assertTrue(proof['both_RAM_targets_proven_safe'])
        self.assertFalse(proof['firmware_installation_proven'])

    def test_valid_scheduling_delay_does_not_make_restoration_unknown(self):
        row=copy.deepcopy(native_case('success')['native_terminal']);row['hold_seconds']=615
        r=menu.decode(encode(row,self.nonce),self.nonce)
        self.assertTrue(menu.terminal_proof(r,ready_row())['both_RAM_targets_proven_safe'])

    def test_actual_restore_failure_and_target_identity_change_stay_unknown(self):
        for name in ('lib_restore_error','app_pid_reused_after_patch','app_restore_error'):
            with self.subTest(case=name):
                row=native_case(name)['native_terminal'];r=menu.decode(encode(row,self.nonce),self.nonce)
                self.assertFalse(menu.terminal_proof(r,ready_row())['both_RAM_targets_proven_safe'])

    def test_partial_wrong_nonce_or_contradictory_success_never_proves_restored(self):
        raw=encode(native_case('success')['native_terminal'],self.nonce)
        for value,nonce in ((raw[:216],self.nonce),(raw,bytes(16))):
            with self.assertRaises(ValueError):menu.decode(value,nonce)
        row=ready_row();row['phase']=6
        with self.assertRaises(ValueError):menu.terminal_proof(row,ready_row())

    def test_worker_termination_has_no_terminal_receipt_to_infer_from_time(self):
        c=native_case('terminate_after_both_patches')
        self.assertFalse(c['terminal_record_complete'])
        self.assertIsNone(c['native_terminal'])


class ChannelTests(unittest.TestCase):
    def test_START_reserved_before_unknown_and_never_replayed(self):
        with tempfile.TemporaryDirectory() as tmp:
            channel=menu.MenuChannel(Mock(),bytes(range(16)))
            channel._packet=Mock(side_effect=OSError('synthetic unknown select'))
            with self.assertRaises(OSError):channel.start_once(tmp)
            self.assertTrue((Path(tmp)/'start-intent.json').exists())
            with self.assertRaises(RuntimeError):channel.start_once(tmp)
            self.assertEqual(channel._packet.call_count,1)

    def test_only_fixed_record_names_are_readable(self):
        c=menu.MenuChannel(Mock(),bytes(16));c._packet=Mock()
        with self.assertRaises(ValueError):c.read('../../anything')
        c._packet.assert_not_called()


class SyntheticMenu:
    def __init__(self,nonce):
        self.nonce=nonce;self.uploads=0;self.starts=0;self.healthy=True;self.fault=None
        self.ready=ready_row()
        self.patched=copy.deepcopy(native_case('success')['native_terminal'])
        self.patched.update(phase=5,flags=765,restored=0,app_restored=0,hold_seconds=0)
    def read_loader(self,path):return None if path==menu.SLOT else b'synthetic-loader'
    def upload_once(self,module,digest,attempt):
        self.uploads+=1
        if self.fault=='upload_unknown':raise OSError('synthetic upload unknown')
    def start_once(self,evidence):
        self.starts+=1
        if self.fault=='START_unknown':raise OSError('synthetic START unknown')
    def read(self,name,missing=False):
        if name=='launch':return LAUNCH.pack(b'M4BOOT01',self.nonce,1,3,0,0,123,0,234,234,0,100000000)
        if name=='ready':return encode(self.ready,self.nonce)
        if name=='patched':
            if self.fault=='patched_partial':return encode(self.patched,self.nonce)[:216]
            return encode(self.patched,self.nonce)
        if name=='result' and self.fault=='early_terminal' and self.starts:
            return encode(native_case('success')['native_terminal'],self.nonce)
        return None


class StartTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.manifest,cls.module=menu.checked_job()
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.evidence=self.root/'evidence';self.evidence.mkdir()
        self.channel=SyntheticMenu(bytes.fromhex(self.manifest['nonce']));self.captures=[]
        self.patchers=[patch.object(menu,'JOB',self.root/'job'),
            patch.object(menu,'asset_reference',return_value=(menu.MenuAssets(self.root/'job',menu.MANIFEST_SHA,menu.MODULE_SHA),self.root/'job')),
            patch.object(menu,'checked_job',return_value=(self.manifest,self.module)),
            patch.object(menu,'MenuChannel',return_value=self.channel),
            patch.dict(menu.LIBRARIES,{'/lib/synthetic':hashlib.sha256(b'synthetic-loader').hexdigest()},clear=True)]
        (self.root/'job').mkdir()
        for p in self.patchers:p.start();self.addCleanup(p.stop)
    def capture(self,device,name,folder,**kwargs):
        self.captures.append(name)
        values={'pre_app':(98212632,'1e1b9202eaa69198f20df03dbfdab2f103b206cc4ebcd2e7bd817e6a710018a2'),
                'pre_ufp':(22768,'f2e7d27602e3f7b236fc41dd93fccf53ba24f0793fd454e7fec171ae378beca7')}
        n,digest=values[name]
        return {'profile':name,'bytes':n,'sha256':digest,'nonce':'f'*32,'source_is_hardware':False,
                'native':{'phase':6,'flags':63,'error':0,'cleanup':0,'offset':n,
                          'first_sha256':digest,'second_sha256':digest}}
    def start(self,**kwargs):
        return menu.start_authenticated(object(),self.evidence,ram_authorized=True,body_verified=True,
            capture_one=self.capture,sleep=lambda _:None,**kwargs)
    def test_success_is_patch_observation_not_installation_handoff(self):
        result=self.start()
        self.assertEqual((self.channel.uploads,self.channel.starts),(1,1))
        self.assertEqual(self.captures,['pre_app','pre_ufp'])
        self.assertFalse(result['service_exit_completed'])
        self.assertFalse(result['normal_body_reappearance_verified'])
        self.assertFalse(result['installation_authorized'])
    def test_no_RAM_permission_does_not_claim_or_touch_channel(self):
        with self.assertRaises(ValueError):menu.start_authenticated(object(),self.evidence)
        self.assertEqual((self.channel.uploads,self.channel.starts),(0,0))
        self.assertFalse((self.root/'job/physical-attempt.json').exists())
    def test_wrong_first_capture_stops_before_next_capture_or_upload(self):
        real=self.capture
        def bad(*args,**kwargs):
            result=real(*args,**kwargs);result['sha256']='0'*64;return result
        with self.assertRaises(ValueError):
            menu.start_authenticated(object(),self.evidence,ram_authorized=True,body_verified=True,capture_one=bad)
        self.assertEqual(self.captures,['pre_app'])
        self.assertEqual((self.channel.uploads,self.channel.starts),(0,0))
    def test_unknown_upload_or_START_never_reports_handoff(self):
        for fault in ('upload_unknown','START_unknown','patched_partial'):
            with self.subTest(fault=fault):
                self.channel.fault=fault
                with self.assertRaises((OSError,ValueError)):self.start()
                self.assertFalse((self.evidence/'handoff.json').exists())
                self.assertFalse(self.channel.healthy)
                # Only synthetic host evidence is cleared between isolated cases.
                for p in self.evidence.iterdir():p.unlink()
                (self.root/'job/physical-attempt.json').unlink()
                self.channel.healthy=True
    def test_raw_terminal_kept_when_window_ended_before_handoff(self):
        self.channel.fault='early_terminal'
        with self.assertRaises(ValueError):self.start()
        self.assertTrue((self.evidence/'terminal-before-handoff.json').exists())
    def test_same_compiled_nonce_cannot_replay_in_different_evidence_folder(self):
        self.start();count=self.channel.uploads
        second=self.root/'second';second.mkdir()
        with self.assertRaises(FileExistsError):
            menu.start_authenticated(object(),second,ram_authorized=True,body_verified=True,capture_one=self.capture)
        self.assertEqual(self.channel.uploads,count)

    def test_collection_reads_receipts_without_upload_or_START(self):
        report=self.start();self.channel.fault='early_terminal'
        before=self.channel.uploads,self.channel.starts
        proof=menu.collect_authenticated(object(),self.root/'collection',report,
            body_verified=True,firmware_never_started_confirmed=True,sleep=lambda _:None)
        self.assertTrue(proof['both_RAM_targets_proven_safe'])
        self.assertFalse(proof['firmware_installation_proven'])
        self.assertEqual((self.channel.uploads,self.channel.starts),before)

    def test_collection_requires_no_firmware_start_confirmation(self):
        report=self.start()
        with self.assertRaises(ValueError):
            menu.collect_authenticated(object(),self.root/'collection',report,body_verified=True)
        self.assertFalse((self.root/'collection').exists())

    def test_collection_missing_original_publication_stops_after_first_read(self):
        report=self.start();self.channel.read=Mock(return_value=None)
        with self.assertRaises(ValueError):
            menu.collect_authenticated(object(),self.root/'collection',report,body_verified=True,
                                      firmware_never_started_confirmed=True)
        self.channel.read.assert_called_once_with('ready',missing=True)

    def test_collection_partial_result_is_retained_but_never_accepted(self):
        report=self.start();original=self.channel.read
        def read(name,missing=False):
            if name=='result':return encode(native_case('success')['native_terminal'],self.channel.nonce)[:216]
            return original(name,missing)
        self.channel.read=Mock(side_effect=read)
        with self.assertRaises(ValueError):
            menu.collect_authenticated(object(),self.root/'collection',report,body_verified=True,
                                      firmware_never_started_confirmed=True)
        receipt=json.loads((self.root/'collection/result-received.json').read_text())
        self.assertEqual(receipt['bytes'],216)
        self.assertEqual([c.args[0] for c in self.channel.read.call_args_list],['ready','patched','result'])


if __name__=='__main__':unittest.main()
