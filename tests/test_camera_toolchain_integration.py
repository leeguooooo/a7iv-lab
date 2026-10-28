"""Cross-component dry run: temporary card, fake SDK, actual serialized model ABI."""
import hashlib
import contextlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from camera_device_lease import CameraDeviceLease
from camera_install_journal import InstallJournal,assert_no_pending_installs,JournalError
import camera_sd_stage as sd
import camera_menu_window as menu
from camera_menu_session import run_menu_session
from test_camera_menu_window import SyntheticMenu


class IntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.meta,cls.module=menu.checked_job()

    def test_card_to_window_handoff_is_still_not_flash_authorization(self):
        self.run_flow(False)

    def test_unknown_STOP_keeps_pending_after_host_lease_released(self):
        self.run_flow(True)

    def run_flow(self,stop_unknown):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();card=root/'simulated-card';card.mkdir()
            source=root/'candidate';payload=b'model-only candidate';source.write_bytes(payload)
            (card/'BODYDATA.DAT').write_bytes(b'original preserve')
            report=root/'stage-report';job=root/'menu-job';job.mkdir()
            menu_folder=root/'menu-evidence';menu_folder.mkdir()
            body='b'*64;plan='a'*64
            volume=dict(device='disk900s1',parent='disk900',mount=str(card),volume_uuid='model-card',
                        volume_bytes=8<<30,registry_id=900,body_matched=True,body_sha256=body,filesystem='exfat')
            channel=SyntheticMenu(bytes.fromhex(self.meta['nonce']))
            attempts={'session':0,'normal':0,'exit':0}
            def exclusive(a,b):
                # Host TEMP filesystem only, models same-volume no-replace rename.
                import os
                os.link(a,b);os.unlink(a)
            def capture(device,name,folder,**kwargs):
                profile={'pre_app':(98212632,'1e1b9202eaa69198f20df03dbfdab2f103b206cc4ebcd2e7bd817e6a710018a2'),
                         'pre_ufp':(22768,'f2e7d27602e3f7b236fc41dd93fccf53ba24f0793fd454e7fec171ae378beca7')}
                size,digest=profile[name]
                return {'profile':name,'bytes':size,'sha256':digest,'nonce':'f'*32,'source_is_hardware':kwargs['source_is_hardware'],
                        'native':dict(phase=6,flags=63,error=0,cleanup=0,offset=size,first_sha256=digest,second_sha256=digest)}
            def start(device,folder,**kwargs):
                return menu.start_authenticated(device,folder,capture_one=capture,**kwargs)
            def session(expected,work,*,record_event,set_stage):
                attempts['session']+=1
                record_event({'model':'ILCE-7M4','body_matched':True})
                result=work(object())
                if stop_unknown:raise OSError('synthetic unknown STOP')
                attempts['exit']+=1
                record_event({'event':'STOP_RESPONSE','mode':'service','known_pipe_response':True})
                return result
            with patch.object(sd,'SOURCE',source),patch.object(sd,'DIGEST',hashlib.sha256(payload).hexdigest()), \
                 patch.object(sd,'SIZE',len(payload)),patch.object(sd,'REPORT',report), \
                 patch.object(sd,'discover',return_value=volume), \
                 patch.object(menu,'JOB',job),patch.object(menu,'checked_job',return_value=(self.meta,self.module)), \
                 patch.object(menu,'asset_reference',return_value=(menu.MenuAssets(job,menu.MANIFEST_SHA,menu.MODULE_SHA),job)), \
                 patch.object(menu,'MenuChannel',return_value=channel), \
                 patch.dict(menu.LIBRARIES,{'/lib/model':hashlib.sha256(b'synthetic-loader').hexdigest()},clear=True):
                with CameraDeviceLease('integration-model',lock_path=root/'owner.lock') as lease:
                    j=InstallJournal.create(root/'sessions','model',plan_sha256=plan,body_sha256=body,model='ILCE-7M4')
                    j.advance('SD_STAGE_INTENT')
                    with contextlib.redirect_stdout(io.StringIO()):sd.stage(lease=lease,journal=j)
                    sd.activate_staged(activation_authorized=True,slot1_confirmed=True,lease=lease,journal=j,rename_fn=exclusive)
                    self.assertEqual((card/'BODYDATA.DAT').read_bytes(),payload)
                    backups=list(card.glob('.camera-use-staging/*/original-BODYDATA.DAT'))
                    self.assertEqual(len(backups),1);self.assertEqual(backups[0].read_bytes(),b'original preserve')
                    j.advance('SD_STAGED')
                    call=lambda:run_menu_session(body,menu_folder,plan_sha256=plan,journal=j,lease=lease,
                        ram_authorized=True,run_session=session,start_fn=start,
                        clock=lambda:100.0,sleep=lambda _:None)
                    if stop_unknown:
                        with self.assertRaises(OSError):call()
                        self.assertEqual(j.state,'STOPPED_UNKNOWN')
                        self.assertEqual(attempts['normal'],0)
                    else:
                        result=call()
                        self.assertEqual(j.state,'RAM_AWAITING_OPERATOR_RECONNECT')
                        self.assertEqual(result['state'],'RAM_AWAITING_OPERATOR_RECONNECT')
                        self.assertFalse(result['installation_authorized'])
                        self.assertFalse(result['firmware_installation_proven'])
                        self.assertFalse(result['source_is_hardware'])
                        self.assertFalse(result['patch_observation']['source_is_hardware'])
                        self.assertEqual(attempts,dict(session=1,normal=0,exit=1))
                    self.assertEqual((channel.uploads,channel.starts),(1,1))
                # Even a released host lease does not clear pending on-camera work.
                with self.assertRaises(JournalError):assert_no_pending_installs(root/'sessions')


if __name__=='__main__':unittest.main()
