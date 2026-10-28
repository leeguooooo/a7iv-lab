import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from camera_device_lease import CameraDeviceLease, DeviceBusy, inspect_lease


class LeaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)/'owner.lock'

    def test_live_exclusive_lock_is_not_just_metadata(self):
        with CameraDeviceLease('first',owner='test:first',lock_path=self.path):
            before=self.path.read_bytes()
            with self.assertRaises(DeviceBusy):
                with CameraDeviceLease('second',lock_path=self.path):pass
            self.assertEqual(self.path.read_bytes(),before)
            self.assertTrue(inspect_lease(self.path)['live_host_lock'])
        self.assertFalse(inspect_lease(self.path)['live_host_lock'])
        self.assertFalse(inspect_lease(self.path)['device_completion_proven'])

    def test_another_process_cannot_take_live_owner(self):
        code="""import sys
from camera_device_lease import CameraDeviceLease, DeviceBusy
try:
 with CameraDeviceLease('child',lock_path=sys.argv[1]):pass
except DeviceBusy:sys.exit(7)
"""
        with CameraDeviceLease('parent',lock_path=self.path):
            result=subprocess.run([sys.executable,'-c',code,str(self.path)],capture_output=True,timeout=10)
        self.assertEqual(result.returncode,7,result.stderr.decode())

    def test_crashed_owner_metadata_is_not_live_or_device_completion(self):
        code="""import os,sys
from camera_device_lease import CameraDeviceLease
lease=CameraDeviceLease('crash',lock_path=sys.argv[1]);lease.__enter__();os._exit(0)
"""
        result=subprocess.run([sys.executable,'-c',code,str(self.path)],capture_output=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr.decode())
        self.assertEqual(json.loads(self.path.read_text())['state'],'HELD')
        observation=inspect_lease(self.path)
        self.assertFalse(observation['live_host_lock'])
        self.assertFalse(observation['device_completion_proven'])
        with CameraDeviceLease('new-local-owner',lock_path=self.path):pass

    def test_exception_releases_lock_without_claiming_device_finished(self):
        with self.assertRaises(OSError):
            with CameraDeviceLease('failure',lock_path=self.path):raise OSError('synthetic')
        self.assertFalse(inspect_lease(self.path)['live_host_lock'])
        self.assertFalse(inspect_lease(self.path)['device_completion_proven'])

    def test_symlink_lock_cannot_overwrite_other_file(self):
        victim=self.path.parent/'original';victim.write_text('preserve')
        self.path.symlink_to(victim)
        with self.assertRaises(OSError):
            with CameraDeviceLease('no-symlink',lock_path=self.path):pass
        self.assertEqual(victim.read_text(),'preserve')


if __name__=='__main__':unittest.main()
