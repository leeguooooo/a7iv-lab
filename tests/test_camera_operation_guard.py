from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch,Mock

from camera_device_lease import CameraDeviceLease
from camera_install_journal import InstallJournal,JournalError
from camera_operation_guard import assert_operation_allowed
import camera_sd_stage


class PendingGuardTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name).resolve();self.root=self.base/'sessions'
        self.j=InstallJournal.create(self.root,'first',plan_sha256='a'*64,body_sha256='b'*64,model='ILCE-7M4')

    def test_current_declared_phase_can_continue_but_not_be_silently_reclassified(self):
        assert_operation_allowed(self.j,allowed_states=('PLANNED',))
        with self.assertRaises(JournalError):assert_operation_allowed(self.j,allowed_states=('SD_STAGED',))
        other=InstallJournal.open(self.j.session_dir);other.advance('SD_STAGE_INTENT')
        with self.assertRaises(JournalError):assert_operation_allowed(self.j,allowed_states=('PLANNED',))

    def test_unknown_blocks_standalone_staging_even_after_host_lock_was_released(self):
        self.j.advance('STOPPED_UNKNOWN')
        with CameraDeviceLease('prior-host',lock_path=self.base/'owner.lock'):pass
        with patch('camera_operation_guard.DEFAULT_SESSIONS',self.root), \
             patch.object(camera_sd_stage,'_stage') as copy:
            with CameraDeviceLease('new-host',lock_path=self.base/'owner.lock') as lease:
                with self.assertRaises(JournalError):camera_sd_stage.stage(lease=lease)
            copy.assert_not_called()

    def test_other_pending_session_blocks_even_safe_current_session(self):
        self.j.advance('CANCELLED_BEFORE_DEVICE_WRITE')
        InstallJournal.create(self.root,'second',plan_sha256='a'*64,body_sha256='b'*64,model='ILCE-7M4')
        with self.assertRaises(JournalError):
            assert_operation_allowed(self.j,allowed_states=('CANCELLED_BEFORE_DEVICE_WRITE',))

    def test_damaged_history_is_not_a_free_device(self):
        (self.j.session_dir/'00000002.json').write_bytes(b'{partial')
        with self.assertRaises(JournalError):assert_operation_allowed(sessions_root=self.root)


if __name__=='__main__':unittest.main()
