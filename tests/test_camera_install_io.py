import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import camera_install_io as io
from camera_device_lease import CameraDeviceLease
from camera_install_journal import InstallJournal


class JournalPinTests(unittest.TestCase):
    def setUp(self):
        self.tmp=self.enterContext(tempfile.TemporaryDirectory())
        self.root=Path(self.tmp).resolve()
        self.lease=self.enterContext(CameraDeviceLease('io-snapshot-test',lock_path=self.root/'lease'))
        self.journal=InstallJournal.create(self.root/'sessions','packet-pin',body_sha256='b'*64,plan_sha256='a'*64,model='ILCE-7M4')
        self.event=self.journal.session_dir/'00000001.json'
    def pin(self):return self.enterContext(io.JournalSnapshotPin(self.journal,self.lease))
    def test_semantic_open_once_and_packet_checks_never_deep_validate(self):
        with patch.object(InstallJournal,'open',wraps=InstallJournal.open) as semantic:
            pin=self.pin()
            self.assertEqual(semantic.call_count,1)
            with patch.object(InstallJournal,'open',side_effect=AssertionError('deep open inside packet')):
                for _ in range(32):self.assertIsNone(pin.check())
            self.assertEqual(semantic.call_count,1)
        self.assertIsNotNone(self.lease.fd)
    def test_ownership_is_required_before_semantic_open(self):
        self.lease.__exit__(None,None,None)
        with patch.object(InstallJournal,'open',side_effect=AssertionError('must not deep-open')) as semantic:
            with self.assertRaises(ValueError):io.JournalSnapshotPin(self.journal,self.lease)
            semantic.assert_not_called()
        self.lease.__enter__()
    def test_lease_instance_replacement_invalidates_snapshot(self):
        pin=self.pin();self.lease.__exit__(None,None,None);self.lease.__enter__()
        with self.assertRaisesRegex(ValueError,'lease identity'):pin.check()
    def test_new_journal_event_refused_without_deep_open(self):
        pin=self.pin();self.journal.advance('SD_STAGE_INTENT')
        with patch.object(InstallJournal,'open',side_effect=AssertionError('deep open forbidden')):
            with self.assertRaises(ValueError):pin.check()
    def test_extra_file_and_deleted_event_refused(self):
        pin=self.pin();extra=self.journal.session_dir/'unexpected';extra.write_bytes(b'x')
        with self.assertRaisesRegex(ValueError,'event set'):pin.check()
        extra.unlink()
        with self.assertRaisesRegex(ValueError,'closed or failed'):pin.check()
    def test_deleted_event_refused(self):
        pin=self.pin();self.event.unlink()
        with self.assertRaises(ValueError):pin.check()
    def test_event_replacement_with_identical_bytes_refused(self):
        pin=self.pin();raw=self.event.read_bytes();self.event.rename(self.root/'old-event');self.event.write_bytes(raw)
        with self.assertRaisesRegex(ValueError,'inode or metadata'):pin.check()
    def test_event_symlink_refused_even_when_target_bytes_match(self):
        pin=self.pin();target=self.root/'event-copy';target.write_bytes(self.event.read_bytes());self.event.unlink();self.event.symlink_to(target)
        with self.assertRaises(ValueError):pin.check()
    def test_directory_replacement_refused(self):
        pin=self.pin();folder=self.journal.session_dir;raw=self.event.read_bytes();folder.rename(self.root/'old-directory');folder.mkdir();self.event.write_bytes(raw)
        with self.assertRaisesRegex(ValueError,'directory identity'):pin.check()
    def test_inplace_bytes_checked_even_if_metadata_observation_matches(self):
        pin=self.pin();identity=pin._files[0]['identity'];raw=self.event.read_bytes();self.event.write_bytes(raw.replace(b'PLANNED',b'CHANGED'))
        os.utime(self.event,ns=(self.event.stat().st_atime_ns,identity[4]))
        with patch.object(io,'_file_identity',return_value=identity):
            with self.assertRaisesRegex(ValueError,'raw bytes'):pin.check()
    def test_stale_caller_object_refused(self):
        pin=self.pin();self.journal._events[0]['details']['not_in_snapshot']=True
        with self.assertRaisesRegex(ValueError,'Caller journal snapshot'):pin.check()
    def test_noncanonical_event_bytes_are_not_silently_normalized(self):
        raw=self.event.read_bytes();self.event.write_bytes(b' '+raw)
        with self.assertRaisesRegex(ValueError,'[Cc]anonical'):io.JournalSnapshotPin(self.journal,self.lease)
    def test_constructor_race_after_full_open_closes_all_owned_FDs(self):
        original_open=InstallJournal.open;opened=[];os_open=os.open
        def semantic(path):
            journal=original_open(path);self.event.write_bytes(b' '+self.event.read_bytes());return journal
        def capture(*args,**kwargs):
            fd=os_open(*args,**kwargs);opened.append(fd);return fd
        with patch.object(InstallJournal,'open',side_effect=semantic),patch.object(io.os,'open',side_effect=capture):
            with self.assertRaises(ValueError):io.JournalSnapshotPin(self.journal,self.lease)
        for fd in set(opened):
            with self.assertRaises(OSError):os.fstat(fd)
        self.assertIsNotNone(self.lease.fd)
    def test_lease_replaced_during_constructor_semantic_open_is_rejected(self):
        original=InstallJournal.open
        def replace(path):
            result=original(path);self.lease.__exit__(None,None,None);self.lease.__enter__();return result
        with patch.object(InstallJournal,'open',side_effect=replace):
            with self.assertRaisesRegex(ValueError,'lease identity'):io.JournalSnapshotPin(self.journal,self.lease)
    def test_event_size_count_and_total_bounds_precede_full_open(self):
        for attr,value in (('MAX_EVENT_BYTES',1),('MAX_EVENTS',0),('MAX_LEDGER_BYTES',1)):
            with self.subTest(bound=attr),patch.object(io,attr,value),patch.object(InstallJournal,'open') as semantic:
                with self.assertRaises(ValueError):io.JournalSnapshotPin(self.journal,self.lease)
                semantic.assert_not_called()
    def test_close_is_idempotent_releases_FDs_but_not_caller_lease(self):
        pin=io.JournalSnapshotPin(self.journal,self.lease);fds=[pin._directory_fd,*(item['fd'] for item in pin._files)]
        pin.close();pin.close()
        for fd in fds:
            with self.assertRaises(OSError):os.fstat(fd)
        self.assertIsNotNone(self.lease.fd)
        with self.assertRaisesRegex(ValueError,'closed or failed'):pin.check()
    def test_semantic_failure_does_not_leave_pinned_descriptors(self):
        with patch.object(InstallJournal,'open',side_effect=ValueError('invalid formal evidence')):
            with self.assertRaisesRegex(ValueError,'invalid formal'):io.JournalSnapshotPin(self.journal,self.lease)
        # The caller still owns its lock and can perform a separately reviewed step.
        self.assertIsNotNone(self.lease.fd)


class DriverTests(unittest.TestCase):
    def test_guard_before_each_call_and_plain_attributes_preserved(self):
        original=Mock();original.label='fixture';original.read.return_value=b'raw'
        guard=Mock();driver=io.PinnedDriver(original,guard)
        self.assertEqual(driver.label,'fixture');self.assertEqual(driver.read(16),b'raw');driver.write(b'x')
        self.assertEqual(guard.call_count,2);original.read.assert_called_once_with(16)
    def test_guard_failure_poisons_proxy_without_any_transport_call_or_retry(self):
        original=Mock();guard=Mock(side_effect=ValueError('ownership drift'));driver=io.PinnedDriver(original,guard)
        with self.assertRaises(ValueError):driver.read(16)
        guard.side_effect=None
        with self.assertRaisesRegex(ValueError,'already failed'):driver.read(16)
        original.read.assert_not_called();self.assertEqual(guard.call_count,1)
    def test_transport_exception_poisons_proxy(self):
        original=Mock();original.read.side_effect=OSError('unknown USB');guard=Mock();driver=io.PinnedDriver(original,guard)
        with self.assertRaises(OSError):driver.read(16)
        original.read.side_effect=None
        with self.assertRaises(ValueError):driver.read(16)
        self.assertEqual(original.read.call_count,1);self.assertEqual(guard.call_count,1)
    def test_falsey_callable_guard_used_without_default_fallback(self):
        class Guard:
            def __init__(self):self.calls=0
            def __bool__(self):return False
            def __call__(self):self.calls+=1
        guard=Guard();driver=io.PinnedDriver(Mock(),guard);driver.read(1);self.assertEqual(guard.calls,1)


if __name__=='__main__':unittest.main()
