"""Offline staging guards: temporary host files and synthetic device metadata only."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import plistlib
import tempfile
import types
import unittest
from unittest import mock

import camera_sd_stage as stage


class StageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.mount = self.root / 'synthetic-card'
        self.mount.mkdir()
        self.source = self.root / 'candidate.dat'
        self.payload = b'offline tiny candidate\x00\xff\n'
        self.source.write_bytes(self.payload)
        self.sha = hashlib.sha256(self.payload).hexdigest()
        self.body = self.mount / 'BODYDATA.DAT'
        self.body.write_bytes(b'original BODYDATA; preserve byte for byte')
        self.original = self.body.read_bytes()
        self.report = self.root / 'report'
        self.volume = dict(device='disk900s1', parent='disk900', mount=str(self.mount),
                           volume_uuid='synthetic-uuid', registry_id=900,
                           body_matched=True, body_sha256='a' * 64, filesystem='exfat')
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.lease = self.stack.enter_context(mock.patch.object(stage, 'CameraDeviceLease'))
        self.stack.enter_context(mock.patch.object(stage, 'assert_operation_allowed'))
        for name, value in [('SOURCE', self.source), ('DIGEST', self.sha),
                            ('SIZE', len(self.payload)), ('REPORT', self.report)]:
            self.stack.enter_context(mock.patch.object(stage, name, value))
        # Any accidental discovery implementation call must fail before subprocess access.
        self.stack.enter_context(mock.patch.object(stage.subprocess, 'check_output',
                                                   side_effect=AssertionError('real discovery forbidden')))
        self.discover = self.stack.enter_context(mock.patch.object(stage, 'discover',
                                                                   return_value=self.volume.copy()))
        self.stdout = io.StringIO()
        self.stack.enter_context(contextlib.redirect_stdout(self.stdout))

    @property
    def folder(self):
        return self.mount / '.camera-use-staging' / ('fl23-' + self.sha[:16])

    def assert_no_success(self):
        self.assertFalse((self.report / 'completed.json').exists())
        self.assertNotIn('STAGED_UNRECOGNIZED_FILE_VERIFIED_NOT_ACTIVATED', self.stdout.getvalue())

    def test_success_copies_candidate_and_preserves_existing_bodydata(self):
        stage.stage()
        self.assertEqual((self.folder / 'candidate.staged').read_bytes(), self.payload)
        self.assertEqual(self.body.read_bytes(), self.original)
        result = json.loads((self.report / 'completed.json').read_text())
        self.assertEqual(result['state'], 'STAGED_UNRECOGNIZED_FILE_VERIFIED_NOT_ACTIVATED')
        self.assertTrue(result['existing_root_update_unchanged'])
        self.assertFalse(result['BODYDATA_DAT_created_or_replaced'])
        self.assertFalse(result['updater_invoked'])
        self.assertEqual(self.discover.call_count, 3)

    def test_source_hash_mismatch_has_no_card_mutation(self):
        self.source.write_bytes(b'X' * len(self.payload))
        with self.assertRaisesRegex(ValueError, 'Frozen candidate changed'):
            stage.stage()
        self.discover.assert_not_called()
        self.assertEqual(list(self.mount.iterdir()), [self.body])
        self.assertEqual(self.body.read_bytes(), self.original)
        self.assertFalse(self.report.exists())
        self.assert_no_success()

    def test_preflight_identity_changes_have_no_card_mutation(self):
        for key in ('device', 'parent', 'mount', 'volume_uuid', 'registry_id'):
            with self.subTest(identity_field=key):
                self.report = self.root / ('report-' + key)
                with mock.patch.object(stage, 'REPORT', self.report):
                    changed = dict(self.volume, **{key: 'changed'})
                    self.discover.side_effect = [self.volume.copy(), changed]
                    with self.assertRaisesRegex(ValueError, 'changed during preflight'):
                        stage.stage()
                self.assertEqual(list(self.mount.iterdir()), [self.body])
                self.assertEqual(self.body.read_bytes(), self.original)
                self.assert_no_success()

    def test_existing_attempt_is_not_overwritten(self):
        self.folder.mkdir(parents=True)
        previous = self.folder / 'candidate.staged'
        previous.write_bytes(b'previous attempt must remain intact')
        with self.assertRaises(FileExistsError):
            stage.stage()
        self.assertEqual(previous.read_bytes(), b'previous attempt must remain intact')
        self.assertEqual(self.body.read_bytes(), self.original)
        self.assert_no_success()

    def test_bad_target_readback_stops_without_success_report(self):
        original_digest = stage.digest

        def readback(path, uncached=False):
            if Path(path).name == 'candidate.staged':
                return '0' * 64
            return original_digest(path, uncached=uncached)

        with mock.patch.object(stage, 'digest', side_effect=readback):
            with self.assertRaisesRegex(ValueError, 'readback mismatch'):
                stage.stage()
        self.assert_no_success()
        self.assertEqual(self.body.read_bytes(), self.original)
        stopped = json.loads((self.report / 'stopped.json').read_text())
        self.assertFalse(stopped['automatic_retry'])

    def test_bodydata_changed_during_copy_stops_without_success_report(self):
        original_digest = stage.digest

        def readback(path, uncached=False):
            result = original_digest(path, uncached=uncached)
            if Path(path).name == 'candidate.staged':
                self.body.write_bytes(b'simulated external modification')
            return result

        with mock.patch.object(stage, 'digest', side_effect=readback):
            with self.assertRaisesRegex(ValueError, 'Existing root BODYDATA changed'):
                stage.stage()
        self.assert_no_success()
        self.assertTrue((self.report / 'stopped.json').exists())

    def test_identity_changed_after_copy_stops_without_success_report(self):
        changed = dict(self.volume, volume_uuid='another-card')
        self.discover.side_effect = [self.volume.copy(), self.volume.copy(), changed]
        with self.assertRaisesRegex(ValueError, 'identity changed during copy'):
            stage.stage()
        self.assert_no_success()
        self.assertEqual(self.body.read_bytes(), self.original)


class ActivationTests(unittest.TestCase):
    setUp = StageTests.setUp
    folder = StageTests.folder

    def prepare(self):
        stage.stage()
        self.discover.reset_mock()
        self.calls = []

    def rename(self, source, target):
        # Local fixture only; link fails atomically if target already exists.
        self.assertTrue((self.report / 'activation-intent.json').is_file())
        self.calls.append((source, target))
        os.link(source, target)
        source.unlink()

    def activate(self, **overrides):
        values = dict(activation_authorized=True, slot1_confirmed=True, rename_fn=self.rename)
        values.update(overrides)
        return stage.activate_staged(**values)

    def assert_stopped(self):
        self.assertFalse((self.report / 'activated-preview-only.json').exists())
        value = json.loads((self.report / 'activation-stopped.json').read_text())
        self.assertFalse(value['automatic_retry'])
        self.assertFalse(value['automatic_rollback'])
        return value

    def test_approval_and_slot_confirmation_are_both_required_before_discovery(self):
        for values in ({}, {'activation_authorized': True}, {'slot1_confirmed': True}):
            with self.subTest(values=values):
                with self.assertRaises(ValueError):
                    stage.activate_staged(rename_fn=mock.Mock(), **values)
        self.discover.assert_not_called()
        self.lease.assert_not_called()
        self.assertEqual(self.body.read_bytes(), self.original)
        self.assertFalse((self.mount / '.camera-use-staging').exists())

    def test_activation_preserves_original_in_exclusive_backup_and_never_invokes_updater(self):
        self.prepare()
        result = self.activate()
        self.assertEqual(self.body.read_bytes(), self.payload)
        self.assertEqual((self.folder / 'original-BODYDATA.DAT').read_bytes(), self.original)
        self.assertFalse((self.folder / 'candidate.staged').exists())
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(result['state'], 'ACTIVATED_PREVIEW_ONLY')
        self.assertFalse(result['updater_invoked'])
        self.assertFalse(result['installation_authorized'])

    def test_existing_backup_is_never_overwritten(self):
        self.prepare()
        backup = self.folder / 'original-BODYDATA.DAT'
        backup.write_bytes(b'earlier backup')
        with self.assertRaisesRegex(ValueError, 'backup already exists'): self.activate()
        self.assertEqual(backup.read_bytes(), b'earlier backup')
        self.assertEqual(self.body.read_bytes(), self.original)
        self.assertEqual(self.calls, [])
        self.assert_stopped()

    def test_target_created_after_backup_is_not_overwritten(self):
        self.prepare()
        def race(source, target):
            if target == self.body:
                target.write_bytes(b'external root collision')
            self.rename(source, target)
        with self.assertRaises(FileExistsError): self.activate(rename_fn=race)
        self.assertEqual(self.body.read_bytes(), b'external root collision')
        self.assertEqual((self.folder / 'original-BODYDATA.DAT').read_bytes(), self.original)
        self.assertEqual((self.folder / 'candidate.staged').read_bytes(), self.payload)
        self.assert_stopped()

    def test_interrupt_after_backup_never_rolls_back_or_retries(self):
        self.prepare()
        def interrupt(source, target):
            self.rename(source, target)
            raise KeyboardInterrupt('simulated interruption after rename')
        with self.assertRaises(KeyboardInterrupt): self.activate(rename_fn=interrupt)
        self.assertEqual(len(self.calls), 1)
        self.assertFalse(self.body.exists())
        self.assertEqual((self.folder / 'original-BODYDATA.DAT').read_bytes(), self.original)
        self.assertEqual((self.folder / 'candidate.staged').read_bytes(), self.payload)
        stopped = self.assert_stopped()
        self.assertEqual(stopped['error_type'], 'KeyboardInterrupt')
        self.assertTrue(stopped['backup']['exists'])
        self.assertFalse(stopped['target']['exists'])

    def test_changed_identity_prevents_any_rename(self):
        self.prepare()
        self.discover.side_effect = [self.volume, dict(self.volume, volume_uuid='other-card')]
        with self.assertRaisesRegex(ValueError, 'identity changed'): self.activate()
        self.assertEqual(self.calls, [])
        self.assertEqual(self.body.read_bytes(), self.original)
        self.assert_stopped()

    def test_changed_body_prevents_any_rename(self):
        self.prepare()
        self.discover.return_value = dict(self.volume, body_sha256='b' * 64)
        with self.assertRaisesRegex(ValueError, 'identity changed'): self.activate()
        self.assertEqual(self.calls, [])
        self.assert_stopped()

    def test_identity_change_after_backup_stops_without_root_activation(self):
        self.prepare()
        self.discover.side_effect = [self.volume, self.volume, dict(self.volume, device='other')]
        with self.assertRaisesRegex(ValueError, 'identity changed'): self.activate()
        self.assertEqual(len(self.calls), 1)
        self.assertFalse(self.body.exists())
        self.assertEqual((self.folder / 'original-BODYDATA.DAT').read_bytes(), self.original)
        self.assert_stopped()

    def test_changed_candidate_or_original_root_prevents_card_rename(self):
        self.prepare()
        (self.folder / 'candidate.staged').write_bytes(b'X' * len(self.payload))
        with self.assertRaisesRegex(ValueError, 'candidate changed'): self.activate()
        self.assertEqual(self.calls, [])
        self.assertEqual(self.body.read_bytes(), self.original)
        self.assert_stopped()

    def test_original_changed_after_staging_prevents_card_rename(self):
        self.prepare()
        self.body.write_bytes(b'changed externally')
        with self.assertRaisesRegex(ValueError, 'Original root BODYDATA changed'): self.activate()
        self.assertEqual(self.calls, [])
        self.assert_stopped()

    def test_corrupted_backup_stops_before_candidate_activation(self):
        self.prepare()
        def corrupt_backup(source, target):
            self.rename(source, target)
            target.write_bytes(b'corrupted backup')
        with self.assertRaisesRegex(ValueError, 'backup readback mismatch'):
            self.activate(rename_fn=corrupt_backup)
        self.assertEqual(len(self.calls), 1)
        self.assertFalse(self.body.exists())
        self.assertTrue((self.folder / 'candidate.staged').exists())
        self.assert_stopped()

    def test_corrupted_activated_target_has_no_success_report_or_rollback(self):
        self.prepare()
        def corrupt_root(source, target):
            self.rename(source, target)
            if target == self.body:
                target.write_bytes(b'X' * len(self.payload))
        with self.assertRaisesRegex(ValueError, 'root candidate readback mismatch'):
            self.activate(rename_fn=corrupt_root)
        self.assertEqual(len(self.calls), 2)
        self.assertEqual((self.folder / 'original-BODYDATA.DAT').read_bytes(), self.original)
        self.assertFalse((self.folder / 'candidate.staged').exists())
        self.assert_stopped()

    def test_activation_intent_persistence_failure_prevents_rename(self):
        self.prepare()
        save = stage.save
        def fail_intent(path, value):
            if path.name == 'activation-intent.json': raise OSError('intent fsync failed')
            return save(path, value)
        with mock.patch.object(stage, 'save', side_effect=fail_intent):
            with self.assertRaisesRegex(OSError, 'intent fsync'): self.activate()
        self.assertEqual(self.calls, [])
        self.assertEqual(self.body.read_bytes(), self.original)
        self.assert_stopped()

    def test_completed_report_is_required_before_discovery(self):
        self.report.mkdir()
        with self.assertRaisesRegex(ValueError, 'completed stage report'): self.activate()
        self.discover.assert_not_called()
        self.assert_stopped()

    def test_original_absent_is_activated_without_backup(self):
        self.body.unlink()
        self.prepare()
        self.activate()
        self.assertEqual(self.body.read_bytes(), self.payload)
        self.assertFalse((self.folder / 'original-BODYDATA.DAT').exists())
        self.assertEqual(len(self.calls), 1)

    def test_held_lease_is_reused_for_stage_and_activation(self):
        lease = stage._LeaseType('offline', lock_path=self.root / 'never-opened.lock')
        lease.fd, lease.metadata = 123, {'state': 'HELD'}
        stage.stage(lease=lease)
        self.lease.assert_not_called()
        self.calls = []
        self.activate(lease=lease)
        self.lease.assert_not_called()
        self.assertFalse((self.root / 'never-opened.lock').exists())

    def test_unheld_supplied_lease_is_rejected_before_discovery(self):
        lease = stage._LeaseType('offline', lock_path=self.root / 'never-opened.lock')
        with self.assertRaisesRegex(ValueError, 'Caller-held'):
            self.activate(lease=lease)
        self.discover.assert_not_called()
        with self.assertRaisesRegex(ValueError, 'Caller-held'):
            stage.stage(lease=lease)
        self.discover.assert_not_called()


class DiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        reference = self.root / 'output/backup-01/execution/run.json'
        reference.parent.mkdir(parents=True)
        reference.write_text(json.dumps({'body': {'usb_serial_sha256':
            hashlib.sha256(b'synthetic-body').hexdigest()}}))
        self.tree = [{'IOObjectClass': 'IOUSBHostDevice', 'idVendor': 0x054c,
                      'idProduct': 0x0da5, 'USB Serial Number': 'synthetic-body',
                      'IORegistryEntryID': 900, 'children': [
                          {'IOObjectClass': 'IOMedia', 'BSD Name': 'disk900', 'Whole': True},
                          {'IOObjectClass': 'IOMedia', 'BSD Name': 'disk900s1', 'Whole': False},
                          {'IOObjectClass': 'IOMedia', 'BSD Name': 'disk900s2', 'Whole': False}]}]
        self.infos = {
            'disk900s1': self.card_info('CARD', 'uuid-card'),
            'disk900s2': dict(self.card_info('PMHOME', 'uuid-pmhome'),
                               Writable=False, TotalSize=32 << 20),
        }
        self.commands = []
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.object(stage, 'ROOT', self.root))
        self.stack.enter_context(mock.patch.object(stage, 'SIZE', 23))
        self.stack.enter_context(mock.patch.object(stage.subprocess, 'check_output',
                                                   side_effect=self.synthetic_command))
        # These paths are lexical metadata only: do not inspect any actual /Volumes entries.
        self.stack.enter_context(mock.patch.object(Path, 'resolve', lambda path, **kwargs: path))
        self.stack.enter_context(mock.patch.object(stage.os.path, 'ismount', return_value=True))
        self.stack.enter_context(mock.patch.object(stage.os, 'statvfs',
            return_value=types.SimpleNamespace(f_bavail=1 << 20, f_frsize=4096)))

    @staticmethod
    def card_info(name, uuid):
        return dict(Writable=True, TotalSize=8 << 30, MountPoint='/Volumes/' + name,
                    VolumeName=name, ParentWholeDisk='disk900', VolumeUUID=uuid,
                    FilesystemType='exfat')

    def synthetic_command(self, argv):
        self.commands.append(argv)
        if argv == ['/usr/sbin/ioreg', '-r', '-c', 'IOUSBHostDevice', '-a', '-l']:
            return plistlib.dumps(self.tree)
        if argv[:3] == ['/usr/sbin/diskutil', 'info', '-plist'] and len(argv) == 4:
            return plistlib.dumps(self.infos[argv[3]])
        raise AssertionError('Unexpected subprocess command: ' + repr(argv))

    def test_read_only_pmhome_is_excluded(self):
        result = stage.discover()
        self.assertEqual(result['device'], 'disk900s1')
        self.assertEqual(result['mount'], '/Volumes/CARD')
        self.assertTrue(result['body_matched'])
        self.assertEqual(result['excluded_media'], [dict(BSD='disk900s2', name='PMHOME',
                                                        bytes=32 << 20, writable=False)])
        self.assertEqual(len(self.commands), 3)

    def test_wrong_body_is_rejected_before_disk_queries(self):
        self.tree[0]['USB Serial Number'] = 'different-body'
        with self.assertRaisesRegex(ValueError, 'Exactly one reference Sony MSC body'):
            stage.discover()
        self.assertEqual(len(self.commands), 1)

    def test_multiple_writable_cards_are_rejected(self):
        self.infos['disk900s2'] = self.card_info('SECOND_CARD', 'uuid-second')
        with self.assertRaisesRegex(ValueError, 'one unambiguous writable camera card'):
            stage.discover()

    def test_only_read_only_pmhome_is_not_a_stage_destination(self):
        self.infos['disk900s1']['Writable'] = False
        with self.assertRaisesRegex(ValueError, 'one unambiguous writable camera card'):
            stage.discover()


if __name__ == '__main__':
    unittest.main()
