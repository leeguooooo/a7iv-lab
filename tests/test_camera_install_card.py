import copy
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import camera_install_card as card
from camera_device_lease import CameraDeviceLease
from camera_install_journal import InstallJournal
import test_camera_install_cancel as cancel_fixtures


class ActiveCardTests(unittest.TestCase):
    def setUp(self):
        self.base = cancel_fixtures.InactiveCardTests()
        self.base.setUp()
        self.addCleanup(self.base.doCleanups)
        self.root = self.base.root
        self.enterContext(patch.object(card, 'DIGEST', hashlib.sha256(self.base.payload).hexdigest()))
        self.enterContext(patch.object(card, 'SIZE', len(self.base.payload)))
        self.enterContext(patch.object(card, 'DEFAULT_SESSIONS', self.root / 'sessions'))
        self.lease = self.enterContext(CameraDeviceLease('active-card-model', lock_path=self.root / 'lease'))
        self.journal = InstallJournal.create(self.root / 'sessions', 'test-card',
            plan_sha256='a'*64, body_sha256=self.base.body, model='ILCE-7M4')
        self.journal.advance('SD_STAGE_INTENT')
        self.journal.advance('SD_STAGED', details=dict(stage_report=str(self.base.stage_path),
            stage_report_sha256=self.base.reference['sha256']))
        self.backup = self.base.candidate.parent / 'original-BODYDATA.DAT'
        self.base.root_update.rename(self.backup)
        self.base.candidate.rename(self.base.root_update)
        self.activation = dict(state='ACTIVATED_PREVIEW_ONLY', source_sha256=card.DIGEST, bytes=card.SIZE,
            target=str(self.base.root_update), backup=str(self.backup),
            volume_identity=copy.deepcopy(self.base.volume), slot1_manually_confirmed=True,
            original_root_update=copy.deepcopy(self.base.stage['existing_root_update']),
            updater_invoked=False, installation_authorized=False, camera_internal_firmware_modified=False)
        self.activation_path = self.root / 'activation.json'
        self.write_activation()

    def write_activation(self):
        raw = json.dumps(self.activation).encode();self.activation_path.write_bytes(raw)
        self.activation_ref = dict(path=str(self.activation_path), sha256=hashlib.sha256(raw).hexdigest())

    def observe(self, **changes):
        values = dict(body_sha256=self.base.body, lease=self.lease, journal=self.journal,
                      card_read_authorized=True, discover=self.base.discover)
        values.update(changes)
        return card.observe_active_card(self.base.reference, self.activation_ref, **values)

    def test_full_candidate_and_preserved_original_are_read_without_mutation(self):
        before = self.journal.events
        result = self.observe()
        self.assertEqual(result['candidate']['sha256'], card.DIGEST)
        self.assertEqual(result['original_backup']['sha256'], hashlib.sha256(self.base.original).hexdigest())
        self.assertFalse(result['source_is_hardware'])
        self.assertFalse(result['installation_authorized'])
        self.assertFalse(result['future_card_state_proven'])
        self.assertFalse(result['explicit_card_writes'])
        self.assertEqual(self.journal.events, before)
        self.assertEqual(self.base.root_update.read_bytes(), self.base.payload)
        self.assertEqual(self.backup.read_bytes(), self.base.original)

    def test_same_card_remount_before_observation_is_supported(self):
        new = self.root / 'remount';self.base.mount.rename(new)
        self.base.volume.update(mount=str(new), device='disk20s1', parent='disk20', registry_id=20)
        result = self.observe()
        self.assertEqual(result['candidate']['path'], str(new / 'BODYDATA.DAT'))
        self.assertEqual(result['candidate']['sha256'], card.DIGEST)

    def test_absent_original_requires_absent_backup(self):
        self.backup.unlink()
        self.base.stage['existing_root_update'] = dict(exists=False);self.base.write_stage()
        self.journal.advance('CANCELLED_BEFORE_DEVICE_WRITE')
        root = self.root / 'absent-sessions'
        self.journal = InstallJournal.create(root, 'absent',plan_sha256='a'*64,
            body_sha256=self.base.body, model='ILCE-7M4')
        self.journal.advance('SD_STAGE_INTENT')
        self.journal.advance('SD_STAGED', details=dict(stage_report=str(self.base.stage_path),
            stage_report_sha256=self.base.reference['sha256']))
        self.activation['original_root_update'] = dict(exists=False);self.write_activation()
        result = self.observe();self.assertFalse(result['original_backup']['exists'])
        self.backup.write_bytes(b'appeared')
        with self.assertRaisesRegex(ValueError, 'Unexpected original'):self.observe()

    def test_wrong_candidate_or_backup_is_rejected(self):
        for p in (self.base.root_update, self.backup):
            with self.subTest(path=p):
                raw=p.read_bytes();p.write_bytes(b'x'*len(raw))
                with self.assertRaises(ValueError):self.observe()
                p.write_bytes(raw)

    def test_reappearing_staged_candidate_and_symlinks_are_rejected(self):
        self.base.candidate.write_bytes(self.base.payload)
        with self.assertRaises(ValueError):self.observe()
        self.base.candidate.unlink()
        self.base.candidate.symlink_to(self.base.root_update)
        with self.assertRaises(ValueError):self.observe()

    def test_unapproved_or_default_noncanonical_route_has_zero_discovery(self):
        for changes in (dict(card_read_authorized=False), dict(discover=None)):
            with self.subTest(changes=changes), self.assertRaises(ValueError):self.observe(**changes)
        self.base.discover.assert_not_called()

    def test_wrong_card_or_handle_drift_is_rejected(self):
        self.base.volume['volume_uuid']='another'
        with self.assertRaises(ValueError):self.observe()
        self.base.volume['volume_uuid']='fixture-uuid'
        calls=0
        def drifting():
            nonlocal calls
            calls+=1;v=copy.deepcopy(self.base.volume)
            if calls>1:v['registry_id']+=1
            return v
        with self.assertRaisesRegex(ValueError, 'handles changed'):self.observe(discover=drifting)

    def test_lease_replacement_during_discovery_stops_observation(self):
        def replace():
            self.lease.__exit__(None,None,None);self.lease.__enter__()
            return copy.deepcopy(self.base.volume)
        with self.assertRaisesRegex(ValueError,'lease identity changed'):self.observe(discover=replace)

    def test_activation_or_stage_reference_tampering_is_rejected(self):
        self.activation_path.write_bytes(b'{}')
        with self.assertRaises(ValueError):self.observe()
        self.write_activation();self.activation['backup']=str(self.root/'wrong')
        self.write_activation()
        with self.assertRaisesRegex(ValueError,'paths differ'):self.observe()


if __name__ == '__main__':unittest.main()
