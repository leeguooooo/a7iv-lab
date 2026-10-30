import hashlib
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from tools.card_backup_replace import (Assurance, FileExpectation, ReplacementError,
                                      ReplacementPlan, WithdrawalPlan, _IO,
                                      replace_with_backup, withdraw_with_backup)


class CardBackupReplaceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.card = self.base / 'card'; self.card.mkdir()
        self.old = b'approved-old-update' * 71
        self.new = b'complete-new-candidate' * 97
        self.root = self.card / 'BODYDATA.DAT'; self.root.write_bytes(self.old)
        self.new_sha = hashlib.sha256(self.new).hexdigest()
        self.attempt = self.card / '.camera-use-staging' / ('fl23-' + self.new_sha[:16] + '-' + 'a' * 16)
        self.attempt.mkdir(parents=True)
        self.candidate = self.attempt / 'candidate.staged'; self.candidate.write_bytes(self.new)
        self.backup = self.attempt / 'original-BODYDATA.DAT'
        self.plan = ReplacementPlan(
            FileExpectation(self.candidate, len(self.new), self.new_sha),
            FileExpectation(self.root, len(self.old), hashlib.sha256(self.old).hexdigest()), self.backup)
        self.evidence = self.base / 'evidence'
        self.identity = {'body_sha256': 'b' * 64, 'volume_uuid': 'test-volume', 'device': os.stat(self.card).st_dev}

    def run_protocol(self, **kwargs):
        values = dict(expected_card_identity=self.identity, identity_reader=lambda: dict(self.identity),
                      assurance=Assurance.SINGLE_WRITER_BACKUP_REPLACE,
                      single_writer_acknowledged=True, _operations=_IO())
        values.update(kwargs)
        return replace_with_backup(self.plan, self.evidence, **values)

    def assert_original_preserved(self):
        self.assertEqual(self.root.read_bytes(), self.old)
        self.assertEqual(self.candidate.read_bytes(), self.new)

    def assert_stopped(self):
        self.assertFalse((self.evidence / 'completed.json').exists())
        stopped = json.loads((self.evidence / 'stopped.json').read_text())
        self.assertEqual(stopped['state'], 'UNKNOWN')
        self.assertFalse(stopped['automatic_retry'])
        self.assertFalse(stopped['automatic_rollback'])

    def prepare_withdrawal(self):
        self.run_protocol()
        self.evidence = self.base / 'withdrawal-proof'
        return WithdrawalPlan(FileExpectation(self.root, len(self.new), self.new_sha),
                              FileExpectation(self.backup, len(self.old), hashlib.sha256(self.old).hexdigest()),
                              self.candidate)

    def run_withdrawal(self, plan, **kwargs):
        values = dict(expected_card_identity=self.identity, identity_reader=lambda: dict(self.identity),
                      assurance=Assurance.SINGLE_WRITER_BACKUP_RESTORE,
                      single_writer_acknowledged=True, _operations=_IO())
        values.update(kwargs)
        return withdraw_with_backup(plan, self.evidence, **values)

    def test_publishes_complete_candidate_and_retains_old_bytes(self):
        result = self.run_protocol()
        self.assertEqual(self.root.read_bytes(), self.new)
        self.assertEqual(self.backup.read_bytes(), self.old)
        self.assertFalse(self.candidate.exists())
        self.assertEqual(result, json.loads((self.evidence / 'completed.json').read_text()))
        self.assertEqual(result['execution_kind'], 'INJECTED_IO_MODEL')
        self.assertFalse(result['atomic_no_clobber'])
        self.assertFalse(result['external_writers_excluded_by_module'])
        self.assertFalse(result['power_loss_atomicity_proven'])

    def test_default_contract_refuses_no_clobber_downgrade(self):
        with self.assertRaises(ValueError):
            replace_with_backup(self.plan, self.evidence, expected_card_identity=self.identity,
                                identity_reader=lambda: self.identity)
        self.assert_original_preserved(); self.assertFalse(self.evidence.exists())

    def test_single_writer_requires_true_not_truthiness(self):
        for value in (False, 1, 'yes', None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.run_protocol(single_writer_acknowledged=value)
        self.assert_original_preserved(); self.assertFalse(self.backup.exists())

    def test_identity_mismatch_stops_before_any_backup_or_evidence(self):
        with self.assertRaises(ValueError):
            self.run_protocol(identity_reader=lambda: {'volume_uuid': 'other'})
        self.assert_original_preserved(); self.assertFalse(self.backup.exists())
        self.assertFalse(self.evidence.exists())

    def test_identity_change_after_backup_does_not_replace(self):
        def identity():
            return {'wrong': True} if self.backup.exists() else self.identity
        with self.assertRaises(ReplacementError):
            self.run_protocol(identity_reader=identity)
        self.assert_original_preserved(); self.assertEqual(self.backup.read_bytes(), self.old)
        self.assert_stopped()

    def test_existing_backup_is_preserved_and_rejected(self):
        self.backup.write_bytes(b'previous backup')
        with self.assertRaises(ValueError):
            self.run_protocol()
        self.assertEqual(self.backup.read_bytes(), b'previous backup'); self.assert_original_preserved()

    def test_backup_symlink_is_not_followed(self):
        other = self.base / 'other'; other.write_bytes(b'untouched')
        self.backup.symlink_to(other)
        with self.assertRaises(ValueError):
            self.run_protocol()
        self.assertEqual(other.read_bytes(), b'untouched'); self.assert_original_preserved()

    def test_root_symlink_is_not_followed(self):
        real = self.base / 'real'; self.root.rename(real); self.root.symlink_to(real)
        with self.assertRaises(ValueError):
            self.run_protocol()
        self.assertEqual(real.read_bytes(), self.old); self.assertFalse(self.backup.exists())

    def test_candidate_parent_symlink_is_rejected(self):
        renamed = self.attempt.with_name('moved'); self.attempt.rename(renamed); self.attempt.symlink_to(renamed)
        with self.assertRaises(ValueError):
            self.run_protocol()
        self.assertEqual(self.root.read_bytes(), self.old)

    def test_hardlinked_original_is_rejected(self):
        os.link(self.root, self.base / 'alias')
        with self.assertRaises(ValueError):
            self.run_protocol()
        self.assert_original_preserved(); self.assertFalse(self.backup.exists())

    def test_trailing_candidate_content_is_rejected(self):
        with self.candidate.open('ab') as stream:
            stream.write(b'trailing')
        with self.assertRaises(ValueError):
            self.run_protocol()
        self.assertEqual(self.root.read_bytes(), self.old); self.assertFalse(self.backup.exists())

    def test_wrong_candidate_digest_is_rejected(self):
        self.candidate.write_bytes(b'x' * len(self.new))
        with self.assertRaises(ValueError):
            self.run_protocol()
        self.assertEqual(self.root.read_bytes(), self.old); self.assertFalse(self.backup.exists())

    def test_short_reads_and_writes_are_completed(self):
        result = self.run_protocol(_operations=_IO(
            read=lambda fd, size: os.read(fd, min(size, 7)),
            write=lambda fd, value: os.write(fd, value[:5])))
        self.assertEqual(result['state'], 'COMPLETED')
        self.assertEqual(self.root.read_bytes(), self.new); self.assertEqual(self.backup.read_bytes(), self.old)

    def test_premature_eof_is_rejected(self):
        with self.assertRaises(ValueError):
            self.run_protocol(_operations=_IO(read=lambda fd, size: b''))
        self.assert_original_preserved(); self.assertFalse(self.backup.exists())

    def test_zero_write_preserves_original_and_unknown_evidence(self):
        def write(fd, data):
            return 0 if self.backup.exists() and os.fstat(fd).st_ino == self.backup.stat().st_ino else os.write(fd, data)
        with self.assertRaises(ReplacementError):
            self.run_protocol(_operations=_IO(write=write))
        self.assert_original_preserved(); self.assert_stopped()

    def test_original_changed_before_replace_is_not_published(self):
        changed = False
        def fsync(fd):
            nonlocal changed
            os.fsync(fd)
            if self.backup.exists() and not changed:
                self.root.write_bytes(b'foreign-new-original'); changed = True
        with self.assertRaises(ReplacementError):
            self.run_protocol(_operations=_IO(fsync=fsync))
        self.assertEqual(self.root.read_bytes(), b'foreign-new-original')
        self.assertEqual(self.candidate.read_bytes(), self.new); self.assert_stopped()

    def test_replace_failure_leaves_complete_backup_and_both_input_names(self):
        def fail(*args, **kwargs):
            raise OSError('rename failed')
        with self.assertRaises(ReplacementError) as error:
            self.run_protocol(_operations=_IO(replace=fail))
        self.assertEqual(error.exception.phase, 'REPLACE_MAY_HAVE_OCCURRED')
        self.assert_original_preserved(); self.assertEqual(self.backup.read_bytes(), self.old)
        self.assert_stopped()

    def test_lost_rename_reply_leaves_new_root_and_no_rollback(self):
        def lost_reply(*args, **kwargs):
            os.replace(*args, **kwargs)
            raise OSError('result lost')
        with self.assertRaises(ReplacementError):
            self.run_protocol(_operations=_IO(replace=lost_reply))
        self.assertEqual(self.root.read_bytes(), self.new); self.assertEqual(self.backup.read_bytes(), self.old)
        self.assertFalse(self.candidate.exists()); self.assert_stopped()

    def test_directory_fsync_failure_after_replace_keeps_new_root(self):
        def fsync(fd):
            if not self.candidate.exists():
                raise OSError('directory sync failed')
            os.fsync(fd)
        with self.assertRaises(ReplacementError) as error:
            self.run_protocol(_operations=_IO(fsync=fsync))
        self.assertEqual(error.exception.phase, 'REPLACED_NOT_FULLY_VERIFIED')
        self.assertEqual(self.root.read_bytes(), self.new); self.assertEqual(self.backup.read_bytes(), self.old)
        self.assertFalse((self.evidence / 'completed.json').exists())

    def test_backup_fsync_failure_never_replaces_root(self):
        def fsync(fd):
            if self.backup.exists() and os.fstat(fd).st_ino == self.backup.stat().st_ino:
                raise OSError('backup sync failed')
            os.fsync(fd)
        with self.assertRaises(ReplacementError):
            self.run_protocol(_operations=_IO(fsync=fsync))
        self.assert_original_preserved(); self.assert_stopped()

    def test_evidence_directory_cannot_be_on_card(self):
        self.evidence = self.card / 'evidence'
        with self.assertRaises(ValueError):
            self.run_protocol()
        self.assert_original_preserved(); self.assertFalse(self.backup.exists())

    def test_evidence_is_single_use_even_after_success(self):
        self.run_protocol()
        with self.assertRaises(FileExistsError):
            self.run_protocol()
        self.assertEqual(self.root.read_bytes(), self.new); self.assertEqual(self.backup.read_bytes(), self.old)

    def test_different_device_is_rejected_before_backup(self):
        original_fstat = os.fstat
        candidate_inode = self.candidate.stat().st_ino
        def fstat(fd):
            value = original_fstat(fd)
            if value.st_ino != candidate_inode:
                return value
            names = ('st_dev', 'st_ino', 'st_size', 'st_mode', 'st_nlink', 'st_mtime_ns', 'st_ctime_ns')
            fields = {name: getattr(value, name) for name in names}
            fields['st_dev'] += 1
            return SimpleNamespace(**fields)
        with mock.patch('tools.card_backup_replace.os.fstat', side_effect=fstat), self.assertRaises(ValueError):
            self.run_protocol()
        self.assert_original_preserved(); self.assertFalse(self.backup.exists())

    def test_partial_backup_read_failure_preserves_partial_backup(self):
        count = 0
        def read(fd, size):
            nonlocal count
            if self.backup.exists() and os.fstat(fd).st_ino == self.root.stat().st_ino:
                count += 1
                if count > 1:
                    raise OSError('source read failed')
                return os.read(fd, 5)
            return os.read(fd, size)
        with self.assertRaises(ReplacementError):
            self.run_protocol(_operations=_IO(read=read))
        self.assertEqual(self.backup.read_bytes(), self.old[:5]); self.assert_original_preserved(); self.assert_stopped()

    def test_backup_changed_after_initial_readback_prevents_replace(self):
        changed = False
        def fsync(fd):
            nonlocal changed
            os.fsync(fd)
            if self.backup.exists() and os.fstat(fd).st_ino == self.attempt.stat().st_ino and not changed:
                self.backup.write_bytes(b'foreign'); changed = True
        with self.assertRaises(ReplacementError):
            self.run_protocol(_operations=_IO(fsync=fsync))
        self.assert_original_preserved(); self.assertEqual(self.backup.read_bytes(), b'foreign'); self.assert_stopped()

    def test_claiming_strict_no_clobber_is_rejected(self):
        with self.assertRaises(ValueError):
            self.run_protocol(assurance=Assurance.NO_CLOBBER)
        self.assert_original_preserved(); self.assertFalse(self.backup.exists())

    def test_withdrawal_restores_original_and_preserves_candidate(self):
        result = self.run_withdrawal(self.prepare_withdrawal())
        self.assertEqual(self.root.read_bytes(), self.old)
        self.assertEqual(self.candidate.read_bytes(), self.new)
        self.assertFalse(self.backup.exists())
        self.assertEqual(result['protocol'], 'BACKUP_COPY_ATOMIC_RESTORE')
        self.assertEqual(result['operation'], 'WITHDRAW')
        self.assertTrue(result['original_backup_source_absent'])
        self.assertEqual(result['original_sha256'], hashlib.sha256(self.old).hexdigest())
        self.assertEqual(result['inactive_candidate_sha256'], self.new_sha)
        self.assertNotIn('backup_sha256', result)
        self.assertFalse(result['updater_invoked'])

    def test_withdrawal_refuses_forward_consent(self):
        plan = self.prepare_withdrawal()
        with self.assertRaises(ValueError):
            self.run_withdrawal(plan, assurance=Assurance.SINGLE_WRITER_BACKUP_REPLACE)
        self.assertEqual(self.root.read_bytes(), self.new)
        self.assertEqual(self.backup.read_bytes(), self.old); self.assertFalse(self.candidate.exists())

    def test_withdrawal_default_is_read_only_rejection(self):
        plan = self.prepare_withdrawal()
        with self.assertRaises(ValueError):
            withdraw_with_backup(plan, self.evidence, expected_card_identity=self.identity,
                                 identity_reader=lambda: self.identity)
        self.assertEqual(self.root.read_bytes(), self.new); self.assertFalse(self.candidate.exists())

    def test_withdrawal_refuses_existing_inactive_path(self):
        plan = self.prepare_withdrawal(); self.candidate.write_bytes(b'foreign')
        with self.assertRaises(ValueError):
            self.run_withdrawal(plan)
        self.assertEqual(self.root.read_bytes(), self.new); self.assertEqual(self.backup.read_bytes(), self.old)
        self.assertEqual(self.candidate.read_bytes(), b'foreign')

    def test_withdrawal_tampered_original_backup_is_rejected(self):
        plan = self.prepare_withdrawal(); self.backup.write_bytes(b'x' * len(self.old))
        with self.assertRaises(ValueError):
            self.run_withdrawal(plan)
        self.assertEqual(self.root.read_bytes(), self.new); self.assertFalse(self.candidate.exists())

    def test_withdrawal_replace_failure_preserves_both_complete_generations(self):
        plan = self.prepare_withdrawal()
        def fail(*args, **kwargs):
            raise OSError('restore failed')
        with self.assertRaises(ReplacementError):
            self.run_withdrawal(plan, _operations=_IO(replace=fail))
        self.assertEqual(self.root.read_bytes(), self.new); self.assertEqual(self.backup.read_bytes(), self.old)
        self.assertEqual(self.candidate.read_bytes(), self.new); self.assert_stopped()

    def test_withdrawal_lost_rename_reply_does_not_reverse_restore(self):
        plan = self.prepare_withdrawal()
        def lost(*args, **kwargs):
            os.replace(*args, **kwargs)
            raise OSError('restore result lost')
        with self.assertRaises(ReplacementError):
            self.run_withdrawal(plan, _operations=_IO(replace=lost))
        self.assertEqual(self.root.read_bytes(), self.old); self.assertEqual(self.candidate.read_bytes(), self.new)
        self.assertFalse(self.backup.exists()); self.assert_stopped()

    def test_withdrawal_post_restore_fsync_failure_keeps_restored_root(self):
        plan = self.prepare_withdrawal()
        def fsync(fd):
            if not self.backup.exists():
                raise OSError('restore directory sync failed')
            os.fsync(fd)
        with self.assertRaises(ReplacementError):
            self.run_withdrawal(plan, _operations=_IO(fsync=fsync))
        self.assertEqual(self.root.read_bytes(), self.old); self.assertEqual(self.candidate.read_bytes(), self.new)
        self.assertFalse((self.evidence / 'completed.json').exists())

    def test_caller_identity_mutation_does_not_rewrite_receipt_metadata(self):
        snapshot = dict(self.identity)
        def identity():
            self.identity['volume_uuid'] = 'mutated-caller-object'
            return snapshot
        result = self.run_protocol(identity_reader=identity)
        self.assertEqual(result['card_identity'], snapshot)
        self.assertNotEqual(result['card_identity'], self.identity)

    def test_nocache_rejection_stops_before_backup(self):
        with mock.patch('tools.card_backup_replace.sys.platform', 'darwin'):
            with mock.patch('tools.card_backup_replace.fcntl.fcntl', side_effect=OSError('cache request rejected')):
                with self.assertRaises(OSError):
                    self.run_protocol()
        self.assert_original_preserved(); self.assertFalse(self.backup.exists())

    def test_replaced_evidence_directory_never_publishes_completion(self):
        moved = self.base / 'moved-evidence'
        def replace(*args, **kwargs):
            os.replace(*args, **kwargs)
            self.evidence.rename(moved); self.evidence.mkdir()
        with self.assertRaises(ReplacementError):
            self.run_protocol(_operations=_IO(replace=replace))
        self.assertEqual(self.root.read_bytes(), self.new); self.assertEqual(self.backup.read_bytes(), self.old)
        self.assertFalse((self.evidence / 'completed.json').exists())
        self.assertFalse((moved / 'completed.json').exists())


if __name__ == '__main__':
    unittest.main()
