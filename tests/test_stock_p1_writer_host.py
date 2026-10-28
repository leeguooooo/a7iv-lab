"""Synthetic host protocol tests. No camera, real writer or service exit is run."""
import hashlib
import json
from pathlib import Path
import shutil
import struct
import tempfile
import unittest
from unittest.mock import patch

from camera_stream_execution import LAUNCH, SLOT
from stock_p1_write_outcome import FRAME
import stock_p1_writer_host as host
from stock_p1_writer_plan import validate, ROOT


class Wire:
    def __init__(self, manifest, fault=None):
        self.m, self.fault, self.selected = manifest, fault, None
        self.calls, self.writes = [], []
        self.module = False
        self.commits = 0

    def record(self, phase, *, flags, before=None, after=None, calls=0, written=0, pid=234,
               error=0, rollback=0, io=0):
        m = self.m
        return FRAME.pack(b'M4P1WR01', bytes.fromhex(m['nonce']), 1, phase, error, 0, pid, 1, 123,
                          0, 1, len(m['windows']), calls, written, rollback, flags, io,
                          bytes.fromhex(before) if before else bytes(32),
                          bytes.fromhex(after) if after else bytes(32))

    def packet(self, channel, command, data, maximum, missing=False):
        self.calls.append((command, self.selected))
        if command == 15:
            path = data[1:-1].decode()
            self.selected = path.rsplit('/', 1)[-1]
            if self.fault == 'commit_select_unknown' and self.selected == 'commit':
                raise OSError('synthetic unknown SELECT')
            return b''
        if command == 16:
            raw = data[3:]
            name = self.selected
            if name in ('prepare', 'commit'):
                expected = (b'M4PREP01' if name == 'prepare' else b'M4COMMIT') + bytes.fromhex(self.m['nonce'])
                expected += bytes.fromhex(self.m['table_sha256']) + struct.pack('<Q', 1)
                assert raw == expected
                assert all(row['name'] in self.writes for row in self.m['windows'])
                assert 'table' in self.writes
            elif name != 'libJit.so':
                digest = (self.m['table_sha256'] if name == 'table' else
                          next(r['packet_sha256'] for r in self.m['windows'] if r['name'] == name))
                assert hashlib.sha256(raw).hexdigest() == digest
            self.writes.append(name)
            if name == 'libJit.so':
                self.module = True
                if self.fault == 'module_unknown':
                    raise OSError('synthetic unknown module upload')
            elif name == 'commit':
                self.commits += 1
                if self.fault == 'commit_unknown':
                    raise OSError('synthetic unknown COMMIT')
            elif self.fault == 'stage_unknown' and name == 'w0000':
                raise OSError('synthetic unknown stage write')
            return b''
        if command != 17:
            raise AssertionError(command)
        name = self.selected
        if name == 'test_loader':
            return b'loader'
        if name == 'libJit.so':
            return b'foreign' if self.fault == 'existing_module' else None
        if name == 'launch' and self.module:
            return LAUNCH.pack(b'M4BOOT01', bytes.fromhex(self.m['nonce']), 1, 3, 0, 0,
                               123, 0, 234, 234, 0, 100000000)
        if name == 'ready' and self.module:
            return self.record(2, flags=3)
        if name == 'prepared' and 'prepare' in self.writes:
            return self.record(3, flags=31, before=('3' * 64 if self.fault == 'prepared_mismatch'
                                                   else self.m['source_sha256']))
        if name == 'result' and self.commits:
            if self.fault == 'final_unknown':
                raise OSError('synthetic unknown result')
            if self.fault in ('native_rollback_ok', 'native_rollback_failed'):
                return self.record(90, flags=63, before=self.m['source_sha256'],
                    after=self.m['source_sha256'] if self.fault == 'native_rollback_ok' else '3' * 64,
                    written=self.m['stage_bytes'], calls=2 * len(self.m['windows']), error=-5,
                    rollback=1 if self.fault == 'native_rollback_ok' else 2)
            if self.fault == 'native_close_error':
                return self.record(90, flags=255, before=self.m['source_sha256'],
                    after=self.m['target_sha256'], written=self.m['stage_bytes'] // 2,
                    calls=len(self.m['windows']), error=-5, io=-5)
            return self.record(6, flags=255, before=self.m['source_sha256'],
                               after=self.m['target_sha256'], written=self.m['stage_bytes'] // 2,
                               calls=len(self.m['windows']) + 2,
                               pid=235 if self.fault == 'final_pid_mismatch' else 234)
        return None


class WriterHostTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest, cls.module = validate()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.folder = self.base / 'evidence';self.folder.mkdir()
        self.wire = Wire(self.manifest)
        self.readbacks = 0
        self.patches = [
            patch.object(host, 'GLOBAL_ATTEMPT', self.base / 'compiled-nonce-claim.json'),
            patch.object(host, 'READBACK_ATTEMPT', self.base / 'readback-nonce-claim.json'),
            patch.object(host, 'validate', return_value=(self.manifest, self.module)),
            patch.dict(host.LIBRARIES, {'/lib/test_loader': hashlib.sha256(b'loader').hexdigest()}, clear=True),
            patch.object(host.WriterChannel, '_packet', autospec=True, side_effect=self.wire.packet),
            patch.object(host, 'execute_after_writer_authenticated', side_effect=self.readback),
        ]
        for p in self.patches:
            p.start();self.addCleanup(p.stop)

    def readback(self, boundary, folder, *, source_is_hardware, **kwargs):
        self.readbacks += 1
        boundary.reserve_readback(bytes.fromhex(host.READBACK_NONCE))
        capture = folder / 'capture';capture.mkdir()
        source = self.wire.fault in ('conflicting_readback', 'native_rollback_ok', 'native_rollback_failed')
        original = self.manifest['source_image' if source else 'target_image']
        target = capture / 'cnflasha1.bin'
        shutil.copyfile(ROOT / original, target)
        digest = hashlib.sha256(target.read_bytes()).hexdigest()
        (capture / 'status.json').write_text(json.dumps({'state': 'TWO_READS_MATCHED', 'sha256': digest,
            'source_is_hardware': source_is_hardware,
            'nonce': 'ff' * 16 if self.wire.fault == 'other_readback_nonce' else host.READBACK_NONCE}))
        (folder / 'completed.json').write_text(json.dumps({'partition': 'cnflasha1', 'bytes': 25100288,
            'native': {'first_sha256': digest, 'second_sha256': digest}}))
        return target

    def execute(self, **kwargs):
        return host.execute_writer_authenticated(object(), self.folder, write_authorized=True,
            same_body_verified=True, source_is_hardware=False, sleep=lambda _: None, **kwargs)

    def test_known_success_stages_exactly_once_then_reconciles(self):
        outcome = self.execute()
        self.assertTrue(outcome['evidence_supports_session_end'])
        expected = ['libJit.so', 'table', *(r['name'] for r in self.manifest['windows']), 'prepare', 'commit']
        self.assertEqual(self.wire.writes, expected)
        self.assertEqual((self.wire.commits, self.readbacks), (1, 1))
        self.assertTrue((self.folder / 'commit-intent.json').exists())
        self.assertFalse((self.folder / 'stopped.json').exists())

    def test_no_consent_or_body_proof_touches_no_usb_or_claim(self):
        for flags in ({'write_authorized': False, 'same_body_verified': True},
                      {'write_authorized': True, 'same_body_verified': False}):
            with self.assertRaises(ValueError):
                host.execute_writer_authenticated(object(), self.folder, **flags)
        self.assertEqual(self.wire.calls, [])
        self.assertFalse(host.GLOBAL_ATTEMPT.exists())

    def test_fixed_nonce_cannot_replay_using_another_evidence_folder(self):
        self.execute()
        count = len(self.wire.calls)
        other = self.base / 'other';other.mkdir()
        with self.assertRaises(FileExistsError):
            host.execute_writer_authenticated(object(), other, write_authorized=True, same_body_verified=True)
        self.assertEqual(len(self.wire.calls), count)

    def test_previously_attempted_readback_blocks_writer_before_usb(self):
        host.READBACK_ATTEMPT.write_text('synthetic prior claim')
        with self.assertRaises(ValueError):
            self.execute()
        self.assertEqual(self.wire.calls, [])
        self.assertFalse(host.GLOBAL_ATTEMPT.exists())

    def test_unknown_or_invalid_results_never_launch_readback_or_retry_commit(self):
        for fault, commits in (('module_unknown', 0), ('stage_unknown', 0), ('prepared_mismatch', 0),
                               ('commit_select_unknown', 0), ('commit_unknown', 1),
                               ('final_unknown', 1), ('final_pid_mismatch', 1), ('native_close_error', 1),
                               ('existing_module', 0)):
            with self.subTest(fault=fault):
                self.wire.fault = fault
                with self.assertRaises((OSError, ValueError)):
                    self.execute()
                self.assertEqual((self.wire.commits, self.readbacks), (commits, 0))
                stopped = json.loads((self.folder / 'stopped.json').read_text())
                self.assertFalse(stopped['automatic_retry'])
                self.assertFalse(stopped['automatic_service_exit'])
                if fault in ('final_pid_mismatch', 'native_close_error'):
                    observation = json.loads((self.folder / 'result-observation-000.json').read_text())
                    self.assertEqual(len(bytes.fromhex(observation['raw_hex'])), FRAME.size)
                    self.assertEqual(stopped['stage'], 'NATIVE_FINAL_RECEIVED_UNVALIDATED')
                if fault == 'prepared_mismatch':
                    self.assertTrue((self.folder / 'prepared-observation-000.json').exists())
                # Only reset isolated synthetic claims; never a physical-job claim.
                host.GLOBAL_ATTEMPT.unlink()
                shutil.rmtree(self.folder);self.folder.mkdir()
                self.wire.calls.clear();self.wire.writes.clear()
                self.wire.commits = 0;self.wire.module = False

    def test_commit_intent_durability_failure_sends_no_commit(self):
        real = host.durable_new
        def durable(path, value):
            if Path(path).name == 'commit-intent.json':
                raise OSError('synthetic fsync failure')
            return real(path, value)
        with patch.object(host, 'durable_new', side_effect=durable):
            with self.assertRaises(OSError):
                self.execute()
        self.assertEqual((self.wire.commits, self.readbacks), (0, 0))

    def test_conflicting_readback_keeps_manual_review_required(self):
        self.wire.fault = 'conflicting_readback'
        with self.assertRaises(ValueError):
            self.execute()
        result = json.loads((self.folder / 'reconciled-outcome.json').read_text())
        self.assertEqual(result['state'], 'NATIVE_AND_INDEPENDENT_READ_CONTRADICT')
        self.assertFalse(result['evidence_supports_session_end'])

    def test_native_rollback_and_full_original_readback_does_not_claim_installed(self):
        self.wire.fault = 'native_rollback_ok'
        result = self.execute()
        self.assertEqual(result['state'], 'ORIGINAL_VERIFIED_AFTER_NATIVE_ROLLBACK')
        self.assertTrue(result['evidence_supports_session_end'])

    def test_failed_native_rollback_does_not_claim_recovery_from_one_good_readback(self):
        self.wire.fault = 'native_rollback_failed'
        with self.assertRaises(ValueError):
            self.execute()
        self.assertEqual(self.readbacks, 1)
        result = json.loads((self.folder / 'reconciled-outcome.json').read_text())
        self.assertFalse(result['evidence_supports_session_end'])

    def test_same_image_with_wrong_readback_job_nonce_is_rejected(self):
        self.wire.fault = 'other_readback_nonce'
        with self.assertRaises(ValueError):
            self.execute()
        self.assertFalse((self.folder / 'reconciled-outcome.json').exists())


if __name__ == '__main__':
    unittest.main()
