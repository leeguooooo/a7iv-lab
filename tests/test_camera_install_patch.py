"""Injected device fixtures and temporary local claims only; never USB."""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import Mock, patch

import camera_install_patch as adapter
import camera_install_volatile as contract
from camera_device_lease import CameraDeviceLease
from camera_install_journal import InstallJournal
from camera_stream_execution import LAUNCH, durable_new

ROOT = Path(__file__).resolve().parents[1]
MODEL_JOB = ROOT / 'output/install-volatile-production-offline-20261029-04'


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class Clock:
    def __init__(self):
        self.now = 0
    def __call__(self):
        return self.now
    def sleep(self, seconds):
        self.now += seconds


class SyntheticPatch:
    def __init__(self, nonce, publications):
        self.nonce = nonce
        self.publications = copy.deepcopy(publications)
        self.uploads = self.starts = 0
        self.reads = []
        self.healthy = True
        self.fault = None
    def read_loader(self, path):
        self.reads.append(path)
        return None if path == adapter.SLOT else b'synthetic-loader'
    def upload_once(self, module, expected, attempt):
        self.uploads += 1
        durable_new(attempt, {'synthetic': True, 'module_sha256': expected})
        if self.fault == 'upload_unknown':
            raise OSError('synthetic upload outcome unknown')
    def start_once(self, evidence):
        self.starts += 1
        durable_new(Path(evidence) / 'start-intent.json', {'synthetic': True})
        if self.fault == 'START_unknown':
            raise OSError('synthetic START outcome unknown')
    def read(self, name, missing=False):
        self.reads.append(name)
        if name == 'launch':
            return LAUNCH.pack(b'M4BOOT01', self.nonce, 1, 3, 0, 0, 123, 0, 234, 234, 0, 100000000)
        if name in ('ready', 'patched', 'result'):
            if name != 'ready' and not self.starts:
                return None
            if self.fault == name + '_unknown':
                raise OSError('synthetic publication outcome unknown')
            if self.fault == name + '_missing':
                return None
            raw = bytes.fromhex(self.publications[name])
            if self.fault == name + '_partial':
                return raw[:216]
            if self.fault == name + '_bad_magic':
                return b'BADMAGIC' + raw[8:]
            return raw
        return None


class ChannelTests(unittest.TestCase):
    def test_only_final_publication_names_and_new_once_START(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'output') as tmp:
            nonce = bytes(range(16))
            channel = adapter.InstallPatchChannel(Mock(), nonce)
            calls = []
            channel._packet = Mock(side_effect=lambda *args: calls.append(args) or b'')
            for name in ('result.pending', '../../anything', 'start'):
                with self.subTest(name=name), self.assertRaises(ValueError):
                    channel.read(name)
            self.assertEqual(calls, [])
            channel.start_once(tmp)
            self.assertEqual(calls[-1][1], b'\0\xff\0' + b'M4ISTART' + nonce + (2).to_bytes(8, 'little'))
            before = len(calls)
            with self.assertRaises(RuntimeError):
                channel.start_once(tmp)
            self.assertEqual(len(calls), before)

    def test_unknown_START_select_is_reserved_before_failure_and_not_replayed(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'output') as tmp:
            channel = adapter.InstallPatchChannel(Mock(), bytes(range(16)))
            channel._packet = Mock(side_effect=OSError('synthetic unknown select'))
            with self.assertRaises(OSError):
                channel.start_once(tmp)
            self.assertTrue((Path(tmp) / 'start-intent.json').is_file())
            with self.assertRaises(RuntimeError):
                channel.start_once(tmp)
            self.assertEqual(channel._packet.call_count, 1)


class AdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.native_manifest = json.loads((MODEL_JOB / 'manifest.json').read_text())
        cases = json.loads((MODEL_JOB / 'native-model-report.json').read_text())['cases']
        cls.native_publications = next(case['publication_hex'] for case in cases if case['case'] == 'success')

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=ROOT / 'output')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.evidence = self.root / 'evidence'
        self.evidence.mkdir()
        self.job = self.root / 'job'
        self.job.mkdir()
        for name in ('manifest.json', 'libJit.so', 'native-model-report.json', 'bootstrap-model-report.json'):
            shutil.copyfile(MODEL_JOB / name, self.job / name)
        self.assets = adapter.InstallPatchAssets(self.job, digest(self.job / 'manifest.json'),
            digest(self.job / 'libJit.so'), digest(self.job / 'native-model-report.json'),
            digest(self.job / 'bootstrap-model-report.json'))
        self.capture_root = self.root / 'captures'
        for name in adapter.CAPTURES:
            path = self.capture_root / name / 'bootstrap'
            path.mkdir(parents=True)
            (path / 'bootstrap.json').write_text(json.dumps({'synthetic_profile': name}))
        self.capture_assets = adapter.InstallCaptureAssets(self.capture_root,
            digest(self.capture_root / 'pre_app/bootstrap/bootstrap.json'),
            digest(self.capture_root / 'pre_ufp/bootstrap/bootstrap.json'))
        self.capture_nonces = {'pre_app': 'c' * 32, 'pre_ufp': 'd' * 32}
        self.capture_hashes = {'pre_app': 'e' * 64, 'pre_ufp': 'f' * 64}
        self.calls = []
        self.clock = Clock()
        self.channel = SyntheticPatch(bytes.fromhex(self.native_manifest['nonce']), self.native_publications)
        self.factory = Mock(return_value=self.channel)
        self.patchers = [patch.object(adapter, 'CLAIMS', self.root / 'patch-claims'),
            patch.object(adapter, 'CAPTURE_CLAIMS', self.root / 'capture-claims'),
            patch.object(adapter, 'DEFAULT_SESSIONS', self.root / 'global-sessions'),
            patch.object(adapter, 'checked_install_volatile', return_value={'offline_only': True}),
            patch.object(adapter, 'checked_capture_assets', side_effect=self.checked_capture),
            patch.dict(adapter.LIBRARIES, {'/lib/synthetic': hashlib.sha256(b'synthetic-loader').hexdigest()}, clear=True)]
        for item in self.patchers:
            item.start()
            self.addCleanup(item.stop)
        self.plan, self.body = 'a' * 64, 'b' * 64
        self.journal = InstallJournal.create(self.root / 'sessions', 'attempt',
            plan_sha256=self.plan, body_sha256=self.body, model='ILCE-7M4')
        self.journal.advance('SD_STAGE_INTENT')
        self.journal.advance('SD_STAGED')
        self.journal.advance(adapter.MAY_STATE)
        self.lease = self.enterContext(CameraDeviceLease('offline-install-patch-test',
                                                      lock_path=self.root / 'fixture.lock'))
        self.reservation = None

    def checked_capture(self, name, root):
        return dict(nonce=bytes.fromhex(self.capture_nonces[name]), module_sha256=self.capture_hashes[name])

    def capture(self, device, name, evidence, **options):
        self.calls.append(name)
        size, expected = adapter.CAPTURES[name]
        return dict(profile=name, bytes=size, sha256=expected, nonce=self.capture_nonces[name],
            module_sha256=self.capture_hashes[name], source_is_hardware=options['source_is_hardware'],
            native=dict(phase=6, flags=63, error=0, cleanup=0, offset=size,
                        first_sha256=expected, second_sha256=expected))

    def reserve(self):
        prepared = adapter.preflight_assets(self.assets, self.capture_assets)
        self.reservation = adapter.reserve_assets(prepared, self.evidence, lease=self.lease,
            journal=self.journal, expected_body_sha256=self.body, plan_sha256=self.plan)
        return prepared

    def invoke(self, **overrides):
        if self.reservation is None:
            self.reserve()
        options = dict(assets=self.assets, capture_assets=self.capture_assets, reservation=self.reservation,
            lease=self.lease, journal=self.journal, expected_body_sha256=self.body, plan_sha256=self.plan,
            volatile_patch_authorized=True, body_verified=True, source_is_hardware=True,
            capture_one=self.capture, channel_factory=self.factory, clock=self.clock, sleep=self.clock.sleep)
        options.update(overrides)
        return adapter.start_authenticated(object(), self.evidence, **options)

    def test_preflight_is_pure_and_reference_is_a_copy(self):
        prepared = adapter.preflight_assets(self.assets, self.capture_assets)
        first = prepared.reference
        first['patch']['nonce'] = '0' * 32
        self.assertEqual(prepared.reference['patch']['nonce'], self.native_manifest['nonce'])
        self.assertFalse((self.job / 'physical-attempt.json').exists())
        self.assertFalse(adapter.CLAIMS.exists())
        adapter.checked_install_volatile.assert_called_with(self.job, list(self.capture_nonces.values()))
        self.assertEqual(self.calls, [])

    def test_reserved_before_entry_and_actual_native_success_stays_unrestored(self):
        self.reserve()
        self.assertTrue((self.job / 'physical-attempt.json').exists())
        self.assertTrue(Path(self.reservation['global_claim']['path']).exists())
        self.assertFalse((self.job / 'host-entry-intent.json').exists())
        result = self.invoke()
        self.assertEqual(result['state'], 'VOLATILE_PATCH_APPLIED_NOT_RESTORED')
        self.assertEqual((self.channel.uploads, self.channel.starts), (1, 1))
        self.assertEqual(self.calls, ['pre_app', 'pre_ufp'])
        self.assertEqual(result['raw_publications'], {name: self.native_publications[name]
                         for name in ('ready', 'patched', 'result')})
        self.assertFalse(result['source_is_hardware'])
        for name in ('installation_authorized', 'firmware_installation_proven', 'RAM_restoration_proven',
                     'device_execution_proven', 'service_exit_completed', 'normal_body_reappearance_verified'):
            self.assertIs(result[name], False)
        self.assertEqual(json.loads((self.evidence / 'patch-receipt.json').read_text()), result)
        for name in ('ready', 'patched', 'result'):
            saved = json.loads((self.evidence / (name + '-received.json')).read_text())
            self.assertEqual(saved['raw_hex'], result['raw_publications'][name])
        self.assertNotIn('result.pending', self.channel.reads)

    def test_approval_or_body_verification_rejected_before_capture_or_channel(self):
        for options in (dict(volatile_patch_authorized=False), dict(body_verified=False)):
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.invoke(**options)
        self.assertEqual(self.calls, [])
        self.factory.assert_not_called()
        self.assertFalse((self.job / 'host-entry-intent.json').exists())

    def test_partial_injection_or_default_IO_without_hardware_context_is_rejected(self):
        self.reserve()
        for values in (dict(capture_one=None), dict(channel_factory=None),
                       dict(capture_one=None, channel_factory=None, source_is_hardware=False),
                       dict(capture_one=None, channel_factory=None, source_is_hardware=True)):
            with self.subTest(values=values), self.assertRaises(ValueError):
                self.invoke(**values)
        self.assertEqual(self.calls, [])
        self.factory.assert_not_called()
        self.assertFalse((self.job / 'host-entry-intent.json').exists())

    def test_default_IO_rejects_custom_journal_even_with_expected_lease_path(self):
        self.reserve()
        with patch.object(adapter, 'DEFAULT_LOCK', self.lease.path):
            with self.assertRaisesRegex(ValueError, 'canonical global session journal'):
                self.invoke(capture_one=None, channel_factory=None, source_is_hardware=True)
        self.assertEqual(self.calls, [])
        self.factory.assert_not_called()
        self.assertFalse((self.job / 'host-entry-intent.json').exists())

    def test_each_nonce_is_checked_in_both_global_claim_spaces(self):
        for claim_root in (adapter.CLAIMS, adapter.CAPTURE_CLAIMS):
            claim_root.mkdir(exist_ok=True)
            for nonce in (*self.capture_nonces.values(), self.native_manifest['nonce']):
                with self.subTest(root=claim_root, nonce=nonce):
                    claim = claim_root / (nonce + '.json')
                    claim.write_text('{}')
                    try:
                        with self.assertRaises(ValueError):
                            adapter.preflight_assets(self.assets, self.capture_assets)
                    finally:
                        claim.unlink()
        self.assertEqual(self.calls, [])
        self.factory.assert_not_called()

    def test_capture_per_job_attempt_marker_blocks_preflight(self):
        marker = self.capture_root / 'pre_ufp/bootstrap/physical-attempt.json'
        marker.write_text('{}')
        with self.assertRaisesRegex(ValueError, 'Capture job already attempted'):
            adapter.preflight_assets(self.assets, self.capture_assets)
        self.assertEqual(self.calls, [])
        self.factory.assert_not_called()

    def test_changed_reviewed_asset_rejected_before_entry(self):
        self.reserve()
        (self.job / 'libJit.so').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'Reviewed patch asset changed'):
            self.invoke()
        self.assertEqual(self.calls, [])
        self.factory.assert_not_called()
        self.assertFalse((self.job / 'host-entry-intent.json').exists())

    def test_consumed_capture_and_patch_nonce_rejected_before_authentication(self):
        adapter.CAPTURE_CLAIMS.mkdir()
        (adapter.CAPTURE_CLAIMS / (self.capture_nonces['pre_ufp'] + '.json')).write_text('{}')
        with self.assertRaisesRegex(ValueError, 'Capture nonce already consumed'):
            adapter.preflight_assets(self.assets, self.capture_assets)
        self.assertFalse(adapter.CLAIMS.exists())
        self.assertEqual(self.calls, [])

    def test_reused_reservation_cannot_capture_upload_or_START_again(self):
        self.invoke()
        before = list(self.calls), self.channel.uploads, self.channel.starts
        with self.assertRaisesRegex(ValueError, 'entry already attempted'):
            self.invoke()
        self.assertEqual((self.calls, self.channel.uploads, self.channel.starts), before)
        with self.assertRaisesRegex(ValueError, 'nonce already reserved'):
            adapter.preflight_assets(self.assets, self.capture_assets)

    def test_no_live_lease_wrong_binding_or_pending_global_session_permits_entry(self):
        self.reserve()
        for values in (dict(lease=None), dict(expected_body_sha256='9' * 64), dict(plan_sha256='9' * 64)):
            with self.subTest(values=values), self.assertRaises(ValueError):
                self.invoke(**values)
        InstallJournal.create(adapter.DEFAULT_SESSIONS, 'other', plan_sha256='1' * 64,
                              body_sha256='2' * 64, model='ILCE-7M4')
        with self.assertRaises(ValueError):
            self.invoke()
        self.assertEqual(self.calls, [])
        self.factory.assert_not_called()

    def test_open_descriptor_with_HELD_metadata_without_flock_is_rejected(self):
        self.reserve()
        fake = CameraDeviceLease('unlocked-fixture', lock_path=self.root / 'unlocked.lock')
        fake.metadata = dict(state='HELD', pid=os.getpid(), instance='synthetic-unlocked')
        fake.path.write_text(json.dumps(fake.metadata))
        fake.fd = os.open(fake.path, os.O_RDWR)
        try:
            with self.assertRaisesRegex(ValueError, 'Held caller lease lock required'):
                self.invoke(lease=fake)
        finally:
            os.close(fake.fd)
            fake.fd = None
        self.assertEqual(self.calls, [])
        self.factory.assert_not_called()

    def test_capture_error_or_mismatch_stops_before_other_capture_or_module(self):
        real = self.capture
        def bad(*args, **options):
            row = real(*args, **options)
            row['native']['second_sha256'] = '0' * 64
            return row
        with self.assertRaises(ValueError):
            self.invoke(capture_one=bad)
        self.assertEqual(self.calls, ['pre_app'])
        self.factory.assert_not_called()
        self.assertTrue((self.job / 'host-entry-intent.json').exists())
        self.assertFalse((self.evidence / 'patch-receipt.json').exists())

    def test_capture_unknown_stops_without_retry_or_module(self):
        attempted = []
        def unknown(device, name, evidence, **options):
            attempted.append(name)
            raise OSError('synthetic capture outcome unknown')
        with self.assertRaises(OSError):
            self.invoke(capture_one=unknown)
        self.assertEqual(attempted, ['pre_app'])
        self.factory.assert_not_called()
        self.assertFalse((self.evidence / 'patch-receipt.json').exists())

    def test_duplicate_capture_nonces_rejected_by_pure_preflight(self):
        self.capture_nonces['pre_ufp'] = self.capture_nonces['pre_app']
        with self.assertRaisesRegex(ValueError, 'nonce collision'):
            adapter.preflight_assets(self.assets, self.capture_assets)
        self.assertFalse(adapter.CLAIMS.exists())
        self.assertEqual(self.calls, [])

    def test_unknown_START_stops_without_later_record_read_or_retry(self):
        self.channel.fault = 'START_unknown'
        with self.assertRaises(OSError):
            self.invoke()
        self.assertEqual((self.channel.uploads, self.channel.starts), (1, 1))
        self.assertNotIn('patched', self.channel.reads)
        self.assertNotIn('result', self.channel.reads)
        self.assertFalse(self.channel.healthy)
        self.assertFalse((self.evidence / 'patch-receipt.json').exists())

    def test_invalid_ready_is_persisted_then_rejected_before_START(self):
        self.channel.fault = 'ready_bad_magic'
        with self.assertRaises(ValueError):
            self.invoke()
        raw = json.loads((self.evidence / 'ready-received.json').read_text())
        self.assertTrue(bytes.fromhex(raw['raw_hex']).startswith(b'BADMAGIC'))
        self.assertEqual(self.channel.starts, 0)
        self.assertFalse(self.channel.healthy)

    def test_partial_patched_is_kept_without_reobserve_or_waiting_result(self):
        self.channel.fault = 'patched_partial'
        with self.assertRaises(ValueError):
            self.invoke()
        raw = json.loads((self.evidence / 'patched-received.json').read_text())
        self.assertEqual(raw['bytes'], 216)
        self.assertEqual(self.channel.reads.count('patched'), 1)
        self.assertNotIn('result', self.channel.reads)
        self.assertFalse(self.channel.healthy)

    def test_unknown_or_partial_terminal_does_not_prove_applied_or_retry(self):
        self.channel.fault = 'result_unknown'
        with self.assertRaises(OSError):
            self.invoke()
        self.assertEqual(self.channel.reads.count('result'), 1)
        self.assertFalse(self.channel.healthy)
        self.assertFalse((self.evidence / 'patch-receipt.json').exists())

    def test_partial_terminal_is_persisted_and_never_reobserved(self):
        self.channel.fault = 'result_partial'
        with self.assertRaises(ValueError):
            self.invoke()
        saved = json.loads((self.evidence / 'result-received.json').read_text())
        self.assertEqual(saved['bytes'], 216)
        self.assertEqual(self.channel.reads.count('result'), 1)
        self.assertFalse(self.channel.healthy)
        self.assertFalse((self.evidence / 'patch-receipt.json').exists())

    def test_missing_atomic_terminal_times_out_without_reupload_or_reSTART(self):
        self.channel.fault = 'result_missing'
        with self.assertRaises(TimeoutError):
            self.invoke()
        self.assertEqual((self.channel.uploads, self.channel.starts), (1, 1))
        self.assertFalse(self.channel.healthy)
        self.assertFalse((self.evidence / 'patch-receipt.json').exists())


if __name__ == '__main__':
    unittest.main()
