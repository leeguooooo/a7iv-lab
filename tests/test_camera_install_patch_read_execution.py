import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import camera_install_patch_read as contract
import camera_install_patch_read_execution as execute
from camera_stream_execution import LAUNCH, durable_new
import test_camera_install_patch_session as original_session
import test_camera_install_patch_read as frames

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class Clock:
    def __init__(self):self.now = 0
    def __call__(self):return self.now
    def sleep(self, value):self.now += value


class SyntheticReader:
    def __init__(self, nonce, spec):
        self.nonce, self.spec = nonce, spec
        self.ready, self.result = frames.rows(spec)
        self.uploads = self.starts = 0
        self.reads = []
        self.healthy = True
        self.fault = None
    def read_loader(self, path):
        self.reads.append(path)
        return None if path == execute.SLOT else b'loader-fixture'
    def upload_once(self, module, digest, evidence):
        self.uploads += 1
        durable_new(evidence, dict(synthetic=True))
        if self.fault == 'upload_unknown':raise OSError('synthetic upload unknown')
    def start_once(self, evidence):
        self.starts += 1
        durable_new(Path(evidence) / 'start-intent.json', dict(synthetic=True))
        if self.fault == 'START_unknown':raise OSError('synthetic START unknown')
    def read(self, name, missing=False):
        self.reads.append(name)
        if name == 'launch':return LAUNCH.pack(b'M4BOOT01', self.nonce, 1, 3, 0, 0, 678, 0, 777, 777, 0, 100000000)
        if name == 'exec_failure':return None
        if name == 'result' and not self.starts and self.fault != 'early_result':return None
        if self.fault == name + '_unknown':raise OSError('synthetic publication unknown')
        if self.fault == name + '_missing':return None
        row = self.ready if name == 'ready' or self.fault == 'duplicate_result' else self.result
        raw = frames.pack(row, self.spec, self.nonce)
        if self.fault == name + '_partial':return raw[:212]
        if self.fault == name + '_oversized':return raw + b'x'
        if self.fault == name + '_bad_magic':return b'WRONGMAG' + raw[8:]
        return raw


class ExecutionTests(unittest.TestCase):
    def setUp(self):
        self.prior = original_session.InstallPatchSessionTests()
        self.prior.setUp()
        self.addCleanup(self.prior.doCleanups)
        self.prior.invoke()
        self.journal, self.lease = self.prior.journal, self.prior.lease
        pending = self.prior.evidence / 'install-patch-awaiting-reconnect.json'
        self.pending_ref = dict(path=str(pending), sha256=sha(pending))
        self.spec = contract.derive_target_spec(pending.read_bytes(), body_sha256=self.prior.body, plan_sha256=self.prior.plan)
        self.temporary = tempfile.TemporaryDirectory(dir=ROOT / 'output')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.evidence = self.root / 'evidence';self.evidence.mkdir()
        self.job = self.root / 'job';self.job.mkdir()
        self.nonce = b'r' * 16
        self.manifest = dict(nonce=self.nonce.hex(), job_dir='/tmp_wbshd/m4ipr_' + self.nonce.hex(),
            target_spec_sha256=contract.spec_sha256(self.spec), original_patch_nonce=self.spec['original_patch_nonce'],
            original_pending=dict(sha256=self.pending_ref['sha256']))
        (self.job / 'manifest.json').write_text(json.dumps(self.manifest))
        (self.job / 'target-spec.json').write_text(json.dumps(self.spec))
        (self.job / 'libJit.so').write_bytes(b'fixed-module-fixture')
        for name in ('native-model-report.json', 'bootstrap-model-report.json'):
            (self.job / name).write_text('{}')
        self.assets = execute.InstallPatchReadAssets(self.job, sha(self.job / 'manifest.json'), sha(self.job / 'libJit.so'),
            sha(self.job / 'native-model-report.json'), sha(self.job / 'bootstrap-model-report.json'), contract.spec_sha256(self.spec))
        self.channel = SyntheticReader(self.nonce, self.spec)
        self.factory = Mock(return_value=self.channel)
        self.clock = Clock()
        self.patchers = [patch.object(execute, 'checked_install_patch_read', return_value={'offline_only': True}),
            patch.object(execute, 'CLAIMS', self.root / 'read-claims'),
            patch.object(execute, 'CAPTURE_CLAIMS', self.root / 'capture-claims'),
            patch.object(execute, 'PATCH_CLAIMS', self.root / 'patch-claims'),
            patch.object(execute, 'DEFAULT_SESSIONS', self.root / 'global-sessions'),
            patch.dict(execute.LIBRARIES, {'/lib/fixture': hashlib.sha256(b'loader-fixture').hexdigest()}, clear=True)]
        for item in self.patchers:item.start();self.addCleanup(item.stop)
        self.reservation = None

    def preflight(self):
        return execute.preflight_assets(self.assets, pending_reference=self.pending_ref,
            expected_body_sha256=self.prior.body, plan_sha256=self.prior.plan)

    def reserve(self):
        prepared = self.preflight()
        self.reservation = execute.reserve_assets(prepared, self.evidence, lease=self.lease, journal=self.journal)
        return prepared

    def invoke(self, **changes):
        if self.reservation is None:self.reserve()
        values = dict(assets=self.assets, reservation=self.reservation, pending_reference=self.pending_ref,
            lease=self.lease, journal=self.journal, expected_body_sha256=self.prior.body, plan_sha256=self.prior.plan,
            read_authorized=True, body_verified=True, source_is_hardware=True, channel_factory=self.factory,
            clock=self.clock, sleep=self.clock.sleep)
        values.update(changes)
        return execute.start_authenticated(object(), self.evidence, **values)

    def no_io(self):
        self.factory.assert_not_called()
        self.assertEqual((self.channel.uploads, self.channel.starts, self.channel.reads), (0, 0, []))

    def test_success_persists_full_raw_then_returns_observation_without_admission(self):
        before = self.journal.events
        self.reserve()
        self.assertTrue((self.job / 'physical-attempt.json').exists())
        self.assertFalse((self.job / 'host-entry-intent.json').exists())
        result = self.invoke()
        self.assertEqual(result['state'], 'CURRENT_OBSERVATION_ONLY')
        self.assertEqual(result['observation'], 'ORIGINAL')
        self.assertEqual((self.channel.uploads, self.channel.starts), (1, 1))
        for name in ('source_is_hardware', 'original_hardware_origin_proven', 'original_mm_continuity_proven',
                     'RAM_restoration_proven', 'cancellation_authorized', 'installation_authorized', 'journal_cleared',
                     'service_exit_completed'):
            self.assertIs(result[name], False)
        self.assertEqual(self.journal.events, before)
        self.assertEqual(json.loads((self.evidence / 'current-read-receipt.json').read_text()), result)
        for name in ('ready', 'result'):
            raw = json.loads((self.evidence / (name + '-received.json')).read_text())
            self.assertEqual(raw['raw_hex'], result['raw_publications'][name])
        self.assertNotIn('result.pending', self.channel.reads)

    def test_false_approval_body_wrong_pending_or_changed_assets_precede_all_IO(self):
        self.reserve()
        for values in (dict(read_authorized=False), dict(body_verified=False), dict(expected_body_sha256='0' * 64),
                       dict(pending_reference=self.pending_ref | {'sha256': '0' * 64})):
            with self.subTest(values=values), self.assertRaises(ValueError):self.invoke(**values)
        (self.job / 'libJit.so').write_bytes(b'tampered')
        with self.assertRaises(ValueError):self.invoke()
        self.no_io()
        self.assertFalse((self.job / 'host-entry-intent.json').exists())

    def test_default_nonhardware_and_invalid_injection_do_not_fall_back_to_real_IO(self):
        self.reserve()
        for values in (dict(channel_factory=None, source_is_hardware=False),
                       dict(channel_factory=None, source_is_hardware=True), dict(channel_factory=False), dict(channel_factory=object())):
            with self.subTest(values=values), self.assertRaises(ValueError):self.invoke(**values)
        self.no_io()

    def test_modeled_prior_cannot_enter_default_route_even_with_canonical_context(self):
        self.reserve()
        with patch.object(execute, 'DEFAULT_LOCK', self.lease.path), patch.object(execute, 'DEFAULT_SESSIONS', self.journal.session_dir.parent):
            with patch.object(execute, 'ReadChannel') as real:
                with self.assertRaisesRegex(ValueError, 'Modeled or non-hardware'):
                    self.invoke(channel_factory=None, source_is_hardware=True)
                real.assert_not_called()
        self.no_io()
        self.assertFalse((self.job / 'host-entry-intent.json').exists())

    def test_module_swap_between_review_hash_and_acquisition_is_local_rejection(self):
        original = execute.checked_install_patch_read
        def swapped(job):
            (self.job / 'libJit.so').write_bytes(b'changed-after-hash')
            return original(job)
        with patch.object(execute, 'checked_install_patch_read', side_effect=swapped):
            with self.assertRaisesRegex(ValueError, 'Acquired read module changed'):self.preflight()
        self.no_io()
        self.assertFalse(execute.CLAIMS.exists())

    def test_nonce_claims_cross_namespace_and_attempt_markers_prevent_preflight(self):
        for root in (execute.CLAIMS, execute.CAPTURE_CLAIMS, execute.PATCH_CLAIMS):
            root.mkdir(exist_ok=True)
            claim = root / (self.nonce.hex() + '.json');claim.write_text('{}')
            with self.subTest(root=root), self.assertRaises(ValueError):self.preflight()
            claim.unlink()
        for name in ('claim.json', 'host-entry-intent.json', 'module-attempt.json'):
            path = self.job / name;path.write_text('{}')
            with self.subTest(name=name), self.assertRaises(ValueError):self.preflight()
            path.unlink()
        self.no_io()

    def test_reuse_rejected_without_more_transport_or_journal_mutation(self):
        self.invoke()
        count = (self.channel.uploads, self.channel.starts, len(self.channel.reads))
        with self.assertRaises(ValueError):self.invoke()
        self.assertEqual((self.channel.uploads, self.channel.starts, len(self.channel.reads)), count)

    def test_invalid_READY_raw_is_durable_before_rejection_without_START(self):
        self.channel.fault = 'ready_bad_magic'
        with self.assertRaises(ValueError):self.invoke()
        saved = json.loads((self.evidence / 'ready-received.json').read_text())
        self.assertTrue(bytes.fromhex(saved['raw_hex']).startswith(b'WRONGMAG'))
        self.assertEqual(self.channel.starts, 0)
        self.assertFalse(self.channel.healthy)

    def test_early_final_refuses_START_and_retains_raw(self):
        self.channel.fault = 'early_result'
        with self.assertRaisesRegex(ValueError, 'already ended'):self.invoke()
        self.assertTrue((self.evidence / 'before-start-result-received.json').exists())
        self.assertEqual(self.channel.starts, 0)
        self.assertFalse(self.channel.healthy)

    def test_unknown_upload_is_terminal_without_record_reads_or_cleanup(self):
        self.channel.fault = 'upload_unknown'
        with self.assertRaises(OSError):self.invoke()
        self.assertEqual((self.channel.uploads, self.channel.starts), (1, 0))
        self.assertNotIn('launch', self.channel.reads)
        self.assertFalse(self.channel.healthy)

    def test_unknown_START_sends_no_later_record_request(self):
        self.channel.fault = 'START_unknown'
        with self.assertRaises(OSError):self.invoke()
        self.assertEqual((self.channel.uploads, self.channel.starts), (1, 1))
        self.assertEqual(self.channel.reads.count('result'), 1)  # Only the pre-START missing check.
        self.assertFalse(self.channel.healthy)

    def test_partial_terminal_never_returns_success(self):
        self.channel.fault = 'result_partial'
        with self.assertRaises(ValueError):self.invoke()
        self.assertEqual(json.loads((self.evidence / 'result-received.json').read_text())['bytes'], 212)
        self.assertEqual(self.channel.reads.count('result'), 2)
        self.assertFalse(self.channel.healthy)
        self.assertFalse((self.evidence / 'current-read-receipt.json').exists())

    def test_oversized_terminal_is_saved_before_rejection_without_retry(self):
        self.channel.fault = 'result_oversized'
        with self.assertRaises(ValueError):self.invoke()
        self.assertEqual(json.loads((self.evidence / 'result-received.json').read_text())['bytes'], 425)
        self.assertEqual(self.channel.reads.count('result'), 2)
        self.assertFalse(self.channel.healthy)
        self.assertFalse((self.evidence / 'current-read-receipt.json').exists())

    def test_duplicate_READY_as_terminal_is_not_a_completed_observation(self):
        self.channel.fault = 'duplicate_result'
        with self.assertRaises(ValueError):self.invoke()
        saved = json.loads((self.evidence / 'result-received.json').read_text())
        row = contract.decode_record(bytes.fromhex(saved['raw_hex']), self.nonce, self.spec)
        self.assertEqual(row['phase'], 1)
        self.assertEqual(self.channel.reads.count('result'), 2)
        self.assertFalse(self.channel.healthy)
        self.assertFalse((self.evidence / 'current-read-receipt.json').exists())

    def test_reacquired_lease_after_first_loader_read_stops_before_next_request(self):
        self.reserve()
        original = self.channel.read_loader
        def changed(path):
            value = original(path)
            self.lease.__exit__(None, None, None)
            self.lease.__enter__()
            return value
        self.channel.read_loader = changed
        with self.assertRaisesRegex(ValueError, 'lease identity changed'):
            self.invoke()
        self.assertEqual(self.channel.reads, ['/lib/fixture'])
        self.assertEqual((self.channel.uploads, self.channel.starts), (0, 0))
        self.assertFalse(self.channel.healthy)

    def test_reacquired_lease_during_ready_prevents_START_or_any_later_request(self):
        self.reserve()
        original = self.channel.read
        def changed(name, missing=False):
            value = original(name, missing)
            if name == 'ready':
                self.lease.__exit__(None, None, None)
                self.lease.__enter__()
            return value
        self.channel.read = changed
        with self.assertRaisesRegex(ValueError, 'lease identity changed'):
            self.invoke()
        self.assertEqual(self.channel.reads[-1], 'ready')
        self.assertEqual(self.channel.starts, 0)
        self.assertTrue((self.evidence / 'ready-received.json').exists())
        self.assertFalse(self.channel.healthy)

    def test_reacquired_lease_during_result_keeps_raw_without_success(self):
        self.reserve()
        original = self.channel.read
        def changed(name, missing=False):
            value = original(name, missing)
            if name == 'result' and self.channel.starts:
                self.lease.__exit__(None, None, None)
                self.lease.__enter__()
            return value
        self.channel.read = changed
        with self.assertRaisesRegex(ValueError, 'lease identity changed'):
            self.invoke()
        self.assertEqual(self.channel.reads[-1], 'result')
        self.assertEqual((self.channel.uploads, self.channel.starts), (1, 1))
        self.assertTrue((self.evidence / 'result-received.json').exists())
        self.assertFalse((self.evidence / 'current-read-receipt.json').exists())
        self.assertFalse(self.channel.healthy)

    def test_timeout_does_not_reupload_restart_or_clear_pending(self):
        before = self.journal.events
        self.channel.fault = 'result_missing'
        with self.assertRaises(TimeoutError):self.invoke()
        self.assertEqual((self.channel.uploads, self.channel.starts), (1, 1))
        self.assertEqual(self.journal.events, before)
        self.assertFalse(self.channel.healthy)
        self.assertFalse((self.evidence / 'current-read-receipt.json').exists())

    def test_terminal_persistence_failure_prevents_success(self):
        original = execute.durable_new
        def failed(path, value):
            if Path(path).name == 'current-read-receipt.json':raise OSError('synthetic receipt fsync failure')
            return original(path, value)
        with patch.object(execute, 'durable_new', side_effect=failed):
            with self.assertRaises(OSError):self.invoke()
        self.assertFalse(self.channel.healthy)
        self.assertEqual((self.channel.uploads, self.channel.starts), (1, 1))


class ReadChannelTests(unittest.TestCase):
    def test_only_fixed_publications_and_exact_once_START(self):
        spec = frames.spec_fixture();nonce = b'r' * 16
        with tempfile.TemporaryDirectory(dir=ROOT / 'output') as tmp:
            channel = execute.ReadChannel(Mock(), nonce, spec)
            channel._packet = Mock(return_value=b'')
            for name in ('start', 'result.pending', '../../secret'):
                with self.subTest(name=name), self.assertRaises(ValueError):channel.read(name)
            channel._packet.assert_not_called()
            channel.start_once(tmp)
            self.assertEqual(channel._packet.call_args.args[1], b'\0\xff\0' +
                contract.START_FRAME.pack(contract.START_MAGIC, nonce, bytes.fromhex(spec['original_patch_nonce']), 1))
            count = channel._packet.call_count
            with self.assertRaises(ValueError):channel.start_once(tmp)
            self.assertEqual(channel._packet.call_count, count)


if __name__ == '__main__':unittest.main()
