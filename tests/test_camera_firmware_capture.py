import hashlib
import json
from dataclasses import replace
from pathlib import Path
import struct

import unittest
from unittest.mock import patch
from contextlib import ExitStack
import tempfile


class LocalPatch:
    def __init__(self):
        self.stack = ExitStack()

    def setattr(self, obj, key, value):
        self.stack.enter_context(patch.object(obj, key, value))

    def setitem(self, obj, key, value):
        self.stack.enter_context(patch.dict(obj, {key: value}))

    def close(self):
        self.stack.close()


def raises(error, match=None):
    case = unittest.TestCase()
    return case.assertRaisesRegex(error, match) if match else case.assertRaises(error)
import camera_firmware_capture as capture
import camera_stream_execution as execution
from camera_stream_receiver import ACK, RECORD
from camera_stream_collect import NATIVE


def record(nonce, phase, digest, size, *, pid=234):
    return NATIVE.pack(b'M4STR001', nonce, 1, phase, 0, 0, pid, 1, 123,
                       0, 1 if phase == 6 else -1, size if phase == 6 else 0,
                       1 if phase == 6 else 0, 63 if phase == 6 else 3, digest, digest)


def check_fixed_regular_source():
    from tools.build_firmware_file_capture_offline import derived_source
    source = derived_source()
    assert '0100000' in source and 'PART_SIZE' in source
    assert 'BLKGETSIZE64' not in source and '/sys/class/block' not in source
    assert source.count('sr.error=verify_identity();if(sr.error)goto done;') == 2
    assert 'A64_READ|0x20000' in source
    with raises(ValueError):
        capture.profile('/usr/lib/appFw.so')


def check_native_identity_stops_before_next_request(monkeypatch):
    nonce = b'N' * 16
    raws = [record(nonce, 1, b'0' * 32, 0), record(nonce, 6, b'0' * 32, 22768, pid=999)]
    monkeypatch.setattr(execution.BootstrapChannel, 'read', lambda *a: raws.pop(0))
    channel = capture.FileChannel(object(), nonce, capture.profile('pre_ufp'))
    channel.read('ready')
    with raises(ValueError, match='differs'):
        channel.read('result')
    assert channel.healthy is False


def check_complete_synthetic_capture_and_nonce_claim(tmp_path, monkeypatch, failure):
    """Real collector, disk readback and orchestration; no device or USB calls."""
    import tools.build_firmware_file_capture_offline as builder
    import tools.firmware_file_capture_assets as emulator
    import tools.firmware_file_capture_bootstrap as bootstrap
    payload = bytes(range(256)) * 88 + bytes(range(240))
    assert len(payload) == 22768
    digest = hashlib.sha256(payload).digest()
    p = replace(capture.profile('pre_ufp'), sha256=('0' * 64 if failure == 'wrong_hash' else digest.hex()))
    monkeypatch.setitem(capture.JOBS, p.name, p)
    monkeypatch.setattr(capture, 'CLAIMS', tmp_path / 'claims')
    nonce = b'N' * 16
    root = tmp_path / 'assets'
    prod = root / p.name / 'prod'
    boot = root / p.name / 'bootstrap'
    prod.mkdir(parents=True); boot.mkdir()
    (prod / 'firmware_file_capture.c').write_text(builder.derived_source())
    (prod / 'target.h').write_text(builder.target_header(p))
    (prod / 'worker.debug.elf').write_bytes(b'worker')
    meta = {'schema': 'camera-firmware-file-offline-worker/1', 'nonce': nonce.hex(),
            'target': list(p.target), 'test_image': False, 'chunk_bytes': 8388608,
            'sources': {}, 'profile': p.name, 'shared_sources': {}, 'worker_sha256': hashlib.sha256(b'worker').hexdigest()}
    (prod / 'job.json').write_text(json.dumps(meta))
    (prod / 'job.h').write_bytes(b'header')
    (boot / 'job.h').write_bytes(b'header')
    (prod / 'emulation.json').write_bytes(b'report')
    tiny = root / p.name / 'tiny'
    tiny.mkdir()
    (tiny / 'job.json').write_bytes(b'tiny')
    (tiny / 'emulation.json').write_bytes(b'report')
    (boot / 'worker.elf').write_bytes(b'module')
    manifest = {'schema': 'camera-firmware-file-bootstrap-offline/1',
                'nonce': nonce.hex(), 'target': list(p.target),
                'production_debug_worker_sha256': meta['worker_sha256'],
                'bootstrap_source_sha256': bootstrap.BOOTSTRAP_SHA,
                'linux_helpers_sha256': bootstrap.LINUX_HELPERS_SHA,
                'builder_sha256': hashlib.sha256(Path(bootstrap.__file__).read_bytes()).hexdigest(),
                'production_emulation_sha256': hashlib.sha256(b'report').hexdigest(),
                'tiny_emulation_sha256': hashlib.sha256(b'report').hexdigest(),
                'tiny_job_manifest_sha256': hashlib.sha256(b'tiny').hexdigest(),
                'compact_worker_sha256': hashlib.sha256(b'module').hexdigest(),
                'production_job_manifest_sha256': hashlib.sha256((prod / 'job.json').read_bytes()).hexdigest(),
                'module': {'sha256': hashlib.sha256(b'module').hexdigest()}}
    (boot / 'bootstrap.json').write_text(json.dumps(manifest))
    (boot / 'libJit.so').write_bytes(b'module')
    monkeypatch.setattr(emulator, 'checked_job', lambda x: (dict(meta, test_image=True) if x.name == 'tiny' else meta, {}))
    monkeypatch.setattr(emulator, 'checked_manifest', lambda x: meta)
    monkeypatch.setattr(execution, 'LIBRARIES', {'/loader': hashlib.sha256(b'loader').hexdigest()})
    trace = []

    class SyntheticChannel:
        def __init__(self, device, got_nonce, selected, clock):
            assert got_nonce == nonce
            self.nonce, self.profile, self.acked, self.uploaded = nonce, selected, False, False
            self.healthy = True

        def touch(self, name):
            assert (capture.CLAIMS / (nonce.hex() + '.json')).is_file()
            trace.append(name)

        def read_loader(self, name):
            self.touch(name)
            return b'loader' if name == '/loader' else None

        def upload_once(self, *args):
            self.touch('module'); self.uploaded = True

        def read(self, name, missing=False):
            self.touch(name)
            if name == 'launch':
                return execution.LAUNCH.pack(b'M4BOOT01', nonce, 1, 3, 0, 0, 123, 0, 1, 1, 0, 0)
            if name == 'ready':
                return record(nonce, 1, digest, p.size)
            if name == 'chunk.ready':
                return RECORD.pack(b'M4CHNK01', nonce, 0, 0, p.size, digest)
            if name == 'chunk.bin':
                if failure == 'unknown_read':
                    raise OSError('Synthetic unknown transport result')
                return payload
            if name == 'done':
                assert self.acked
                return RECORD.pack(b'M4DONE01', nonce, 1, p.size, 0, digest)
            if name == 'result':
                return record(nonce, 6, digest, p.size)
            return None

        def write_control(self, name, value):
            self.touch(name)
            if name == 'ack':
                assert value == ACK.pack(b'M4SACK01', nonce, 0, digest)
                self.acked = True

    monkeypatch.setattr(capture, 'FileChannel', SyntheticChannel)
    if failure:
        with raises((OSError, ValueError)):
            capture.capture_one_authenticated(object(), p.name, tmp_path / 'evidence', assets=root)
        assert trace[-1] == ('done' if failure == 'wrong_hash' else 'chunk.bin')
        assert not (tmp_path / 'evidence/firmware-capture.json').exists()
        return
    result = capture.capture_one_authenticated(object(), p.name, tmp_path / 'evidence', assets=root)
    assert Path(result['capture']).read_bytes() == payload
    assert result['sha256'] == p.sha256 and result['source_is_hardware'] is False
    count = len(trace)
    with raises(FileExistsError):
        capture.capture_one_authenticated(object(), p.name, tmp_path / 'other', assets=root)
    assert len(trace) == count


class FirmwareCaptureTests(unittest.TestCase):
    def run_local(self, check, *args):
        with tempfile.TemporaryDirectory() as directory:
            local_patch = LocalPatch()
            try:
                check(Path(directory), local_patch, *args)
            finally:
                local_patch.close()

    def test_fixed_regular_source(self):
        check_fixed_regular_source()

    def test_only_fixed_post_p1_is_block_with_no_expected_whole_hash(self):
        from tools.build_firmware_file_capture_offline import derived_source, target_header
        p = capture.profile('post_p1')
        self.assertEqual((p.path, p.size, p.minor, p.source_kind, p.sha256),
                         ('/dev/cnflasha1', 25100288, 129, 'BLOCK', None))
        self.assertEqual([j.name for j in capture.JOBS.values() if j.sha256 is None], ['post_p1'])
        self.assertIn('BLKGETSIZE64', derived_source('post_p1'))
        self.assertIn('252:129', target_header(p))
        for name in ('pre_app', 'pre_ufp', 'post_app', 'post_cp'):
            self.assertNotIn('BLKGETSIZE64', derived_source(name))
        with self.assertRaises(ValueError):
            capture.profile('/dev/cnflasha1')

    def test_post_p1_accepts_two_read_capture_without_whole_partition_expected_hash(self):
        from types import SimpleNamespace
        p = capture.profile('post_p1')
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            (folder / 'status.json').write_text(json.dumps({'sha256': '7' * 64}))
            final = folder / 'post_p1.bin'
            channel = SimpleNamespace(profile=p, healthy=True)
            with patch.object(capture, '_collect_profile', return_value=final) as collector:
                self.assertEqual(capture.collect_file(channel, folder), final)
                self.assertEqual(collector.call_args.args[2], p.target)
            self.assertTrue(channel.healthy)

    def test_native_identity(self):
        local_patch = LocalPatch()
        try:
            check_native_identity_stops_before_next_request(local_patch)
        finally:
            local_patch.close()

    def test_complete_synthetic_capture(self):
        self.run_local(check_complete_synthetic_capture_and_nonce_claim, None)

    def test_wrong_expected_hash(self):
        self.run_local(check_complete_synthetic_capture_and_nonce_claim, 'wrong_hash')

    def test_unknown_transport_stops(self):
        self.run_local(check_complete_synthetic_capture_and_nonce_claim, 'unknown_read')


if __name__ == '__main__':
    unittest.main()
