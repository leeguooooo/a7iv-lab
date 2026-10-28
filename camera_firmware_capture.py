"""Four fixed regular files and post-install P1 on an authenticated device.

Caller must hold CameraDeviceLease and own authentication/USB exit policy.
No discovery, authentication, service switching or device CLI. Identity checks
are bounded observations, not a lock: privileged concurrent mutation and a
change reverted between observations cannot be excluded. The fixed P1 BLOCK
profile reuses pilot block identity/geometry checks, without a whole-image
expected hash; P1 filesystem and DAT semantic acceptance belongs to the caller.
"""
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import time
from camera_stream_collect import _collect_profile, native_status
from camera_stream_execution import BootstrapChannel, _execute_profile, durable_new
from camera_stream_receiver import StreamReceiver

ROOT = Path(__file__).resolve().parent
ASSETS = ROOT / 'output/firmware-file-capture-offline-03'
CLAIMS = ROOT / 'output/firmware-file-capture-nonce-claims'

@dataclass(frozen=True)
class FileProfile:
    name: str
    path: str
    size: int
    sha256: str | None
    tiny_size: int = 9728
    source_kind: str = "REGULAR"
    minor: int = 0

    @property
    def target(self):
        return (self.name, self.minor, self.size)

    @property
    def chunks(self):
        return (self.size + 8388607) // 8388608

JOBS = {p.name: p for p in (
    FileProfile("post_p1", "/dev/cnflasha1", 25100288, None, source_kind="BLOCK", minor=129),
    FileProfile('pre_app', '/usr/lib/appFw.so', 98212632, '1e1b9202eaa69198f20df03dbfdab2f103b206cc4ebcd2e7bd817e6a710018a2'),
    FileProfile('pre_ufp', '/usr/lib/libupdaterufp.so', 22768, 'f2e7d27602e3f7b236fc41dd93fccf53ba24f0793fd454e7fec171ae378beca7'),
    FileProfile('post_app', '/usr/lib/appFw.so', 98212632, 'd17e61fb4ba193d8e7d802196edff5f578d5691b3fcc4abcd1cbbb6e58bdd8ff'),
    FileProfile('post_cp', '/cp/cpapp-b.bin', 16236816, '4551c73386c27a0a9b247fd3e05c3bd5e3425bdb9fe9f8374c201c96533b3479'),
)}

def profile(name):
    if not isinstance(name, str) or name not in JOBS:
        raise ValueError('Fixed firmware file job required')
    return JOBS[name]

class FileReceiver(StreamReceiver):
    ALLOWED_TARGETS = tuple(p.target for p in JOBS.values())

class FileChannel(BootstrapChannel):
    def __init__(self, device, nonce, selected, clock=time.monotonic):
        super().__init__(device, nonce, clock)
        self.profile = selected
        self.ACK_CHUNKS = selected.chunks
        self.ready_identity = None

    def read(self, name, missing=False):
        raw = super().read(name, missing)
        if raw is not None and name in ('ready', 'result') and len(raw) == 184:
            try:
                status = native_status(raw, self.nonce)
                identity = tuple(status[k] for k in ('pid', 'ppid', 'euid', 'loader_pid'))
                if status['pid'] <= 1 or status['loader_pid'] <= 1 or identity[1:3] != (1, 0):
                    raise ValueError('Invalid native process identity')
                if name == 'ready':
                    if self.ready_identity is not None and identity != self.ready_identity:
                        raise ValueError('Readiness process identity changed')
                    self.ready_identity = identity
                elif self.ready_identity is None or identity != self.ready_identity:
                    raise ValueError('Final process differs from ready worker')
            except BaseException:
                self.healthy = False
                raise
        return raw

def collect_file(channel, directory, **kwargs):
    selected = profile(channel.profile.name)
    if selected != channel.profile:
        raise ValueError('File profile changed')
    captured = _collect_profile(channel, directory, selected.target, FileReceiver, **kwargs)
    status = json.loads((Path(directory) / 'status.json').read_text())
    if selected.sha256 is not None and status['sha256'] != selected.sha256:
        channel.healthy = False
        raise ValueError('Captured firmware differs from fixed expected SHA256')
    return captured

def checked_capture_assets(name, assets=ASSETS):
    """Validate all prepared local evidence without opening a device or claiming a nonce."""
    selected = profile(name)
    from tools.build_firmware_file_capture_offline import derived_source, target_header
    folder = Path(assets).resolve() / name
    prod = folder / 'prod'
    boot = folder / 'bootstrap'
    from tools.firmware_file_capture_assets import checked_manifest, checked_job, BOOTSTRAP_SHA, LINUX_HELPERS_SHA
    from camera_inventory import NATIVE
    meta, _ = checked_job(prod)
    tiny, _ = checked_job(folder / 'tiny')
    checked_manifest(prod)
    if (hashlib.sha256((NATIVE / 'bootstrap.c').read_bytes()).hexdigest() != BOOTSTRAP_SHA
            or hashlib.sha256((NATIVE / 'linux_a64.h').read_bytes()).hexdigest() != LINUX_HELPERS_SHA):
        raise ValueError('Pinned bootstrap helpers changed')
    manifest = json.loads((boot / 'bootstrap.json').read_text())
    nonce = bytes.fromhex(meta['nonce'])
    if (len(nonce) != 16 or meta['schema'] != 'camera-firmware-file-offline-worker/1'
            or meta['target'] != list(selected.target) or meta['test_image'] is not False
            or meta['chunk_bytes'] != 8388608 or manifest['nonce'] != nonce.hex()
            or manifest.get('schema') != 'camera-firmware-file-bootstrap-offline/1'
            or manifest['target'] != list(selected.target)
            or tiny['test_image'] is not True or tiny['profile'] != name
            or tiny['shared_sources'] != meta['shared_sources']
            or manifest['production_debug_worker_sha256'] != meta['worker_sha256']
            or manifest['bootstrap_source_sha256'] != BOOTSTRAP_SHA
            or manifest['linux_helpers_sha256'] != LINUX_HELPERS_SHA
            or manifest['builder_sha256'] != hashlib.sha256((ROOT / 'tools/firmware_file_capture_bootstrap.py').read_bytes()).hexdigest()
            or (boot / 'job.h').read_bytes() != (prod / 'job.h').read_bytes()
            or (prod / 'firmware_file_capture.c').read_text() != derived_source(name)
            or (prod / 'target.h').read_text() != target_header(selected)):
        raise ValueError('Prepared fixed file job rejected')
    for path, expected in meta['sources'].items():
        if hashlib.sha256((ROOT / path).read_bytes()).hexdigest() != expected:
            raise ValueError('Prepared worker source changed')
    if (hashlib.sha256((prod / 'worker.debug.elf').read_bytes()).hexdigest() != meta['worker_sha256']
            or manifest['production_job_manifest_sha256'] != hashlib.sha256((prod / 'job.json').read_bytes()).hexdigest()):
        raise ValueError('Prepared worker changed')
    for location, field in ((prod / 'emulation.json', 'production_emulation_sha256'),
                            (folder / 'tiny/job.json', 'tiny_job_manifest_sha256'),
                            (folder / 'tiny/emulation.json', 'tiny_emulation_sha256'),
                            (boot / 'worker.elf', 'compact_worker_sha256')):
        if hashlib.sha256(location.read_bytes()).hexdigest() != manifest[field]:
            raise ValueError('Prepared bootstrap evidence changed')
    module = (boot / 'libJit.so').read_bytes()
    if module.count((boot / 'worker.elf').read_bytes()) != 1:
        raise ValueError('Embedded worker changed')
    module_hash = hashlib.sha256(module).hexdigest()
    if module_hash != manifest['module']['sha256'] or len(module) > 65520:
        raise ValueError('Prepared bootstrap changed')
    return {'name': name, 'nonce': nonce, 'module': module, 'module_sha256': module_hash}

def capture_one_authenticated(device, name, evidence, source_is_hardware=False, *,
                              assets=ASSETS, clock=time.monotonic, sleep=time.sleep):
    """Single-use prepared job; durable global nonce claim precedes every request.

    An exception is terminal: caller must issue no later device request in that
    transaction. Assets are trusted local reviewed build inputs, verified again
    against their manifest and pinned derived source before protocol use.
    """
    selected = profile(name)
    if type(source_is_hardware) is not bool:
        raise ValueError('Explicit bool source provenance required')
    prepared = checked_capture_assets(name, assets)
    nonce, module, module_hash = (prepared[k] for k in ('nonce', 'module', 'module_sha256'))
    evidence = Path(evidence).resolve()
    evidence.mkdir(mode=0o700)
    CLAIMS.mkdir(mode=0o700, parents=True, exist_ok=True)
    durable_new(CLAIMS / (nonce.hex() + '.json'), {'nonce': nonce.hex(), 'name': name,
                'evidence': str(evidence), 'state': 'CLAIMED_BEFORE_PROTOCOL', 'automatic_retry': False})
    channel = FileChannel(device, nonce, selected, clock)
    channel.source_is_hardware = source_is_hardware
    captured = _execute_profile(channel, module, module_hash, evidence, selected.target,
                                selected.chunks, collect_file, clock, sleep)
    status = json.loads((evidence / 'capture/status.json').read_text())
    # _execute_profile already proves two source digests == host disk readback.
    if selected.sha256 is not None and status['sha256'] != selected.sha256:
        raise ValueError('Captured firmware differs from fixed expected SHA256')
    native = json.loads((evidence / 'completed.json').read_text())['native']
    ready = json.loads((evidence / 'launch-and-ready.json').read_text())['ready']
    if any(native[k] != ready[k] for k in ('pid', 'ppid', 'euid', 'loader_pid')):
        raise ValueError('Native final process identity changed')
    report = {'profile': name, 'name': name, 'capture': str(captured.resolve()),
              'bytes': selected.size, 'sha256': status['sha256'], 'nonce': nonce.hex(),
              'source_is_hardware': source_is_hardware, 'native': native,
              'module_sha256': module_hash, 'source_path': selected.path,
              'targetpath': selected.path, 'source_kind': selected.source_kind,
              'expected_sha256': selected.sha256,
              'identity_is_snapshot_lock': False}
    durable_new(evidence / 'firmware-capture.json', report)
    return report
