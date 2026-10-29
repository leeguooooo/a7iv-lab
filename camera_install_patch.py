"""One-shot volatile patch on an already authenticated, caller-owned device.

No discovery, authentication, STOP, card activation, reconnect or firmware action.
Local review and reservation precede service entry. Returned publications prove
byte consistency only; intentionally retained RAM patches are not restoration.
"""
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import time

import camera_install_volatile as contract
from camera_device_lease import CameraDeviceLease, inspect_lease, DEFAULT_LOCK
from camera_firmware_capture import (checked_capture_assets, capture_one_authenticated,
                                     CLAIMS as CAPTURE_CLAIMS)
from camera_install_journal import InstallJournal
from camera_operation_guard import assert_operation_allowed, DEFAULT_SESSIONS
from camera_stream_execution import BootstrapChannel, LIBRARIES, SLOT, validate_launch, durable_new
from camera_toolchain import checked_install_volatile

ROOT = Path(__file__).resolve().parent
CLAIMS = ROOT / 'output/install-volatile-patch-nonce-claims'
MAY_STATE = 'INSTALL_PATCH_MAY_BE_ACTIVE'
LENGTHS = {'launch': 104, 'ready': 432, 'patched': 432, 'result': 432, 'exec_failure': 8}
CAPTURES = {'pre_app': (98212632, '1e1b9202eaa69198f20df03dbfdab2f103b206cc4ebcd2e7bd817e6a710018a2'),
            'pre_ufp': (22768, 'f2e7d27602e3f7b236fc41dd93fccf53ba24f0793fd454e7fec171ae378beca7')}
SHA = re.compile(r'[0-9a-f]{64}\Z')


def require(ok, message):
    if not ok:
        raise ValueError(message)


def _sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def _path(value, *, directory=False):
    path = Path(value).absolute()
    require('..' not in path.parts and all(not p.is_symlink() for p in (path, *path.parents)),
            'Canonical nonsymlink local path required')
    require(path.is_dir() if directory else path.is_file(), 'Regular local input required')
    return path


@dataclass(frozen=True)
class InstallPatchAssets:
    directory: Path
    manifest_sha256: str
    module_sha256: str
    native_model_sha256: str
    bootstrap_model_sha256: str


@dataclass(frozen=True)
class InstallCaptureAssets:
    directory: Path
    pre_app_manifest_sha256: str
    pre_ufp_manifest_sha256: str


@dataclass(frozen=True)
class PreparedPatchAssets:
    assets: InstallPatchAssets
    capture_assets: InstallCaptureAssets
    reference_json: str
    manifest_json: str
    module: bytes

    @property
    def reference(self):
        return json.loads(self.reference_json)

    @property
    def manifest(self):
        return json.loads(self.manifest_json)


def _claim_paths(prepared):
    nonce = prepared.manifest['nonce']
    return CLAIMS / (nonce + '.json'), Path(prepared.assets.directory).absolute() / 'physical-attempt.json'


def _preflight_assets(assets, capture_assets, owned=None):
    require(isinstance(assets, InstallPatchAssets) and isinstance(capture_assets, InstallCaptureAssets),
            'Explicit reviewed patch and capture assets required')
    hashes = (assets.manifest_sha256, assets.module_sha256, assets.native_model_sha256,
              assets.bootstrap_model_sha256, capture_assets.pre_app_manifest_sha256,
              capture_assets.pre_ufp_manifest_sha256)
    require(all(isinstance(value, str) and SHA.fullmatch(value) for value in hashes),
            'Caller-reviewed SHA256 values required')
    job = _path(assets.directory, directory=True)
    require(job.is_relative_to(ROOT / 'output'), 'Workspace output patch assets required')
    for name, digest in (('manifest.json', assets.manifest_sha256), ('libJit.so', assets.module_sha256),
                         ('native-model-report.json', assets.native_model_sha256),
                         ('bootstrap-model-report.json', assets.bootstrap_model_sha256)):
        require(_sha(_path(job / name)) == digest, 'Reviewed patch asset changed: ' + name)
    capture_root = _path(capture_assets.directory, directory=True)
    require(capture_root.is_relative_to(ROOT / 'output'), 'Workspace output capture assets required')
    captures = {'directory': str(capture_root)}
    nonces = []
    for name in CAPTURES:
        digest = getattr(capture_assets, name + '_manifest_sha256')
        require(_sha(_path(capture_root / name / 'bootstrap/bootstrap.json')) == digest,
                'Reviewed capture manifest changed: ' + name)
        item = checked_capture_assets(name, capture_root)
        nonce = item['nonce']
        require(type(nonce) is bytes and len(nonce) == 16, 'Complete capture nonce required')
        nonces.append(nonce.hex())
        captures[name] = dict(manifest_sha256=digest, nonce=nonce.hex(), module_sha256=item['module_sha256'])
        for directory in (capture_root / name, capture_root / name / 'prod',
                          capture_root / name / 'bootstrap', capture_root / name / 'tiny'):
            for marker in ('physical-attempt.json', 'host-entry-intent.json', 'module-attempt.json'):
                path = directory / marker
                require(not path.exists() and not path.is_symlink(), 'Capture job already attempted: ' + name)
    require(len(set(nonces)) == len(nonces), 'Capture nonce collision')
    checked_install_volatile(job, nonces)
    manifest = json.loads((job / 'manifest.json').read_text())
    module = (job / 'libJit.so').read_bytes()
    reference = {'schema': 'camera-install-patch-assets/1',
        'patch': dict(directory=str(job), manifest_sha256=assets.manifest_sha256,
                      module_sha256=assets.module_sha256, native_model_sha256=assets.native_model_sha256,
                      bootstrap_model_sha256=assets.bootstrap_model_sha256,
                      nonce=manifest['nonce'], job_dir=manifest['job_dir']), 'captures': captures}
    prepared = PreparedPatchAssets(assets, capture_assets, _json(reference), _json(manifest), module)
    global_claim, attempt_claim = _claim_paths(prepared)
    for nonce in (*nonces, manifest['nonce']):
        old_claim = CAPTURE_CLAIMS / (nonce + '.json')
        require(not old_claim.exists() and not old_claim.is_symlink(), 'Capture nonce already consumed')
        new_claim = CLAIMS / (nonce + '.json')
        if owned is None or nonce != manifest['nonce']:
            require(not new_claim.exists() and not new_claim.is_symlink(), 'Patch nonce already reserved; no reuse')
    if owned is None:
        require(not any(p.exists() or p.is_symlink() for p in (global_claim, attempt_claim)),
                'Patch nonce already reserved; no reuse')
    else:
        _owned_reservation(prepared, owned)
    require(not (job / 'host-entry-intent.json').exists() and not (job / 'host-entry-intent.json').is_symlink(),
            'Patch entry already attempted; no replay')
    return prepared


def preflight_assets(assets, capture_assets):
    """Read-only source/model/hash/nonce/reuse checks before authentication."""
    return _preflight_assets(assets, capture_assets)


def _context(lease, journal, expected_body_sha256, plan_sha256):
    require(isinstance(lease, CameraDeviceLease) and lease.fd is not None
            and isinstance(lease.metadata, dict) and lease.metadata.get('state') == 'HELD',
            'Caller-held CameraDeviceLease required')
    descriptor, location = os.fstat(lease.fd), os.stat(lease.path, follow_symlinks=False)
    require(stat.S_ISREG(descriptor.st_mode) and stat.S_ISREG(location.st_mode)
            and (descriptor.st_dev, descriptor.st_ino) == (location.st_dev, location.st_ino),
            'Live caller lease descriptor required')
    raw = os.pread(lease.fd, 8193, 0)
    require(len(raw) <= 8192 and json.loads(raw) == lease.metadata
            and lease.metadata.get('pid') == os.getpid(), 'Held lease ownership record changed')
    inspected = inspect_lease(lease.path)
    require(inspected['live_host_lock'] is True and inspected['owner_metadata'] == lease.metadata,
            'Held caller lease lock required')
    require(all(isinstance(value, str) and SHA.fullmatch(value) for value in
                (expected_body_sha256, plan_sha256)), 'Exact body and plan SHA256 required')
    binding = dict(plan_sha256=plan_sha256, body_sha256=expected_body_sha256, model='ILCE-7M4')
    require(isinstance(journal, InstallJournal) and journal.binding == binding, 'Fresh same-body plan journal required')
    current = InstallJournal.open(journal.session_dir)
    require(current.events == journal.events and current.state == MAY_STATE, 'Fresh install-patch MAY state required')
    assert_operation_allowed(journal, allowed_states=(MAY_STATE,))
    if journal.session_dir.parent.resolve() != DEFAULT_SESSIONS.resolve():
        assert_operation_allowed(sessions_root=DEFAULT_SESSIONS)
    return binding


def _owned_reservation(prepared, reservation):
    require(isinstance(reservation, dict) and set(reservation) == {'global_claim', 'attempt_claim', 'record'},
            'Owned patch reservation required')
    paths = _claim_paths(prepared)
    for name, expected in zip(('global_claim', 'attempt_claim'), paths):
        ref = reservation[name]
        require(isinstance(ref, dict) and set(ref) == {'path', 'sha256'}
                and ref['path'] == str(expected) and isinstance(ref.get('sha256'), str)
                and SHA.fullmatch(ref['sha256']),
                'Reservation path/hash differs')
        path = _path(expected)
        require(_sha(path) == ref['sha256'] and json.loads(path.read_text()) == reservation['record'],
                'Reserved nonce record changed')
    record = reservation['record']
    require(isinstance(record, dict), 'Reservation record required')
    require(record.get('schema') == 'camera-install-patch-reservation/1'
            and record.get('scope') == 'INSTALL_PREPARATION_VOLATILE_PATCH_ONLY'
            and record.get('state') == 'RESERVED_BEFORE_AUTHENTICATION'
            and record.get('automatic_retry') is False
            and record.get('asset_reference') == prepared.reference
            and record.get('nonce') == prepared.manifest['nonce'], 'Reservation assets or scope differ')


def reserve_assets(prepared, evidence, *, lease, journal, expected_body_sha256, plan_sha256):
    """Claim this nonce globally and locally before any authentication request."""
    binding = _context(lease, journal, expected_body_sha256, plan_sha256)
    require(isinstance(prepared, PreparedPatchAssets), 'Prepared patch assets required')
    fresh = preflight_assets(prepared.assets, prepared.capture_assets)
    require(fresh == prepared, 'Local patch review changed before reservation')
    evidence = _path(evidence, directory=True)
    record = dict(schema='camera-install-patch-reservation/1', **binding,
                  nonce=prepared.manifest['nonce'], asset_reference=prepared.reference,
                  evidence=str(evidence), lease_instance=lease.metadata.get('instance'),
                  session_id=journal.session_dir.name, scope='INSTALL_PREPARATION_VOLATILE_PATCH_ONLY',
                  state='RESERVED_BEFORE_AUTHENTICATION', automatic_retry=False)
    global_claim, attempt_claim = _claim_paths(prepared)
    require(all(not p.is_symlink() for p in (CLAIMS, *CLAIMS.parents)), 'Regular global nonce directory required')
    CLAIMS.mkdir(mode=0o700, parents=True, exist_ok=True)
    durable_new(global_claim, record)
    durable_new(attempt_claim, record)
    return {'global_claim': {'path': str(global_claim), 'sha256': _sha(global_claim)},
            'attempt_claim': {'path': str(attempt_claim), 'sha256': _sha(attempt_claim)}, 'record': record}


class InstallPatchChannel(BootstrapChannel):
    def __init__(self, device, nonce, clock=time.monotonic):
        super().__init__(device, nonce, clock)
        self.directory = '/tmp_wbshd/m4ivp_' + nonce.hex()
        self.start_attempted = False

    def read(self, name, missing=False):
        require(name in LENGTHS, 'Only published install-patch records may be read')
        self._select(name)
        return self._packet(17, b'\0\xff\0', LENGTHS[name], missing)

    def start_once(self, evidence):
        if self.start_attempted:
            raise RuntimeError('Install patch START already attempted; no replay')
        self.start_attempted = True
        durable_new(Path(evidence) / 'start-intent.json', {'nonce': self.nonce.hex(), 'automatic_retry': False})
        self._select('start')
        raw = contract.START_MAGIC + self.nonce + struct.pack('<Q', 2)
        if self._packet(16, b'\0\xff\0' + raw, 0) != b'':
            self.healthy = False
            raise ValueError('Install patch START response differs')


def _raw(evidence, name, raw):
    require(type(raw) is bytes, 'Publication must be bytes')
    durable_new(Path(evidence) / (name + '-received.json'), {'bytes': len(raw), 'raw_hex': raw.hex()})


def _poll(channel, name, seconds, evidence, clock, sleep):
    deadline = clock() + seconds
    while clock() < deadline:
        raw = channel.read(name, missing=True)
        if raw is not None:
            _raw(evidence, name, raw)
            require(len(raw) == LENGTHS[name], 'Incomplete publication; no re-observation or replay')
            return raw
        if name != 'result':
            final = channel.read('result', missing=True)
            if final is not None:
                _raw(evidence, name + '-early-result', final)
                raise RuntimeError('Worker ended before requested publication')
        failure = channel.read('exec_failure', missing=True)
        if failure is not None:
            _raw(evidence, name + '-exec-failure', failure)
            raise RuntimeError('Install patch worker exec failed')
        sleep(0.1)
    raise TimeoutError('Install patch publication deadline; no retry')


def start_authenticated(device, evidence, *, assets, capture_assets, reservation, lease, journal,
                        expected_body_sha256, plan_sha256, volatile_patch_authorized=False,
                        body_verified=False, source_is_hardware=False, capture_one=None,
                        channel_factory=None, clock=time.monotonic, sleep=time.sleep):
    """Use one reserved job on an authenticated device; caller owns service exit."""
    channel = None
    stage = 'LOCAL_PREFLIGHT'
    requests_may_have_started = False
    folder = Path(evidence).absolute()
    try:
        require(volatile_patch_authorized is True and body_verified is True,
                'Explicit volatile patch approval and verified body required')
        require(type(source_is_hardware) is bool, 'Explicit source evidence kind required')
        injected = capture_one is not None or channel_factory is not None
        require(not injected or (capture_one is not None and channel_factory is not None),
                'Both capture and channel must be injected together')
        if not injected:
            require(source_is_hardware is True, 'Default I/O requires explicit hardware source context')
            require(isinstance(lease, CameraDeviceLease)
                    and Path(lease.path).absolute() == DEFAULT_LOCK.absolute()
                    and all(not p.is_symlink() for p in (DEFAULT_LOCK, *DEFAULT_LOCK.parents)),
                    'Default I/O requires the canonical device lease')
            require(isinstance(journal, InstallJournal)
                    and journal.session_dir.parent.absolute() == DEFAULT_SESSIONS.absolute()
                    and all(not p.is_symlink() for p in (DEFAULT_SESSIONS, *DEFAULT_SESSIONS.parents)),
                    'Default I/O requires the canonical global session journal')
        binding = _context(lease, journal, expected_body_sha256, plan_sha256)
        folder = _path(folder, directory=True)
        prepared = _preflight_assets(assets, capture_assets, reservation)
        record = reservation['record']
        require(all(record.get(key) == value for key, value in binding.items())
                and record.get('evidence') == str(folder)
                and record.get('session_id') == journal.session_dir.name
                and record.get('lease_instance') == lease.metadata.get('instance'),
                'Reservation body/plan/session/lease differs')
        hardware = source_is_hardware and not injected
        durable_new(Path(assets.directory) / 'host-entry-intent.json',
                    dict(reservation_sha256=reservation['attempt_claim']['sha256'], **binding,
                         nonce=prepared.manifest['nonce'], automatic_retry=False))
        captures = {}
        capture = capture_one or capture_one_authenticated
        stage = 'COMPLETE_ORIGINAL_FILE_CAPTURE'
        for name, (size, expected) in CAPTURES.items():
            requests_may_have_started = True
            value = capture(device, name, folder / name, source_is_hardware=hardware,
                            assets=capture_assets.directory, clock=clock, sleep=sleep)
            native = value['native']
            require(value['profile'] == name and value['bytes'] == size and value['sha256'] == expected
                    and value['nonce'] == prepared.reference['captures'][name]['nonce']
                    and value['module_sha256'] == prepared.reference['captures'][name]['module_sha256']
                    and value['source_is_hardware'] is hardware
                    and native['phase'] == 6 and native['flags'] == 63 and native['error'] == native['cleanup'] == 0
                    and native['offset'] == size and native['first_sha256'] == native['second_sha256'] == expected,
                    'Exact full double capture differs; no next request')
            captures[name] = value
        durable_new(folder / 'complete-library-captures.json', captures)
        nonce = bytes.fromhex(prepared.manifest['nonce'])
        channel = (channel_factory or InstallPatchChannel)(device, nonce, clock)
        stage = 'LOADER_AND_SLOT_CHECK'
        for path, expected in LIBRARIES.items():
            require(hashlib.sha256(channel.read_loader(path)).hexdigest() == expected, 'Loader library differs')
        require(channel.read_loader(SLOT) is None, 'Module slot already occupied')
        stage = 'MODULE_UPLOAD_MAY_HAVE_STARTED'
        channel.upload_once(prepared.module, assets.module_sha256, folder / 'module-attempt.json')
        loader = validate_launch(_poll(channel, 'launch', 30, folder, clock, sleep), nonce)
        ready_raw = _poll(channel, 'ready', 30, folder, clock, sleep)
        ready = contract.decode_record(ready_raw, nonce)
        contract._ready(ready, loader)
        stage = 'START_MAY_HAVE_BEEN_SENT'
        channel.start_once(folder)
        patched_raw = _poll(channel, 'patched', 330, folder, clock, sleep)
        patched = contract.decode_record(patched_raw, nonce)
        contract._applied(patched, 5)
        require(all(patched[key] == ready[key] for key in contract.WORKER_FIELDS), 'Patched worker identity differs')
        stage = 'AWAITING_ATOMIC_TERMINAL'
        result_raw = _poll(channel, 'result', 30, folder, clock, sleep)
        proof = contract.validate_publications(ready_raw, patched_raw, result_raw, nonce=nonce, loader_pid=loader)
        receipt = dict(proof, **binding, asset_reference=prepared.reference, reservation=reservation,
            loader_pid=loader, raw_publications={'ready': ready_raw.hex(), 'patched': patched_raw.hex(),
                                                'result': result_raw.hex()},
            source_is_hardware=hardware, full_live_file_capture_reports=captures,
            scope='INSTALL_PREPARATION_VOLATILE_PATCH_ONLY', service_exit_completed=False,
            normal_body_reappearance_verified=False, automatic_retry=False, automatic_STOP=False,
            automatic_reboot=False, automatic_reset=False, automatic_rollback=False,
            automatic_reupload=False, automatic_START=False)
        durable_new(folder / 'patch-receipt.json', receipt)
        return receipt
    except BaseException as error:
        if channel is not None:
            channel.healthy = False
        failure = dict(stage=stage, error_type=type(error).__name__,
            device_requests_may_have_started=requests_may_have_started,
            state='STOPPED_UNKNOWN' if requests_may_have_started else 'LOCAL_PREFLIGHT_REJECTED',
            installation_authorized=False, firmware_installation_proven=False,
            RAM_restoration_proven=False, automatic_retry=False, automatic_STOP=False,
            automatic_reboot=False, automatic_reset=False, automatic_rollback=False,
            automatic_reupload=False, automatic_START=False)
        try:
            _path(folder, directory=True)
            durable_new(folder / 'patch-stopped.json', failure)
        except BaseException:
            pass
        raise
