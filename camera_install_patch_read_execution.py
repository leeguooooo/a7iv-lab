"""One reserved fixed-target read on an already authenticated device.

No discovery, authentication, STOP, reboot, flash or journal transition. Current
observations never certify the original mm, restoration or cancellation.
"""
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import time

import camera_install_patch_read as contract
from camera_device_lease import DEFAULT_LOCK, CameraDeviceLease
from camera_firmware_capture import CLAIMS as CAPTURE_CLAIMS
from camera_install_journal import InstallJournal
from camera_install_patch import CLAIMS as PATCH_CLAIMS
from camera_install_patch_session import _held_lease
from camera_operation_guard import DEFAULT_SESSIONS, assert_operation_allowed
from camera_stream_execution import BootstrapChannel, LIBRARIES, SLOT, validate_launch, durable_new
from camera_toolchain import checked_install_patch_read

ROOT = Path(__file__).resolve().parent
CLAIMS = ROOT / 'output/install-patch-read-nonce-claims'
PENDING_STATE = 'INSTALL_PATCH_AWAITING_OPERATOR_RECONNECT'
SCOPE = 'INSTALL_PATCH_CURRENT_READ_ONLY'
LENGTHS = dict(launch=104, ready=424, result=424, exec_failure=8)
SHA = re.compile(r'[0-9a-f]{64}\Z')


def require(ok, message):
    if not ok:
        raise ValueError(message)


def _path(value, directory=False):
    p = Path(value).absolute()
    require('..' not in p.parts and all(not x.is_symlink() for x in (p, *p.parents)), 'Nonsymlink canonical path required')
    require(p.is_dir() if directory else p.is_file(), 'Regular local input required')
    return p


def _sha(path):
    with Path(path).open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def _reference(ref):
    require(isinstance(ref, dict) and set(ref) == {'path', 'sha256'}
            and isinstance(ref['sha256'], str) and SHA.fullmatch(ref['sha256']), 'Exact pending artifact reference required')
    p = _path(ref['path'])
    require(str(p) == ref['path'], 'Canonical pending reference required')
    raw = p.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == ref['sha256'], 'Original pending artifact changed')
    return raw


@dataclass(frozen=True)
class InstallPatchReadAssets:
    directory: Path
    manifest_sha256: str
    module_sha256: str
    native_model_sha256: str
    bootstrap_model_sha256: str
    target_spec_sha256: str


@dataclass(frozen=True)
class PreparedReadAssets:
    assets: InstallPatchReadAssets
    reference_json: str
    manifest_json: str
    spec_json: str
    module: bytes

    @property
    def reference(self):
        return json.loads(self.reference_json)

    @property
    def manifest(self):
        return json.loads(self.manifest_json)

    @property
    def spec(self):
        return json.loads(self.spec_json)


def _claims(prepared):
    return CLAIMS / (prepared.manifest['nonce'] + '.json'), Path(prepared.assets.directory).absolute() / 'physical-attempt.json'


def _owned(prepared, reservation):
    require(isinstance(reservation, dict) and set(reservation) == {'global_claim', 'job_claim', 'record'}, 'Owned read reservation required')
    for key, path in zip(('global_claim', 'job_claim'), _claims(prepared)):
        ref = reservation[key]
        require(isinstance(ref, dict) and set(ref) == {'path', 'sha256'} and ref['path'] == str(path)
                and isinstance(ref['sha256'], str) and SHA.fullmatch(ref['sha256']), 'Read reservation reference differs')
        require(_sha(_path(path)) == ref['sha256'] and json.loads(path.read_text()) == reservation['record'], 'Read reservation changed')
    r = reservation['record']
    require(isinstance(r, dict) and r.get('schema') == 'camera-install-patch-read-reservation/1'
            and r.get('scope') == SCOPE and r.get('state') == 'RESERVED_BEFORE_AUTHENTICATION'
            and r.get('asset_reference') == prepared.reference and r.get('automatic_retry') is False,
            'Read reservation scope/assets differ')


def _preflight(assets, pending_reference, expected_body_sha256, plan_sha256, owned=None):
    require(isinstance(assets, InstallPatchReadAssets), 'Explicit reviewed read assets required')
    require(all(isinstance(v, str) and SHA.fullmatch(v) for v in (assets.manifest_sha256, assets.module_sha256,
            assets.native_model_sha256, assets.bootstrap_model_sha256, assets.target_spec_sha256,
            expected_body_sha256, plan_sha256)), 'Reviewed complete SHA256 values required')
    job = _path(assets.directory, True)
    require(job.is_relative_to(ROOT / 'output'), 'Workspace output read job required')
    for name, digest in (('manifest.json', assets.manifest_sha256), ('libJit.so', assets.module_sha256),
            ('native-model-report.json', assets.native_model_sha256), ('bootstrap-model-report.json', assets.bootstrap_model_sha256)):
        require(_sha(_path(job / name)) == digest, 'Reviewed read artifact changed: ' + name)
    checked_install_patch_read(job)
    manifest = json.loads((job / 'manifest.json').read_text())
    spec = json.loads(_path(job / 'target-spec.json').read_text())
    raw = _reference(pending_reference)
    derived = contract.derive_target_spec(raw, body_sha256=expected_body_sha256, plan_sha256=plan_sha256)
    require(spec == derived and contract.spec_sha256(spec) == assets.target_spec_sha256
            and manifest['target_spec_sha256'] == assets.target_spec_sha256
            and manifest['original_pending']['sha256'] == pending_reference['sha256']
            and manifest['original_patch_nonce'] == spec['original_patch_nonce'], 'Read job does not derive from this complete pending receipt')
    nonce = manifest['nonce']
    old = {spec['original_patch_nonce'], *(spec['original_asset_reference']['captures'][n]['nonce'] for n in ('pre_app', 'pre_ufp'))}
    require(nonce not in old, 'Read nonce collides with original job')
    for root in (CAPTURE_CLAIMS, PATCH_CLAIMS):
        claim = root / (nonce + '.json')
        require(not claim.exists() and not claim.is_symlink(), 'Read nonce consumed in another namespace')
    reference = dict(schema='camera-install-patch-read-assets/1', directory=str(job),
        manifest_sha256=assets.manifest_sha256, module_sha256=assets.module_sha256,
        native_model_sha256=assets.native_model_sha256, bootstrap_model_sha256=assets.bootstrap_model_sha256,
        target_spec_sha256=assets.target_spec_sha256, nonce=nonce, job_dir=manifest['job_dir'],
        pending_reference=dict(pending_reference), body_sha256=expected_body_sha256, plan_sha256=plan_sha256)
    module = _path(job / 'libJit.so').read_bytes()
    require(hashlib.sha256(module).hexdigest() == assets.module_sha256, 'Acquired read module changed')
    prepared = PreparedReadAssets(assets, _canonical(reference), _canonical(manifest), _canonical(spec), module)
    if owned is None:
        require(not any(p.exists() or p.is_symlink() for p in _claims(prepared)), 'Read nonce already reserved')
    else:
        _owned(prepared, owned)
    for name in ('host-entry-intent.json', 'module-attempt.json', 'claim.json'):
        require(not (job / name).exists() and not (job / name).is_symlink(), 'Read job already attempted')
    return prepared


def preflight_assets(assets, *, pending_reference, expected_body_sha256, plan_sha256):
    """Only local reads; validate the exact compiled prior-pending derivation."""
    return _preflight(assets, pending_reference, expected_body_sha256, plan_sha256)


def _context(prepared, lease, journal):
    identity = _held_lease(lease)
    require(isinstance(journal, InstallJournal), 'Original pending InstallJournal required')
    current = InstallJournal.open(journal.session_dir)
    ref = prepared.reference
    require(current.events == journal.events and current.state == PENDING_STATE
            and current.binding == dict(body_sha256=ref['body_sha256'], plan_sha256=ref['plan_sha256'], model='ILCE-7M4')
            and current.events[-1]['details'].get('install_patch_artifact') == ref['pending_reference']
            and not any(e['state'] == 'FLASH_MAY_HAVE_STARTED' for e in current.events), 'Original pending history/body/plan binding differs')
    require(hashlib.sha256(_reference(ref['pending_reference'])).hexdigest() == prepared.spec['pending_receipt_sha256'], 'Pending receipt changed at read boundary')
    assert_operation_allowed(journal, allowed_states=(PENDING_STATE,))
    if journal.session_dir.parent.resolve() != DEFAULT_SESSIONS.resolve():
        assert_operation_allowed(sessions_root=DEFAULT_SESSIONS)
    return identity


def _same_context(prepared, lease, journal, expected_identity):
    require(_context(prepared, lease, journal) == expected_identity,
            'Reserved lease identity changed during read')


def reserve_assets(prepared, evidence, *, lease, journal):
    """Persist global and job-local once-only claims before caller service entry."""
    require(isinstance(prepared, PreparedReadAssets), 'Prepared read assets required')
    identity = _context(prepared, lease, journal)
    r = prepared.reference
    fresh = preflight_assets(prepared.assets, pending_reference=r['pending_reference'],
                            expected_body_sha256=r['body_sha256'], plan_sha256=r['plan_sha256'])
    require(fresh == prepared, 'Read assets changed before reservation')
    _same_context(prepared, lease, journal, identity)
    folder = _path(evidence, True)
    require(not any(folder.iterdir()), 'Fresh empty read evidence directory required')
    record = dict(schema='camera-install-patch-read-reservation/1', scope=SCOPE,
        state='RESERVED_BEFORE_AUTHENTICATION', asset_reference=r, evidence=str(folder),
        session_id=journal.session_dir.name, pending_event_sha256=journal.events[-1]['event_sha256'],
        lease_identity=identity, automatic_retry=False)
    require(all(not p.is_symlink() for p in (CLAIMS, *CLAIMS.parents)), 'Regular read claim directory required')
    CLAIMS.mkdir(mode=0o700, parents=True, exist_ok=True)
    paths = _claims(prepared)
    for path in paths:
        _same_context(prepared, lease, journal, identity)
        durable_new(path, record)
    _same_context(prepared, lease, journal, identity)
    return dict(global_claim=dict(path=str(paths[0]),sha256=_sha(paths[0])),
                job_claim=dict(path=str(paths[1]),sha256=_sha(paths[1])),record=record)


class ReadChannel(BootstrapChannel):
    def __init__(self, device, nonce, spec, clock=time.monotonic):
        super().__init__(device, nonce, clock)
        self.directory = '/tmp_wbshd/m4ipr_' + nonce.hex()
        self.spec, self.start_attempted = spec, False

    def _packet(self, command, data, maximum, missing=False):
        guard = getattr(self, 'context_guard', None)
        if guard is not None:
            guard()
        return super()._packet(command, data, maximum, missing)

    def read(self, name, missing=False):
        require(name in LENGTHS, 'Only final published reader files may be read')
        self._select(name)
        return self._packet(17, b'\0\xff\0', LENGTHS[name], missing)

    def start_once(self, evidence):
        require(not self.start_attempted, 'Read START already attempted; no replay')
        self.start_attempted = True
        durable_new(Path(evidence) / 'start-intent.json', dict(nonce=self.nonce.hex(), automatic_retry=False))
        self._select('start')
        token = contract.START_FRAME.pack(contract.START_MAGIC, self.nonce, bytes.fromhex(self.spec['original_patch_nonce']), contract.VERSION)
        if self._packet(16, b'\0\xff\0' + token, 0) != b'':
            self.healthy = False
            raise ValueError('Reader START response differs')


def _raw(folder, name, raw):
    require(type(raw) is bytes, 'Raw publication bytes required')
    durable_new(folder / (name + '-received.json'), dict(bytes=len(raw), raw_hex=raw.hex()))


def _poll(channel, name, seconds, folder, clock, sleep, guard):
    deadline = clock() + seconds
    while clock() < deadline:
        guard()
        raw = channel.read(name, missing=True)
        if raw is not None:
            _raw(folder, name, raw)
            require(len(raw) == LENGTHS[name], 'Partial/oversized publication; no retry')
            return raw
        if name != 'result':
            guard()
            terminal = channel.read('result', missing=True)
            if terminal is not None:
                _raw(folder, name + '-early-result', terminal)
                raise ValueError('Reader ended before requested publication')
        guard()
        failure = channel.read('exec_failure', missing=True)
        if failure is not None:
            _raw(folder, name + '-exec-failure', failure)
            raise ValueError('Reader exec failed')
        sleep(0.1)
    raise TimeoutError('Reader publication deadline; no retry')


def start_authenticated(device, evidence, *, assets, reservation, pending_reference, lease, journal,
        expected_body_sha256, plan_sha256, read_authorized=False, body_verified=False,
        source_is_hardware=False, channel_factory=None, clock=time.monotonic, sleep=time.sleep):
    """Run one fixed read; caller owns authentication and any known service exit."""
    channel = None
    folder = Path(evidence).absolute()
    stage, requests = 'LOCAL_PREFLIGHT', False
    try:
        require(read_authorized is True and body_verified is True, 'Explicit current-read consent and verified body required')
        require(type(source_is_hardware) is bool, 'Explicit source context required')
        require(channel_factory is None or callable(channel_factory), 'Injected channel factory must be callable')
        injected = channel_factory is not None
        if not injected:
            require(source_is_hardware is True and isinstance(lease, CameraDeviceLease)
                    and isinstance(journal, InstallJournal) and Path(lease.path).absolute() == DEFAULT_LOCK.absolute()
                    and journal.session_dir.parent.absolute() == DEFAULT_SESSIONS.absolute(), 'Default I/O requires canonical hardware context')
        prepared = _preflight(assets, pending_reference, expected_body_sha256, plan_sha256, reservation)
        identity = _context(prepared, lease, journal)
        folder = _path(folder, True)
        record = reservation['record']
        require(record.get('evidence') == str(folder) and record.get('lease_identity') == identity
                and record.get('session_id') == journal.session_dir.name
                and record.get('pending_event_sha256') == journal.events[-1]['event_sha256'], 'Read reservation context differs')
        if not injected:
            _path(lease.path)
            _path(journal.session_dir, True)
            require(prepared.spec['original_source_is_hardware'] is True
                    and not contract._modeled(json.loads(bytes.fromhex(prepared.spec['pending_receipt_raw_hex']))),
                    'Modeled or non-hardware prior receipt cannot enter default I/O')
        guard = lambda: _same_context(prepared, lease, journal, identity)
        nonce = bytes.fromhex(prepared.manifest['nonce'])
        durable_new(Path(assets.directory) / 'host-entry-intent.json', dict(reservation_sha256=reservation['job_claim']['sha256'], scope=SCOPE, automatic_retry=False))
        factory = ReadChannel if channel_factory is None else channel_factory
        channel = factory(device, nonce, prepared.spec, clock)
        if isinstance(channel, ReadChannel):
            channel.context_guard = guard
        stage, requests = 'LOADER_AND_SLOT_CHECK', True
        for path, digest in LIBRARIES.items():
            guard()
            require(hashlib.sha256(channel.read_loader(path)).hexdigest() == digest, 'Loader differs from pinned source')
        guard()
        require(channel.read_loader(SLOT) is None, 'Module slot already occupied; no cleanup')
        guard()
        stage = 'MODULE_UPLOAD_MAY_HAVE_STARTED'
        channel.upload_once(prepared.module, assets.module_sha256, folder / 'module-attempt.json')
        loader = validate_launch(_poll(channel, 'launch', 30, folder, clock, sleep, guard), nonce)
        ready_raw = _poll(channel, 'ready', 30, folder, clock, sleep, guard)
        ready = contract.decode_record(ready_raw, nonce, prepared.spec)
        contract._context(ready, prepared.spec, loader)
        require(ready['phase'] == 1 and ready['flags'] == contract.READY_FLAGS and ready['passes'] == 0
                and all(ready[f'{target}_{suffix}'] == 0 for target in ('lib', 'app') for suffix in contract.TARGET_SUFFIXES), 'Exact readonly READY required before START')
        guard()
        early = channel.read('result', missing=True)
        if early is not None:
            _raw(folder, 'before-start-result', early)
            raise ValueError('Reader already ended; no START')
        guard()
        stage = 'START_MAY_HAVE_BEEN_SENT'
        channel.start_once(folder)
        stage = 'AWAITING_CURRENT_OBSERVATION'
        result_raw = _poll(channel, 'result', 30, folder, clock, sleep, guard)
        proof = contract.validate_publications(ready_raw, result_raw, nonce=nonce, loader_pid=loader, spec=prepared.spec)
        guard()
        receipt = proof | dict(scope=SCOPE, asset_reference=prepared.reference, reservation=reservation,
            source_is_hardware=source_is_hardware and not injected, service_exit_completed=False,
            automatic_retry=False, automatic_STOP=False, automatic_restore=False, automatic_reboot=False,
            automatic_reupload=False, automatic_START=False, journal_cleared=False, cancellation_recorded=False)
        durable_new(folder / 'current-read-receipt.json', receipt)
        return receipt
    except BaseException as error:
        if channel is not None:
            channel.healthy = False
        failure = dict(stage=stage, error_type=type(error).__name__, device_requests_may_have_started=requests,
            state='READ_OUTCOME_UNKNOWN' if requests else 'LOCAL_PREFLIGHT_REJECTED',
            automatic_retry=False, automatic_STOP=False, automatic_restore=False, automatic_reboot=False,
            automatic_reupload=False, automatic_START=False, journal_cleared=False, installation_authorized=False)
        try:
            durable_new(_path(folder, True) / 'read-stopped.json', failure)
        except BaseException:
            pass
        raise
