"""One-attempt RO_METADATA host integration, with no discovery or authentication.

All device I/O uses an explicitly injected already-authenticated channel. Hardware
origin is a trusted caller assertion, never inferred from JSON or a binary nonce.
Unknown outcomes remain in the shared install journal after the lease closes.
"""
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import struct
import time

from camera_device_lease import DEFAULT_LOCK
from camera_install_journal import InstallJournal
from camera_install_patch_session import _held_lease
from camera_operation_guard import DEFAULT_SESSIONS, assert_operation_allowed
from camera_stream_execution import BootstrapChannel, LIBRARIES, SLOT, durable_new, validate_launch as validate_bootstrap_launch

ROOT = Path(__file__).resolve().parent
CLAIMS = ROOT / 'output/readonly-identity-nonce-claims'
FREEZE_SHA256 = 'fa05555e4e8aef36b6c36fb7509bad9aa5831d0e92caba34470c46a0aaba9410'
NONCE = '957ba14fe2d99b34871ae4f436d92d96'
WORKER_SHA256 = '847bf052ef5c4916d71ea9e78f3e61818d2d11725321ecf249882b1baa6a33a7'
MODULE_SHA256 = 'e2971269981e5d69a8dd754f0c52cb16eb19f23b457fae625498836fcb7afc2a'
HEADER = struct.Struct('<8s16sIIqqII36s36s')
HOST_SOURCES = ('camera_readonly_identity.py', 'camera_device_lease.py', 'camera_install_journal.py',
                'camera_install_patch_session.py', 'camera_operation_guard.py',
                'camera_stream_execution.py', 'camera_stream_channel.py', 'camera_stream_senser.py',
                'camera_stream_transport_bounds.py', 'camera_stream_receiver.py')
SCOPE = 'RO_METADATA'
MAY = 'RO_METADATA_MAY_BE_ACTIVE'
OBSERVED = 'RO_METADATA_OBSERVED'
UNKNOWN = 'RO_METADATA_UNKNOWN'
EXPECTED_WRITES = ('owned fixed upload /tmp/jiritsu/libJit.so and bootstrap cleanup',
                   'nonce job directory, worker, launch, conditional exec_failure',
                   'ready.pending -> ready, start token consumed, result.pending -> result')


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def safe_path(value):
    path = Path(value).absolute()
    require('..' not in path.parts and all(not p.is_symlink() for p in (path, *path.parents)),
            'Nonsymlink canonical path required')
    return path


def read_json(path):
    path = safe_path(path)
    require(path.is_file(), 'Regular local file required')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'Duplicate JSON field')
            result[key] = value
        return result
    raw = path.read_bytes()
    return raw, json.loads(raw, object_pairs_hook=unique)


def valid_nonce(value):
    require(type(value) is str and re.fullmatch('[0-9a-f]{32}', value) and any(bytes.fromhex(value)),
            'Exact nonzero lower-case 16-byte nonce required')


@dataclass(frozen=True)
class Assets:
    kit_dir: Path
    source_root: Path


@dataclass(frozen=True)
class Prepared:
    assets: Assets
    reference_json: bytes
    module: bytes
    contract: bytes

    @property
    def reference(self):
        return json.loads(self.reference_json)


def host_source_bindings():
    return {name: sha(safe_path(ROOT / name).read_bytes()) for name in HOST_SOURCES}


def preflight_assets(assets):
    """Verify the frozen review, all its bytes, native inputs and compiler pin.

    Hashing the compiler is read-only; no compiler or native program is run.
    """
    require(isinstance(assets, Assets), 'Explicit frozen Assets required')
    kit, sources = safe_path(assets.kit_dir), safe_path(assets.source_root)
    freeze_raw, freeze = read_json(kit / 'freeze.json')
    require(sha(freeze_raw) == FREEZE_SHA256, 'Frozen review changed')
    for name, pin in freeze['files'].items():
        p = safe_path(kit / name)
        require(p.is_relative_to(kit) and p.is_file(), 'Frozen file absent')
        raw = p.read_bytes()
        require(len(raw) == pin['bytes'] and sha(raw) == pin['sha256'], 'Frozen file changed: ' + name)
    manifest_raw, manifest = read_json(kit / 'canonical/manifest.json')
    valid_nonce(manifest['nonce'])
    require(manifest['nonce'] == NONCE and manifest['scope'] == SCOPE
            and manifest['job_dir'] == '/tmp_wbshd/roid_' + NONCE
            and manifest['worker_sha256'] == WORKER_SHA256
            and manifest['bootstrap_sha256'] == MODULE_SHA256, 'Reviewed identity artifacts differ')
    for name, expected in manifest['sources'].items():
        require(sha(safe_path(kit / name).read_bytes()) == expected, 'Source changed: ' + name)
    for name, expected in manifest['pins'].items():
        require(sha(safe_path(sources / name).read_bytes()) == expected, 'Pinned input changed: ' + name)
    for name, count in (('model-report.json', 22), ('bootstrap-model-report.json', 18)):
        _, report = read_json(kit / 'canonical' / name)
        require(report['all_passed'] is True and report['hardware_operations'] == 0
                and len(report['results']) == count and all(r['passed'] is True for r in report['results']),
                'Complete offline compiled model required')
    reference = dict(scope=SCOPE, nonce=NONCE, job_dir=manifest['job_dir'], kit_dir=str(kit),
                     source_root=str(sources), freeze_sha256=FREEZE_SHA256,
                     manifest_sha256=sha(manifest_raw), worker_sha256=WORKER_SHA256,
                     module_sha256=MODULE_SHA256, contract_sha256=manifest['sources']['contract.py'],
                     host_sha256=sha(Path(__file__).read_bytes()), host_sources=host_source_bindings())
    return Prepared(assets, canonical(reference), (kit / 'canonical/libJit.so').read_bytes(),
                    (kit / 'contract.py').read_bytes())


@dataclass(frozen=True)
class CaptureContext:
    """Caller-owned origin binding; callbacks must inspect trusted runtime context.

    A dict with source_is_hardware=True is deliberately not accepted. The callback
    must bind this particular authenticated object and target on every guard. It
    The callback must also establish exclusive device operation ownership for
    the fixed bootstrap cleanup; the host lease alone is only cooperative. It
    remains an assertion by the caller, not cryptographic hardware attestation.
    """
    target_id: str
    origin: str = 'SIMULATED'
    hardware_context_check: object = None


def context_binding(context, device, lease, journal, states):
    require(isinstance(context, CaptureContext) and type(context.target_id) is str
            and re.fullmatch('[A-Za-z0-9_.:-]{1,120}', context.target_id), 'Explicit target context required')
    require(context.origin in ('SIMULATED', 'HARDWARE'), 'Explicit origin required')
    lease_identity = _held_lease(lease)
    safe_path(lease.path)
    safe_path(journal.session_dir)
    current = InstallJournal.open(journal.session_dir)
    require(current.events == journal.events and current.state in states, 'Fresh exact journal history required')
    if context.origin == 'HARDWARE':
        require(not (ROOT / '.git').is_file(), 'Isolated worktree cannot perform hardware I/O')
        require(safe_path(lease.path) == safe_path(DEFAULT_LOCK)
                and safe_path(journal.session_dir.parent) == safe_path(DEFAULT_SESSIONS),
                'Hardware requires canonical lease and global journal')
        require(callable(context.hardware_context_check)
                and context.hardware_context_check(device, context.target_id) is True,
                'Trusted caller must bind the authenticated device and physical target')
    else:
        require(context.hardware_context_check is None, 'Simulation cannot assert hardware origin')
    assert_operation_allowed(journal, allowed_states=states)
    if safe_path(journal.session_dir.parent) != safe_path(DEFAULT_SESSIONS):
        assert_operation_allowed(sessions_root=DEFAULT_SESSIONS)
    return dict(scope=SCOPE, target_id=context.target_id, origin=context.origin,
                lease_identity=lease_identity, session_dir=str(safe_path(journal.session_dir)),
                journal_binding=journal.binding, initial_event_sha256=current.events[0]['event_sha256'])


def approval_payload(prepared, context):
    """Data for review only; this does not create or confer operator approval."""
    stable = {key: value for key, value in context.items() if key != 'lease_identity'}
    return dict(scope=SCOPE, context=stable, asset_reference=prepared.reference,
                attempts=1, automatic_retry=False, expected_writes=list(EXPECTED_WRITES),
                flash_authorized=False, RAM_patch_authorized=False, installation_authorized=False)


def validate_approval(approval, prepared, context):
    require(type(approval) is dict and set(approval) == {'operator', 'explicit_approval', 'binding'},
            'Separate explicit bound operator approval required')
    require(type(approval['operator']) is str and 0 < len(approval['operator'].strip()) <= 120
            and approval['explicit_approval'] is True
            and approval['binding'] == approval_payload(prepared, context), 'Approval scope or binding differs')


def reserve_assets(prepared, evidence, *, lease, journal, device, context, approval):
    require(isinstance(prepared, Prepared), 'Prepared assets required')
    bound = context_binding(context, device, lease, journal, ('PLANNED',))
    require(len(journal.events) == 1, 'Fresh RO-only journal required')
    validate_approval(approval, prepared, bound)
    require(preflight_assets(prepared.assets) == prepared, 'Prepared assets changed')
    folder = safe_path(evidence)
    require(folder.is_dir() and not any(folder.iterdir()), 'Fresh empty evidence folder required')
    valid_nonce(prepared.reference['nonce'])
    # Check all existing public nonce namespaces, including prior metadata tools.
    nonce = prepared.reference['nonce']
    require(not (CLAIMS / (nonce + '.json')).exists() and
            not (CLAIMS / (nonce + '.json')).is_symlink(), 'Nonce already consumed')
    for namespace in ROOT.joinpath('output').glob('*nonce-claims'):
        require(not (namespace / (nonce + '.json')).exists() and
                not (namespace / (nonce + '.json')).is_symlink(), 'Nonce already consumed')
    claims = safe_path(CLAIMS)
    claims.mkdir(mode=0o700, parents=True, exist_ok=True)
    record = dict(schema='camera-readonly-identity-reservation/1', context=bound,
                  asset_reference=prepared.reference, evidence=str(folder), approval=approval,
                  automatic_retry=False)
    claim = claims / (nonce + '.json')
    durable_new(claim, record)
    return dict(record=record, claim=dict(path=str(claim), sha256=sha(claim.read_bytes())))


class IdentityChannel(BootstrapChannel):
    """Bounded protocol only, never authenticates, resets, STOPs or discovers."""
    def __init__(self, device, nonce, clock=time.monotonic):
        valid_nonce(nonce.hex())
        super().__init__(device, nonce, clock)
        self.directory = '/tmp_wbshd/roid_' + nonce.hex()
        self.start_attempted = False
        self.context_guard = None

    def _packet(self, *args, **kwargs):
        require(callable(self.context_guard), 'Host context guard required before every packet')
        self.context_guard()
        return super()._packet(*args, **kwargs)

    def assert_job_absent(self):
        path = '/tmp/jiritsu/../..' + self.directory
        require(self._packet(15, b'\0' + path.encode('ascii') + b'\0', 0) == b'', 'Select failed')
        require(self._packet(17, b'\0\xff\0', 1, True) is None, 'Nonce job already exists')

    def read(self, name, missing=False):
        limits = dict(launch=104, ready=128, result=200000, exec_failure=8)
        require(name in limits, 'Fixed RO job publications only')
        self._select(name)
        return self._packet(17, b'\0\xff\0', limits[name], missing)

    def write_control(self, name, data):
        raise ValueError('Only the bound one-shot RO START method is allowed')

    def start_once(self, evidence):
        require(not self.start_attempted and self.healthy, 'START already attempted or channel unknown')
        self.start_attempted = True
        durable_new(safe_path(evidence) / 'start-attempt.json', dict(nonce=self.nonce.hex(), automatic_retry=False))
        self._select('start')
        frame = b'ROSTART1' + self.nonce + struct.pack('<Q', 1)
        require(self._packet(16, b'\0\xff\0' + frame, 0) == b'', 'START response differs')


def validate_launch(raw, nonce):
    require(type(raw) is bytes and len(raw) == 104, 'Exact bootstrap launch required')
    loader = validate_bootstrap_launch(raw, nonce)
    available = struct.unpack_from('<q', raw, 96)[0]
    require(loader <= 0x7fffffff and available >= 8 * 1024 * 1024,
            'Bounded loader PID and reviewed tmpfs capacity required')
    return loader


def validate_ready(raw, nonce):
    valid_nonce(nonce)
    require(type(raw) is bytes and len(raw) == HEADER.size, 'Exact 128-byte ready required')
    require(HEADER.unpack(raw) == (b'ROID0001', bytes.fromhex(nonce), 1, 1, 0, 0, 0, 0,
                                  bytes(36), bytes(36)), 'Ready schema/nonce/status differs')


def decode_result(raw, reference):
    contract = safe_path(Path(reference['kit_dir']) / 'contract.py').read_bytes()
    require(sha(contract) == reference['contract_sha256'], 'Bound decoder changed')
    namespace = {}
    exec(compile(contract, '<pinned readonly contract>', 'exec'), namespace)
    return namespace['decode'](raw, reference['nonce'])


def validate_receipt(receipt, operation):
    require(type(receipt) is dict and receipt.get('schema') == 'camera-readonly-identity-receipt/1'
            and receipt.get('state') == OBSERVED and receipt.get('operation') == operation
            and receipt.get('scope') == SCOPE and receipt.get('automatic_retry') is False
            and receipt.get('full_image_admission') is False
            and receipt.get('identity_admission') is False and receipt.get('firmware_admission') is False,
            'Bound observation-only receipt required')
    require(receipt.get('source_is_hardware') is (operation['context']['origin'] == 'HARDWARE'),
            'Receipt cannot assert a different origin')
    reference = operation['asset_reference']
    pubs = receipt['raw_publications']
    require(set(pubs) == {'launch', 'ready', 'result'}, 'Full raw handshake required')
    raws = {}
    for name, item in pubs.items():
        raw, _ = read_json(item['path'])
        require(sha(raw) == item['sha256'], 'Raw publication changed')
        value = json.loads(raw)
        require(set(value) == {'raw_hex', 'bytes'} and type(value['bytes']) is int, 'Raw envelope differs')
        raws[name] = bytes.fromhex(value['raw_hex'])
        require(len(raws[name]) == value['bytes'], 'Raw length differs')
        require(safe_path(item['path']).parent == safe_path(operation['evidence']), 'Mixed evidence folders')
    validate_launch(raws['launch'], bytes.fromhex(reference['nonce']))
    validate_ready(raws['ready'], reference['nonce'])
    decoded = decode_result(raws['result'], reference)
    require(receipt.get('decoded') == decoded, 'Decoded observation differs')
    return receipt


def validate_journal_details(state, details, binding, history, session_dir):
    require(set(details) == ({'scope', 'operation'} if state != OBSERVED else
                            {'scope', 'operation', 'receipt'}), 'Exact RO journal details required')
    require(details['scope'] == SCOPE and type(details['operation']) is dict, 'RO scope required')
    operation = details['operation']
    require(set(operation) == {'context', 'asset_reference', 'evidence', 'approval_sha256', 'reservation_sha256', 'reservation'},
            'Exact RO operation binding required')
    context = operation['context']
    require(type(context) is dict and set(context) == {'scope', 'target_id', 'origin',
            'lease_identity', 'session_dir', 'journal_binding', 'initial_event_sha256'}
            and context['origin'] in ('SIMULATED', 'HARDWARE'), 'Exact RO source context required')
    require(context['scope'] == SCOPE and context['journal_binding'] == binding
            and context['session_dir'] == str(safe_path(session_dir))
            and context['initial_event_sha256'] == history[0]['event_sha256'], 'RO target/history binding differs')
    reference = operation['asset_reference']
    valid_nonce(reference['nonce'])
    require(reference['nonce'] == NONCE and reference['scope'] == SCOPE
            and reference['freeze_sha256'] == FREEZE_SHA256 and reference['worker_sha256'] == WORKER_SHA256
            and reference['module_sha256'] == MODULE_SHA256
            and reference['contract_sha256'] == '2fdcb6bd741970d5c86f6c93867393b085cc14b10f50c8dd4fb8ee286ee12c7e'
            and reference['host_sha256'] == sha(Path(__file__).read_bytes())
            and reference['host_sources'] == host_source_bindings(),
            'RO artifact binding differs')
    reservation = operation['reservation']
    record = reservation['record']
    claim_raw, claimed = read_json(reservation['claim']['path'])
    require(safe_path(reservation['claim']['path']) == safe_path(CLAIMS / (NONCE + '.json'))
            and sha(claim_raw) == reservation['claim']['sha256'] and claimed == record
            and record['context'] == context and record['asset_reference'] == reference
            and record['evidence'] == operation['evidence'] and record['automatic_retry'] is False
            and operation['reservation_sha256'] == sha(canonical(reservation))
            and operation['approval_sha256'] == sha(canonical(record['approval'])),
            'RO reservation/approval changed')
    prepared = Prepared(None, canonical(reference), b'', b'')
    validate_approval(record['approval'], prepared, context)
    for field in ('approval_sha256', 'reservation_sha256'):
        require(type(operation[field]) is str and re.fullmatch('[0-9a-f]{64}', operation[field]), 'Invalid RO SHA256')
    if state != MAY:
        require(operation == history[-1]['details']['operation'], 'RO operation changed')
    if state == OBSERVED:
        item = details['receipt']
        raw, receipt = read_json(item['path'])
        require(sha(raw) == item['sha256'] and safe_path(item['path']).parent == safe_path(operation['evidence']),
                'RO receipt reference changed')
        validate_receipt(receipt, operation)


def capture_authenticated(device, evidence, *, assets, reservation, lease, journal,
                          context, approval, channel, clock=time.monotonic, sleep=time.sleep):
    """Consume one approved reservation; caller supplies the authenticated channel.

    All reads and writes are guarded. No unknown operation is retried. Polling is
    bounded and repeats only a known missing publication, never a failed read.
    """
    bound = context_binding(context, device, lease, journal, ('PLANNED',))
    prepared = preflight_assets(assets)
    validate_approval(approval, prepared, bound)
    folder = safe_path(evidence)
    require(folder.is_dir() and not any(folder.iterdir()), 'Fresh evidence folder required')
    require(type(reservation) is dict and set(reservation) == {'record', 'claim'}, 'Exact reservation required')
    record = reservation['record']
    require(record == dict(schema='camera-readonly-identity-reservation/1', context=bound,
                           asset_reference=prepared.reference, evidence=str(folder), approval=approval,
                           automatic_retry=False), 'Reservation binding differs')
    claim = reservation['claim']
    require(safe_path(claim['path']) == safe_path(CLAIMS / (prepared.reference['nonce'] + '.json')),
            'Canonical nonce claim required')
    raw, reread = read_json(claim['path'])
    require(sha(raw) == claim['sha256'] and reread == record, 'Reservation changed')
    require(getattr(channel, 'device', None) is device and channel.nonce == bytes.fromhex(NONCE)
            and channel.directory == prepared.reference['job_dir'] and channel.healthy is True
            and channel.module_attempted is False and channel.start_attempted is False,
            'Fresh channel bound to authenticated device/job required')
    if context.origin == 'HARDWARE':
        require(type(channel) is IdentityChannel, 'Hardware requires reviewed bounded channel')
    operation = dict(context=bound, asset_reference=prepared.reference, evidence=str(folder),
                     approval_sha256=sha(canonical(approval)), reservation_sha256=sha(canonical(reservation)), reservation=reservation)
    def guard():
        require(context_binding(context, device, lease, journal, (MAY,)) == bound, 'Lease/history/target changed')
        require(journal.events[-1]['details']['operation'] == operation, 'RO operation changed')
    channel.context_guard = guard
    # No I/O (even loader reads) until durable global uncertainty exists.
    journal.advance(MAY, details=dict(scope=SCOPE, operation=operation))
    publications = {}
    sequence = 0
    def read(name, missing=False):
        nonlocal sequence
        guard()
        value = channel.read(name, missing=missing)
        if value is not None:
            require(type(value) is bytes and len(value) <= dict(launch=104, ready=128, result=200000, exec_failure=8)[name],
                    'Publication byte bound exceeded')
            sequence += 1
            path = folder / f'{sequence:04d}-{name}-raw.json'
            # Persist every returned publication BEFORE parsing or interpreting it.
            durable_new(path, dict(raw_hex=value.hex(), bytes=len(value)))
            publications[name] = dict(path=str(path), sha256=sha(path.read_bytes()))
        return value
    def poll(name):
        deadline = clock() + 120
        for _ in range(1201):
            require(read('exec_failure', True) is None, 'Native exec failed')
            value = read(name, True)
            if value is not None:
                return value
            if name != 'result':
                require(read('result', True) is None, 'Terminal publication before handshake')
            require(clock() < deadline, 'Publication deadline expired')
            sleep(.1)
        raise TimeoutError('Publication poll count exhausted')
    try:
        guard(); channel.assert_job_absent()
        for path, expected in LIBRARIES.items():
            guard(); require(sha(channel.read_loader(path)) == expected, 'Original loader library changed')
        guard(); require(channel.read_loader(SLOT) is None, 'Fixed upload slot occupied')
        # The absent slot, exact fresh upload, and held lease jointly establish
        # cooperative ownership of the unchanged bootstrap's fixed cleanup.
        durable_new(folder / 'fixed-upload-ownership.json', dict(operation=operation,
                    path=SLOT, observed_absent_before_upload=True, module_sha256=MODULE_SHA256))
        require(preflight_assets(assets) == prepared, 'Assets changed before upload')
        guard(); channel.upload_once(prepared.module, MODULE_SHA256, folder / 'upload-attempt.json')
        validate_launch(poll('launch'), bytes.fromhex(NONCE))
        validate_ready(poll('ready'), NONCE)
        require(read('result', True) is None, 'Result present before START')
        guard(); channel.start_once(folder)
        raw = poll('result')
        decoded = decode_result(raw, prepared.reference)
        guard(); require(channel.read_loader(SLOT) is None, 'Exact upload cleanup unconfirmed')
        receipt = dict(schema='camera-readonly-identity-receipt/1', state=OBSERVED, scope=SCOPE,
                       operation=operation, raw_publications=publications, decoded=decoded,
                       source_is_hardware=context.origin == 'HARDWARE', automatic_retry=False,
                       full_image_admission=False, identity_admission=False, firmware_admission=False)
        validate_receipt(receipt, operation)
        path = folder / 'readonly-identity-receipt.json'
        durable_new(path, receipt)
        guard()
        journal.advance(OBSERVED, details=dict(scope=SCOPE, operation=operation,
                        receipt=dict(path=str(path), sha256=sha(path.read_bytes()))))
        return receipt
    except BaseException:
        channel.healthy = False
        # Failure to persist UNKNOWN leaves durable MAY (or damaged event), both
        # of which block every participating tool. Never clear or replay either.
        if journal.state == MAY:
            journal.advance(UNKNOWN, details=dict(scope=SCOPE, operation=operation))
        raise
