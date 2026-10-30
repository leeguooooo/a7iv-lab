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
from camera_stream_channel import StreamFileChannel
from camera_stream_execution import BootstrapChannel, LIBRARIES, SLOT, durable_new, validate_launch as validate_bootstrap_launch

ROOT = Path(__file__).resolve().parent
CLAIMS = ROOT / 'output/readonly-identity-nonce-claims'
FREEZE_SHA256 = 'fa05555e4e8aef36b6c36fb7509bad9aa5831d0e92caba34470c46a0aaba9410'
NONCE = '957ba14fe2d99b34871ae4f436d92d96'
WORKER_SHA256 = '847bf052ef5c4916d71ea9e78f3e61818d2d11725321ecf249882b1baa6a33a7'
MODULE_SHA256 = 'e2971269981e5d69a8dd754f0c52cb16eb19f23b457fae625498836fcb7afc2a'
HISTORICAL_DECODERS = {'ro-identity-v1': '2fdcb6bd741970d5c86f6c93867393b085cc14b10f50c8dd4fb8ee286ee12c7e'}
HEADER = struct.Struct('<8s16sIIqqII36s36s')
HOST_SOURCES = ('camera_readonly_identity.py', 'camera_device_lease.py', 'camera_install_journal.py',
                'camera_install_patch_session.py', 'camera_operation_guard.py',
                'camera_stream_execution.py', 'camera_stream_channel.py', 'camera_stream_senser.py',
                'camera_stream_transport_bounds.py', 'camera_stream_receiver.py')
SCOPE = 'RO_METADATA'
MAY = 'RO_METADATA_MAY_BE_ACTIVE'
OBSERVED = 'RO_METADATA_OBSERVED'
UNKNOWN = 'RO_METADATA_UNKNOWN'
# Version-1 replay semantics are append-only; current profiles may evolve.
HISTORICAL_CAPTURE_WRITES_V1 = ('owned fixed upload /tmp/jiritsu/libJit.so and bootstrap cleanup',
                   'nonce job directory, worker, launch, conditional exec_failure',
                   'ready.pending -> ready, start token consumed, result.pending -> result')
EXPECTED_WRITES = HISTORICAL_CAPTURE_WRITES_V1


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
    must bind this particular authenticated object and target on every guard.
    The callback must also establish exclusive device operation ownership for
    the fixed bootstrap cleanup; the host lease alone is only cooperative. It
    remains an assertion by the caller, not cryptographic hardware attestation.
    This MUST be a pure cached authority check, with no device I/O, discovery,
    authentication or SDK calls: it also runs before the durable MAY boundary.
    The host can enforce MAY-before-I/O only for its own IdentityChannel calls.
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


def validate_historical_approval_v1(approval, reference, context):
    """Trusted frozen schema-1 approval parser, independent of current policy."""
    stable = {key: value for key, value in context.items() if key != 'lease_identity'}
    expected = dict(scope='RO_METADATA', context=stable, asset_reference=reference,
                    attempts=1, automatic_retry=False, expected_writes=list(HISTORICAL_CAPTURE_WRITES_V1),
                    flash_authorized=False, RAM_patch_authorized=False, installation_authorized=False)
    require(type(approval) is dict and set(approval) == {'operator', 'explicit_approval', 'binding'}
            and type(approval['operator']) is str and 0 < len(approval['operator'].strip()) <= 120
            and approval['explicit_approval'] is True and approval['binding'] == expected,
            'Historical v1 approval scope or binding differs')


def seal_history(prepared, path):
    """Preserve review bytes; hashes give integrity, never physical authenticity."""
    reference = prepared.reference
    blobs = {'host/' + name: safe_path(ROOT / name).read_bytes().hex()
             for name in reference['host_sources']}
    for key, name in (('contract', 'contract.py'), ('freeze', 'freeze.json'),
                      ('manifest', 'canonical/manifest.json')):
        blobs[key] = safe_path(Path(reference['kit_dir']) / name).read_bytes().hex()
    snapshot = dict(schema='camera-readonly-identity-history/1', decoder='ro-identity-v1',
                    asset_reference=reference, blobs=blobs)
    durable_new(path, snapshot)
    path.chmod(0o400)
    item = dict(path=str(path), sha256=sha(path.read_bytes()))
    validate_history(item, reference)
    return item


def validate_history(item, reference):
    """Replay a sealed historical review without consulting live source/profile.

    This is a versioned ABI validator. Future profiles add decoder versions;
    existing versions and their meanings must remain supported.
    """
    raw, snapshot = read_json(item['path'])
    require(sha(raw) == item['sha256'] and snapshot['schema'] == 'camera-readonly-identity-history/1'
            and snapshot['asset_reference'] == reference, 'Historical snapshot changed')
    blobs = {key: bytes.fromhex(value) for key, value in snapshot['blobs'].items()}
    require(set(blobs) == {'host/' + name for name in reference['host_sources']} |
            {'contract', 'freeze', 'manifest'}, 'Historical source closure differs')
    require(sha(blobs['contract']) == reference['contract_sha256'] ==
            HISTORICAL_DECODERS.get(snapshot['decoder']), 'Unsupported historical decoder')
    require(sha(blobs['freeze']) == reference['freeze_sha256'] and
            sha(blobs['manifest']) == reference['manifest_sha256'], 'Historical review manifest changed')
    freeze, manifest = json.loads(blobs['freeze']), json.loads(blobs['manifest'])
    require(freeze['schema'] == 'readonly-runtime-identity-freeze/1'
            and manifest['schema'] == 'readonly-runtime-identity-offline/1'
            and manifest['scope'] == reference['scope'] == 'RO_METADATA'
            and manifest['nonce'] == reference['nonce']
            and manifest['job_dir'] == reference['job_dir'] == '/tmp_wbshd/roid_' + reference['nonce']
            and manifest['worker_sha256'] == reference['worker_sha256']
            and manifest['bootstrap_sha256'] == reference['module_sha256']
            and manifest['sources']['contract.py'] == reference['contract_sha256'],
            'Historical artifact bindings differ')
    for name, expected in (('canonical/manifest.json', reference['manifest_sha256']),
                           ('canonical/worker.elf', reference['worker_sha256']),
                           ('canonical/libJit.so', reference['module_sha256']),
                           ('contract.py', reference['contract_sha256'])):
        require(freeze['files'][name]['sha256'] == expected, 'Historical freeze bindings differ')
    require(reference['host_sources'].get('camera_readonly_identity.py') == reference['host_sha256'],
            'Historical host binding differs')
    for name, expected in reference['host_sources'].items():
        require(sha(blobs['host/' + name]) == expected, 'Historical host source changed')
    return blobs['contract']


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
    snapshot = seal_history(prepared, claims / (nonce + '.snapshot.json'))
    record = dict(schema='camera-readonly-identity-reservation/1', historical_snapshot=snapshot, context=bound,
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


def decode_result(raw, reference, *, historical_contract=None):
    contract = (safe_path(Path(reference['kit_dir']) / 'contract.py').read_bytes()
                if historical_contract is None else historical_contract)
    require(sha(contract) == reference['contract_sha256'] and
            sha(contract) in HISTORICAL_DECODERS.values(), 'Known reviewed decoder required')
    namespace = {}
    exec(compile(contract, '<pinned readonly contract>', 'exec'), namespace)
    return namespace['decode'](raw, reference['nonce'])


def historical_lifecycle_v1(launch, ready, nonce):
    """Stable schema-1 parser; current profile constants do not define history."""
    valid_nonce(nonce)
    require(type(launch) is bytes and len(launch) == 104, 'Historical launch length differs')
    values = struct.Struct('<8s16s10q').unpack(launch)
    require(values[:6] == (b'M4BOOT01', bytes.fromhex(nonce), 1, 3, 0, 0)
            and 1 < values[6] <= 0x7fffffff and values[7] == 0
            and values[8] > 0 and values[8] == values[9] and values[10] == 0
            and values[11] >= 8 * 1024 * 1024, 'Historical launch rejected')
    header = struct.Struct('<8s16sIIqqII36s36s')
    require(type(ready) is bytes and len(ready) == header.size and
            header.unpack(ready) == (b'ROID0001', bytes.fromhex(nonce), 1, 1, 0, 0, 0, 0,
                                     bytes(36), bytes(36)), 'Historical ready rejected')


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
    observation = receipt.get('terminal_observation')
    raw_folder = operation['evidence']
    if observation is not None:
        validate_terminal_observation(observation, operation)
        raw_folder = observation['evidence']
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
        require(safe_path(item['path']).parent == safe_path(raw_folder), 'Mixed evidence folders')
    historical_lifecycle_v1(raws['launch'], raws['ready'], reference['nonce'])
    contract = validate_history(operation['reservation']['record']['historical_snapshot'], reference)
    decoded = decode_result(raws['result'], reference, historical_contract=contract)
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
    require(reference['scope'] == 'RO_METADATA', 'Historical RO scope required')
    reservation = operation['reservation']
    record = reservation['record']
    claim_raw, claimed = read_json(reservation['claim']['path'])
    validate_history(record['historical_snapshot'], reference)
    require(safe_path(reservation['claim']['path']).name == reference['nonce'] + '.json'
            and sha(claim_raw) == reservation['claim']['sha256'] and claimed == record
            and record['context'] == context and record['asset_reference'] == reference
            and record['evidence'] == operation['evidence'] and record['automatic_retry'] is False
            and operation['reservation_sha256'] == sha(canonical(reservation))
            and operation['approval_sha256'] == sha(canonical(record['approval'])),
            'RO reservation/approval changed')
    validate_historical_approval_v1(record['approval'], reference, context)
    for field in ('approval_sha256', 'reservation_sha256'):
        require(type(operation[field]) is str and re.fullmatch('[0-9a-f]{64}', operation[field]), 'Invalid RO SHA256')
    if state != MAY:
        require(operation == history[-1]['details']['operation'], 'RO operation changed')
    if state == OBSERVED:
        item = details['receipt']
        raw, receipt = read_json(item['path'])
        require(sha(raw) == item['sha256'] and safe_path(item['path']).parent ==
                safe_path(receipt.get('terminal_observation', {}).get('evidence', operation['evidence'])),
                'RO receipt reference changed')
        if history[-1]['state'] == UNKNOWN:
            require(receipt.get('terminal_observation', {}).get('unknown_event_sha256') ==
                    history[-1]['event_sha256'], 'Late observation must bind exact UNKNOWN event')
        else:
            require('terminal_observation' not in receipt, 'Initial capture cannot use late observation')
        validate_receipt(receipt, operation)


def capture_authenticated(device, evidence, *, assets, reservation, lease, journal,
                          context, approval, channel, clock=time.monotonic, sleep=time.sleep):
    """Consume one approved reservation; caller supplies the authenticated channel.

    All reads and writes are guarded. No unknown operation is retried. Polling is
    bounded and repeats only a known missing publication, never a failed read.
    """
    bound = context_binding(context, device, lease, journal, ('PLANNED',))
    if context.origin == 'SIMULATED':
        require(not isinstance(channel, StreamFileChannel),
                'Physical transport cannot be classified as a simulated model')
    prepared = preflight_assets(assets)
    validate_approval(approval, prepared, bound)
    folder = safe_path(evidence)
    require(folder.is_dir() and not any(folder.iterdir()), 'Fresh evidence folder required')
    require(type(reservation) is dict and set(reservation) == {'record', 'claim'}, 'Exact reservation required')
    record = reservation['record']
    require(record == dict(schema='camera-readonly-identity-reservation/1', historical_snapshot=record.get('historical_snapshot'), context=bound,
                           asset_reference=prepared.reference, evidence=str(folder), approval=approval,
                           automatic_retry=False), 'Reservation binding differs')
    validate_history(record['historical_snapshot'], prepared.reference)
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


class TerminalObservationChannel(IdentityChannel):
    """Read the old job's terminal publications only; no executable upload path."""
    def read(self, name, missing=False):
        require(name in ('launch', 'ready', 'result'), 'Existing terminal publications only')
        return super().read(name, missing=missing)

    def read_loader(self, path):
        require(path == SLOT, 'Only observe the fixed upload slot')
        return super().read_loader(path)

    def upload_once(self, *args, **kwargs):
        raise ValueError('Late observer cannot upload or execute')

    def start_once(self, *args, **kwargs):
        raise ValueError('Late observer cannot START')

    def assert_job_absent(self):
        raise ValueError('Late observer reads an existing job only')


def terminal_observation_payload(journal, context, evidence, observation_nonce):
    """Review data for a new one-shot read; never reuses capture authorization."""
    valid_nonce(observation_nonce)
    require(journal.state == UNKNOWN, 'Only an existing UNKNOWN RO job may be observed')
    operation = journal.events[-1]['details']['operation']
    original = operation['context']
    require(isinstance(context, CaptureContext) and context.target_id == original['target_id']
            and context.origin == original['origin'], 'Original target and source classification required')
    require(observation_nonce != operation['asset_reference']['nonce'], 'Separate observation attempt nonce required')
    return dict(scope='RO_METADATA_EXISTING_TERMINAL_ONLY', observation_nonce=observation_nonce,
                unknown_event_sha256=journal.events[-1]['event_sha256'], operation_sha256=sha(canonical(operation)),
                target_id=context.target_id, origin=context.origin, evidence=str(safe_path(evidence)),
                host_sources=host_source_bindings(), attempts=1, automatic_retry=False,
                allowed_reads=[operation['asset_reference']['job_dir'] + '/' + name
                               for name in ('launch', 'ready', 'result')] + [SLOT],
                upload_authorized=False, START_authorized=False, installation_authorized=False)


def validate_terminal_observation(observation, operation):
    require(set(observation) == {'schema', 'evidence', 'unknown_event_sha256', 'context',
            'approval', 'attempt_reference', 'source_reference', 'slot_reference'}, 'Exact terminal observer envelope required')
    require(observation['schema'] == 'camera-readonly-identity-terminal-observation/1', 'Unknown observer schema')
    original = operation['context']
    observed = observation['context']
    require({key: value for key, value in observed.items() if key != 'lease_identity'} ==
            {key: value for key, value in original.items() if key != 'lease_identity'},
            'Terminal observer changed original target/source/history')
    approval = observation['approval']
    require(set(approval) == {'operator', 'explicit_approval', 'binding'} and
            type(approval['operator']) is str and 0 < len(approval['operator'].strip()) <= 120
            and approval['explicit_approval'] is True, 'Separate explicit observation approval required')
    binding = approval['binding']
    valid_nonce(binding['observation_nonce'])
    expected_reads = [operation['asset_reference']['job_dir'] + '/' + name
                      for name in ('launch', 'ready', 'result')] + ['/tmp/jiritsu/libJit.so']
    require(binding == dict(scope='RO_METADATA_EXISTING_TERMINAL_ONLY',
            observation_nonce=binding['observation_nonce'], unknown_event_sha256=observation['unknown_event_sha256'],
            operation_sha256=sha(canonical(operation)), target_id=original['target_id'], origin=original['origin'],
            evidence=observation['evidence'], host_sources=binding['host_sources'], attempts=1,
            automatic_retry=False, allowed_reads=expected_reads, upload_authorized=False,
            START_authorized=False, installation_authorized=False), 'Observer approval binding differs')
    source = observation['source_reference']
    raw, sources = read_json(source['path'])
    require(sha(raw) == source['sha256'] and safe_path(source['path']).parent == safe_path(observation['evidence'])
            and set(sources) == set(binding['host_sources']) and
            all(sha(bytes.fromhex(value)) == binding['host_sources'][name] for name, value in sources.items()),
            'Sealed observer source closure changed')
    slot = observation['slot_reference']
    raw, value = read_json(slot['path'])
    require(sha(raw) == slot['sha256'] and safe_path(slot['path']).parent == safe_path(observation['evidence'])
            and value == dict(path='/tmp/jiritsu/libJit.so', absent=True, raw_hex=None),
            'Terminal slot absence observation differs')
    attempt = observation['attempt_reference']
    raw, intent = read_json(attempt['path'])
    require(sha(raw) == attempt['sha256'] and intent == dict(schema='camera-readonly-terminal-attempt/1',
            context=observed, approval=approval, source_reference=source, automatic_retry=False),
            'One-shot observation intent changed')


def observe_existing_terminal_authenticated(device, evidence, *, lease, journal, context, approval,
                                             observation_nonce, channel):
    """One separately approved read attempt; never uploads, STARTs or cleans up.

    A new approval/attempt nonce is required for any later observation. Replaying
    an attempt is forbidden, including after missing or uncertain reads. Neither
    elapsed time nor lease closure nor a healthy camera closes UNKNOWN.
    """
    bound = context_binding(context, device, lease, journal, (UNKNOWN,))
    operation = journal.events[-1]['details']['operation']
    unknown_event = journal.events[-1]['event_sha256']
    expected = terminal_observation_payload(journal, context, evidence, observation_nonce)
    require(type(approval) is dict and set(approval) == {'operator', 'explicit_approval', 'binding'}
            and type(approval['operator']) is str and 0 < len(approval['operator'].strip()) <= 120
            and approval['explicit_approval'] is True and approval['binding'] == expected,
            'Fresh exact terminal-observation approval required')
    original = operation['context']
    require({key: value for key, value in bound.items() if key != 'lease_identity'} ==
            {key: value for key, value in original.items() if key != 'lease_identity'},
            'Same original target/source/history required')
    if context.origin == 'SIMULATED':
        require(not isinstance(channel, StreamFileChannel), 'Physical transport cannot be classified as a simulated model')
    else:
        require(type(channel) is TerminalObservationChannel, 'Exact read-only terminal channel required')
    nonce = operation['asset_reference']['nonce']
    require(getattr(channel, 'device', None) is device and channel.nonce == bytes.fromhex(nonce)
            and channel.directory == operation['asset_reference']['job_dir'] and channel.healthy is True,
            'Channel must bind the original job and authenticated device')
    folder = safe_path(evidence)
    require(folder.is_dir() and not any(folder.iterdir()), 'Fresh observation evidence folder required')
    contract = validate_history(operation['reservation']['record']['historical_snapshot'], operation['asset_reference'])
    def guard():
        require(context_binding(context, device, lease, journal, (UNKNOWN,)) == bound
                and journal.events[-1]['event_sha256'] == unknown_event
                and host_source_bindings() == expected['host_sources'], 'Observer lease/history/source changed')
    channel.context_guard = guard
    sources = folder / 'observer-sources.json'
    durable_new(sources, {name: safe_path(ROOT / name).read_bytes().hex() for name in expected['host_sources']})
    source_reference = dict(path=str(sources), sha256=sha(sources.read_bytes()))
    # A consumed attempt remains consumed even if the first read is missing or unknown.
    claim_root = safe_path(Path(operation['reservation']['claim']['path']).parent)
    attempt_path = claim_root / (nonce + '.terminal-' + observation_nonce + '.json')
    durable_new(attempt_path, dict(schema='camera-readonly-terminal-attempt/1', context=bound,
                approval=approval, source_reference=source_reference, automatic_retry=False))
    observation = dict(schema='camera-readonly-identity-terminal-observation/1', evidence=str(folder),
            unknown_event_sha256=unknown_event, context=bound, approval=approval,
            source_reference=source_reference,
            attempt_reference=dict(path=str(attempt_path), sha256=sha(attempt_path.read_bytes())))
    try:
        raws, publications = {}, {}
        for name, maximum in (('launch', 104), ('ready', 128), ('result', 200000)):
            guard()
            raw = channel.read(name, missing=True)
            if raw is None:
                raise ValueError('Existing terminal publication missing; UNKNOWN remains')
            require(type(raw) is bytes and len(raw) <= maximum, 'Bounded terminal publication required')
            path = folder / (name + '-raw.json')
            durable_new(path, dict(raw_hex=raw.hex(), bytes=len(raw)))
            publications[name] = dict(path=str(path), sha256=sha(path.read_bytes()))
            raws[name] = raw
        guard()
        slot = channel.read_loader(SLOT)
        require(slot is None or (type(slot) is bytes and len(slot) <= 65520), 'Bounded slot observation required')
        slot_path = folder / 'slot-observation.json'
        durable_new(slot_path, dict(path=SLOT, absent=slot is None, raw_hex=None if slot is None else slot.hex()))
        observation['slot_reference'] = dict(path=str(slot_path), sha256=sha(slot_path.read_bytes()))
        require(slot is None, 'Fixed upload slot cleanup remains unconfirmed')
        historical_lifecycle_v1(raws['launch'], raws['ready'], nonce)
        decoded = decode_result(raws['result'], operation['asset_reference'], historical_contract=contract)
        receipt = dict(schema='camera-readonly-identity-receipt/1', state=OBSERVED, scope=SCOPE,
                operation=operation, terminal_observation=observation, raw_publications=publications,
                decoded=decoded, source_is_hardware=context.origin == 'HARDWARE', automatic_retry=False,
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
        raise
