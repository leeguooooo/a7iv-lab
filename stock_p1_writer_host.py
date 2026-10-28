"""One fixed P1 transaction on an injected, already authenticated device.

No USB discovery, reset, service entry/exit, retry, host rollback or run CLI.
Physical use requires separate explicit write approval and same-body preflight.
Local nonce claims prevent accidental replay, not deliberate deletion by an owner.
"""
import hashlib
import json
from pathlib import Path
import struct
import time

from camera_stream_execution import BootstrapChannel, LIBRARIES, SLOT, LAUNCH, validate_launch, durable_new
from stock_p1_write_outcome import Proposal, FRAME, FIELDS, classify
from stock_p1_writer_boundary import WriterTerminalBoundary
from stock_p1_readback import execute_after_writer_authenticated, GLOBAL_ATTEMPT as READBACK_ATTEMPT
from stock_p1_writer_plan import JOB, MODULE_SHA, SOURCE_SHA, TARGET_SHA, validate
from stock_p1_readback_plan import checked_bytes, require
from stock_p1_readback_plan import NONCE as READBACK_NONCE

GLOBAL_ATTEMPT = JOB.parent / 'fixed-writer-attempt.json'


def unpack(raw, proposal):
    require(isinstance(raw, bytes) and len(raw) == FRAME.size, 'Complete writer record required')
    magic, nonce, *values = FRAME.unpack(raw)
    require(magic == b'M4P1WR01' and nonce == proposal.nonce and values[0] == 1,
            'Writer record identity differs')
    return dict(zip(FIELDS, values[:15])) | {'before_sha256': values[15].hex(), 'after_sha256': values[16].hex()}


class WriterChannel(BootstrapChannel):
    def __init__(self, device, manifest, clock=time.monotonic):
        super().__init__(device, bytes.fromhex(manifest['nonce']), clock)
        self.directory = '/tmp_wbshd/m4p1_' + self.nonce.hex()
        require(self.directory == manifest['job_dir'] and manifest['source_sha256'] == SOURCE_SHA
                and manifest['target_sha256'] == TARGET_SHA and len(manifest['windows']) == 550,
                'Fixed writer manifest required')
        self.manifest = manifest
        self.stages = ('table', *(r['name'] for r in manifest['windows']))
        self.stage_index = 0
        self.written = set()
        self.prepared = False
        self.commit_attempted = False

    def read(self, name, missing=False):
        limits = {'launch': LAUNCH.size, 'ready': FRAME.size, 'prepared': FRAME.size,
                  'intent': FRAME.size, 'result': FRAME.size, 'exec_failure': 8}
        require(name in limits, 'Only fixed writer records may be read')
        self._select(name)
        return self._packet(17, b'\0\xff\0', limits[name], missing)

    def _write_once(self, name, raw):
        if name in self.written:
            raise RuntimeError('Writer file already attempted; no replay')
        self.written.add(name)  # Reserve before even SELECT, not after a reply.
        self._select(name)
        if self._packet(16, b'\0\xff\0' + raw, 0) != b'':
            self.healthy = False
            raise ValueError('Writer upload response changed')

    def stage_next(self):
        require(self.stage_index < len(self.stages), 'All staging already attempted')
        name = self.stages[self.stage_index]
        if name == 'table':
            digest = self.manifest['table_sha256']
        else:
            digest = self.manifest['windows'][self.stage_index - 1]['packet_sha256']
        raw = checked_bytes(JOB / 'assets' / name, digest)
        self._write_once(name, raw)
        self.stage_index += 1

    def token(self, name):
        require(name in ('prepare', 'commit') and self.stage_index == len(self.stages),
                'Complete staging and fixed control name required')
        require(name != 'commit' or self.prepared, 'Verified PREPARED required before COMMIT')
        magic = b'M4PREP01' if name == 'prepare' else b'M4COMMIT'
        raw = magic + self.nonce + bytes.fromhex(self.manifest['table_sha256']) + struct.pack('<Q', 1)
        if name == 'commit':
            self.commit_attempted = True
        self._write_once(name, raw)


def poll(channel, name, length, seconds, *, evidence, clock, sleep):
    deadline = clock() + seconds
    observations = 0
    def preserve(record_name, raw):
        nonlocal observations
        require(observations < 64, 'Too many partial native observations')
        durable_new(Path(evidence) / f'{name}-observation-{observations:03d}.json',
                    {'requested_record': name, 'received_record': record_name,
                     'bytes': len(raw), 'raw_hex': raw.hex()})
        observations += 1
    while clock() < deadline:
        raw = channel.read(name, missing=True)
        if raw is not None:
            preserve(name, raw)  # Preserve received bytes before any semantic rejection.
            require(len(raw) <= length, 'Oversized native writer record')
            if len(raw) == length:
                return raw
        failed = channel.read('exec_failure', missing=True)
        if failed is not None:
            preserve('exec_failure', failed)
            raise RuntimeError('Native writer exec failed')
        if name != 'result':
            final = channel.read('result', missing=True)
            if final is not None:
                preserve('result', final)
                raise RuntimeError('Native writer ended before requested phase')
        sleep(0.1)
    raise TimeoutError('Native writer deadline; never replay a control file')


def verify_prepared(raw, boundary):
    p = boundary.proposal
    s = unpack(raw, p)
    require((s['pid'], s['loader_pid']) == boundary.identity and s['phase'] == 3
            and s['euid'] == 0 and s['ppid'] == 1 and s['error'] == s['cleanup'] == s['io_status'] == 0
            and s['mode'] == p.mode and s['rows'] == p.rows and s['flags'] == 31
            and s['write_calls'] == s['write_bytes'] == s['rollback'] == 0
            and s['before_sha256'] == p.source_sha256 and s['after_sha256'] == bytes(32).hex(),
            'Native PREPARED identity/source/zero-write proof rejected')
    return s


def execute_writer_authenticated(device, evidence, *, write_authorized=False,
                                 same_body_verified=False, source_is_hardware=False,
                                 clock=time.monotonic, sleep=time.sleep):
    """Only a caller with explicit P1-write consent may set write_authorized.

    The real SDK wrapper must verify model/body before entering this callback.
    Any exception keeps the session open for manual review: caller MUST NOT
    send STOP/reset/reboot, retry COMMIT, or run a host rollback in a finally.
    """
    require(write_authorized is True and same_body_verified is True,
            'Explicit fixed P1 write approval and same-body verification required')
    require(type(source_is_hardware) is bool, 'Explicit source evidence kind required')
    m, module = validate()  # All files and readback artifacts checked before any USB.
    require(not READBACK_ATTEMPT.exists(), 'Readback nonce already attempted; do not start writer')
    folder = Path(evidence)
    require(folder.is_dir() and not folder.is_symlink(), 'Fresh evidence directory required')
    reservation = {'nonce': m['nonce'], 'module_sha256': MODULE_SHA,
        'source_sha256': SOURCE_SHA, 'target_sha256': TARGET_SHA,
        'source_is_hardware': source_is_hardware, 'automatic_retry': False,
        'state': 'RESERVED_BEFORE_ANY_USB'}
    # One claim for this compiled nonce, including across alternate evidence folders.
    durable_new(GLOBAL_ATTEMPT, reservation)
    durable_new(folder / 'job-attempt.json', reservation)
    channel = WriterChannel(device, m, clock)
    proposal = Proposal(channel.nonce, 1, len(m['windows']), m['stage_bytes'] // 2, SOURCE_SHA, TARGET_SHA)
    stage = 'LOADER_CHECK'
    try:
        for path, digest in LIBRARIES.items():
            require(hashlib.sha256(channel.read_loader(path)).hexdigest() == digest, 'Loader library differs')
        require(channel.read_loader(SLOT) is None, 'Existing module slot must be preserved')
        stage = 'MODULE_UPLOAD'
        channel.upload_once(module, MODULE_SHA, folder / 'module-attempt.json')
        stage = 'LAUNCH_AND_READY'
        launch = poll(channel, 'launch', LAUNCH.size, 30, evidence=folder, clock=clock, sleep=sleep)
        loader = validate_launch(launch, channel.nonce)
        ready = poll(channel, 'ready', FRAME.size, 30, evidence=folder, clock=clock, sleep=sleep)
        require(unpack(ready, proposal)['loader_pid'] == loader, 'Ready/launch loader differs')
        boundary = WriterTerminalBoundary(proposal, channel, ready)
        durable_new(folder / 'ready.json', unpack(ready, proposal))
        stage = 'STAGING_ONLY_NO_COMMIT'
        deadline = clock() + 900
        while channel.stage_index < len(channel.stages):
            require(clock() < deadline, 'Staging budget exceeded before PREPARE')
            channel.stage_next()
        stage = 'PREPARE_ATTEMPT'
        channel.token('prepare')
        prepared = poll(channel, 'prepared', FRAME.size, 180, evidence=folder, clock=clock, sleep=sleep)
        stage = 'PREPARED_RECEIVED_UNVALIDATED'
        durable_new(folder / 'prepared.json', verify_prepared(prepared, boundary))
        channel.prepared = True
        # Fsync file AND parent before sending even SELECT for COMMIT.
        durable_new(folder / 'commit-intent.json', {'nonce': m['nonce'], 'table_sha256': m['table_sha256'],
            'state': 'COMMIT_MAY_BE_SENT_AFTER_THIS_RECORD', 'automatic_recommit': False})
        stage = 'COMMIT_MAY_HAVE_BEEN_SENT'
        channel.token('commit')
        final = poll(channel, 'result', FRAME.size, 180, evidence=folder, clock=clock, sleep=sleep)
        stage = 'NATIVE_FINAL_RECEIVED_UNVALIDATED'
        native_outcome = boundary.observe_final(final)
        durable_new(folder / 'native-final.json', unpack(final, proposal))
        durable_new(folder / 'native-outcome.json', native_outcome)
        stage = 'INDEPENDENT_READBACK'
        readback = folder / 'readback'
        readback.mkdir(mode=0o700)
        backup = execute_after_writer_authenticated(boundary, readback,
            source_is_hardware=source_is_hardware, clock=clock, sleep=sleep)
        completed = json.loads((readback / 'completed.json').read_text())
        capture = json.loads((readback / 'capture/status.json').read_text())
        native = completed['native']
        with Path(backup).open('rb') as f:
            observed = hashlib.file_digest(f, 'sha256').hexdigest()
        require(completed['partition'] == 'cnflasha1' and completed['bytes'] == 25100288
                and Path(backup).stat().st_size == 25100288 and capture['state'] == 'TWO_READS_MATCHED'
                and capture['sha256'] == observed and capture['source_is_hardware'] is source_is_hardware
                and capture['nonce'] == READBACK_NONCE,
                'Independent full P1 readback evidence differs')
        outcome = classify(proposal, final, {'bytes': 25100288, 'camera_body_matched': same_body_verified,
            'source_reads_equal': native['first_sha256'] == native['second_sha256'],
            'host_readback_verified': observed == capture['sha256'], 'reader_nonce': capture['nonce'],
            'first_sha256': native['first_sha256'], 'second_sha256': native['second_sha256'],
            'host_sha256': observed})
        durable_new(folder / 'reconciled-outcome.json', outcome | {'source_is_hardware': source_is_hardware})
        require(outcome['evidence_supports_session_end'], 'P1 outcome requires manual review; no service exit')
        return outcome
    except BaseException as error:
        channel.healthy = False
        durable_new(folder / 'stopped.json', {'stage': stage, 'error_type': type(error).__name__,
            'commit_attempted': channel.commit_attempted, 'automatic_retry': False,
            'automatic_host_rollback': False, 'automatic_service_exit': False,
            'automatic_camera_reboot': False, 'manual_review_required': True})
        raise
