"""Collect PRE_INSTALL runtime bytes in one explicitly authorized service session.

The technical post_p1 capture profile supplies fixed geometry, not an epoch.
No RAM patch, card rename, READY, FLASH or installation permission is provided.
"""
from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import time

import camera_install_runtime as runtime
import camera_install_runtime_metadata as metadata
import camera_postinstall_verify as postinstall
from camera_capture_session import read_pdt_bounded
from camera_device_lease import DEFAULT_LOCK
from camera_firmware_capture import checked_capture_assets, capture_one_authenticated, CLAIMS as CAPTURE_CLAIMS
from camera_install_journal import InstallJournal
from camera_install_patch_session import (SOURCE_ONLY_RUNTIME, _source_only_runtime, _held_lease,
    _safe_path, _json, _known_stop, canonical_sha256, review_source_paths as preparation_sources)
from camera_operation_guard import DEFAULT_SESSIONS, assert_operation_allowed
from camera_stream_execution import durable_new

ROOT = Path(__file__).resolve().parent
GLOBAL_SESSIONS = DEFAULT_SESSIONS
ATTEMPTS = ROOT / 'output/install-runtime-session-attempts'
SCOPE = 'INSTALL_PRE_RUNTIME_READ_ONLY'
REVIEW_SCHEMA = 'camera-install-runtime-session-plan/1'
ASSET_SCHEMA = 'camera-install-runtime-assets/1'
PDT_BYTES, P1_BYTES = runtime.PDT_BYTES, runtime.P1_BYTES
SHA = re.compile(r'[0-9a-f]{64}\Z')
FALSE_CLAIMS = ('installation_authorized', 'write_admission', 'READY', 'ready_for_confirmation',
    'hardware_admission_proven', 'firmware_installation_proven', 'restoration_proven',
    'package_requirements_proven', 'runtime_freshness_proven', 'post_installation_observed')
STATES = ('PLANNED', 'SD_STAGED')
REQUIRED_RUNTIME_SOURCES = frozenset((
    'ref/sony-a7m4-custom-firmware/a7m4/__init__.py',
    'ref/sony-a7m4-custom-firmware/a7m4/fat.py',
    'ref/sony-a7m4-custom-firmware/a7m4/common.py',
    'tools/fl23_prewrite_guard.py'))


def require(value, message):
    if not value:
        raise ValueError(message)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


@dataclass(frozen=True)
class RuntimeAssets:
    p1_directory: Path
    p1_manifest_sha256: str
    metadata_assets: metadata.MetadataAssets


@dataclass(frozen=True)
class PreparedRuntimeAssets:
    assets: RuntimeAssets
    reference_json: str
    manifest_json: str
    metadata_prepared: metadata.PreparedMetadataAssets

    @property
    def reference(self):
        return json.loads(self.reference_json)

    @property
    def manifest(self):
        return json.loads(self.manifest_json)


def _requirements(value):
    expected = {'nflasha' + str(n) for n in metadata.NUMBERS}
    require(isinstance(value, dict) and set(value) == expected
            and all(type(size) is int and 0 < size <= 0x7fffffffffffffff for size in value.values()),
            'Exact six positive canonical partition requirements required')
    return dict(value)


def _unused_capture(reference):
    nonce = reference['p1']['nonce']
    roots = ('firmware-file-capture-nonce-claims', 'install-volatile-patch-nonce-claims',
             'install-patch-read-nonce-claims', 'install-runtime-metadata-nonce-claims')
    for name in roots:
        path = (CAPTURE_CLAIMS if name == roots[0] else ROOT / 'output' / name) / (nonce + '.json')
        require(not path.exists() and not path.is_symlink(), 'P1 capture nonce already consumed')
    directory = Path(reference['p1']['directory']) / 'post_p1/bootstrap'
    for name in ('physical-attempt.json', 'host-entry-intent.json', 'claim.json', 'module-attempt.json'):
        require(not (directory / name).exists() and not (directory / name).is_symlink(), 'P1 capture job already attempted')


def preflight_assets(assets, *, owned_metadata_reservation=None):
    """Read local native closures and reject consumed jobs before authentication."""
    require(isinstance(assets, RuntimeAssets), 'Explicit reviewed RuntimeAssets required')
    require(type(assets.p1_manifest_sha256) is str and SHA.fullmatch(assets.p1_manifest_sha256),
            'Reviewed P1 bootstrap manifest SHA required')
    directory = _safe_path(assets.p1_directory, directory=True)
    require(directory.is_relative_to(ROOT / 'output'), 'Workspace P1 capture assets required')
    manifest_path = _safe_path(directory / 'post_p1/bootstrap/bootstrap.json')
    require(_sha(manifest_path.read_bytes()) == assets.p1_manifest_sha256, 'Reviewed P1 capture changed')
    capture = checked_capture_assets('post_p1', directory)
    p1 = dict(directory=str(directory), manifest_sha256=assets.p1_manifest_sha256,
              module_sha256=capture['module_sha256'], nonce=capture['nonce'].hex(),
              technical_profile='post_p1', source_path='/dev/cnflasha1', source_kind='BLOCK', minor=129, bytes=P1_BYTES)
    prepared_metadata = metadata.preflight_assets(assets.metadata_assets, owned_reservation=owned_metadata_reservation)
    require(capture['nonce'].hex() != prepared_metadata.reference['nonce'], 'Native runtime nonces must differ')
    _, production = _json(directory / 'post_p1/prod/job.json')
    sources = dict(production['sources'])
    for name, digest in prepared_metadata.manifest['sources'].items():
        require(name not in sources or sources[name] == digest, 'Native runtime source closures disagree')
        sources[name] = digest
    reference = dict(schema=ASSET_SCHEMA, p1=p1, metadata=prepared_metadata.reference)
    _unused_capture(reference)
    require(_sha(manifest_path.read_bytes()) == assets.p1_manifest_sha256, 'P1 capture manifest changed during preflight')
    return PreparedRuntimeAssets(assets, _canonical(reference), _canonical(dict(sources=sources)), prepared_metadata)


def review_source_paths(prepared):
    return tuple(sorted(set(preparation_sources(prepared)) | REQUIRED_RUNTIME_SOURCES | {
        'camera_install_runtime_session.py', 'camera_install_runtime_plan.py',
        'camera_install_runtime.py', 'camera_install_runtime_metadata.py'}))


def validate_review(path, review_sha256, prepared, body_sha256, plan_sha256, required_partition_sizes):
    required = _requirements(required_partition_sizes)
    raw, review = _json(path)
    require(_sha(raw) == review_sha256, 'Runtime review changed')
    require(review.get('schema') == REVIEW_SCHEMA and review.get('scope') == SCOPE
            and review.get('model') == 'ILCE-7M4' and review.get('body_sha256') == body_sha256
            and review.get('original_plan_sha256') == plan_sha256 and review.get('asset_reference') == prepared.reference
            and _requirements(review.get('required_partition_sizes')) == required
            and review.get('acquisition_phase') == 'PRE_INSTALL'
            and review.get('technical_p1_profile') == 'post_p1'
            and review.get('source_only_runtime') == SOURCE_ONLY_RUNTIME
            and all(type(review['source_only_runtime'].get(name)) is bool for name in
                    ('dont_write_bytecode', 'ignore_environment', 'no_user_site', 'prefix_must_not_exist'))
            and review.get('execution_approval_received') is False
            and type(review.get('hardware_operations')) is int and review['hardware_operations'] == 0
            and all(review.get(name) is False for name in FALSE_CLAIMS), 'Runtime review scope/body/assets differ')
    nonces = [review.get('group_nonce'), review.get('pdt_nonce'), prepared.reference['p1']['nonce'],
              prepared.reference['metadata']['nonce']]
    require(all(type(n) is str and re.fullmatch('[0-9a-f]{32}', n) and any(bytes.fromhex(n)) for n in nonces)
            and len(set(nonces)) == 4, 'Distinct runtime group/PDT/native nonces required')
    sources = review.get('sources')
    require(isinstance(sources, dict) and set(review_source_paths(prepared)).issubset(sources)
            and all(sources.get(name) == digest for name, digest in prepared.manifest['sources'].items()),
            'Complete runtime host/SDK/native source closure required')
    snapshots = Path(path).absolute().parent / 'sources'
    require(review.get('source_snapshot_directory') == str(snapshots), 'Bound runtime source snapshots required')
    _safe_path(snapshots, directory=True)
    for name, digest in sources.items():
        relative = Path(name)
        require(not relative.is_absolute() and '..' not in relative.parts and type(digest) is str
                and SHA.fullmatch(digest), 'Invalid runtime source binding')
        require(_sha(_safe_path(ROOT / name).read_bytes()) == digest, 'Runtime source changed: ' + name)
        require(_sha(_safe_path(snapshots / name).read_bytes()) == digest, 'Runtime snapshot changed: ' + name)
    return review, dict(path=str(Path(path).absolute()), sha256=review_sha256, payload_sha256=canonical_sha256(review))


def _context(lease, journal, binding, history, identity):
    require(_held_lease(lease) == identity, 'Runtime lease identity changed')
    current = InstallJournal.open(journal.session_dir)
    require(current.events == history == journal.events and current.state in STATES and current.binding == binding,
            'Runtime journal/history changed')


def _barrier(journal):
    assert_operation_allowed(journal, allowed_states=STATES)
    if journal.session_dir.parent.resolve() != Path(GLOBAL_SESSIONS).resolve():
        assert_operation_allowed(sessions_root=GLOBAL_SESSIONS)


class _PinnedDriver:
    """Delegate existing driver operations while retaining one lease/history pin."""
    def __init__(self, original, guard):
        self.original, self.guard, self.failed = original, guard, False

    def __getattr__(self, name):
        value = getattr(self.original, name)
        if not callable(value):
            return value
        def invoke(*args, **kwargs):
            require(not self.failed, 'Runtime driver already stopped')
            try:
                self.guard()
                return value(*args, **kwargs)
            except BaseException:
                self.failed = True
                raise
        return invoke


def _save_raw(path, raw):
    require(type(raw) is bytes, 'Raw runtime bytes required')
    with path.open('xb') as stream:
        os.fchmod(stream.fileno(), 0o600)
        require(stream.write(raw) == len(raw), 'Short local raw write')
        stream.flush();os.fsync(stream.fileno())
    require(path.read_bytes() == raw, 'Raw runtime host readback differs')
    fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return dict(path=path.name, bytes=len(raw), sha256=_sha(raw))


def _file_reference(folder, path):
    path = _safe_path(path)
    relative = path.relative_to(folder)
    with path.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    return dict(path=str(relative), bytes=path.stat().st_size, sha256=digest)


def _check_files(folder, references):
    for reference in references:
        require(_file_reference(folder, folder / reference['path']) == reference,
                'Collected runtime evidence changed: ' + reference['path'])


def run_runtime_session(expected_body_sha256, evidence, *, plan_sha256, review_path, review_sha256,
        journal, lease, assets, required_partition_sizes, runtime_read_authorized=False,
        run_session=None, capture_fn=None, pdt_reader=None, metadata_fn=None,
        preflight_fn=None, reserve_fn=None, clock=time.monotonic, sleep=time.sleep):
    folder = Path(evidence).absolute()
    stage, attempted, claims_attempted = 'LOCAL_PREFLIGHT', False, False
    installed = None
    try:
        require(runtime_read_authorized is True, 'Explicit pre-install runtime read consent required')
        callbacks = (run_session, capture_fn, pdt_reader, metadata_fn)
        injected = any(fn is not None for fn in callbacks)
        require(not injected or all(callable(fn) for fn in callbacks), 'All four transport callbacks must be injected or none')
        require(not (preflight_fn is not None or reserve_fn is not None) or injected,
                'Local test hooks require all four injected transport callbacks')
        require(preflight_fn is None or callable(preflight_fn), 'Callable local preflight required')
        require(reserve_fn is None or callable(reserve_fn), 'Callable local reservation required')
        require(all(type(value) is str and SHA.fullmatch(value) for value in (expected_body_sha256, plan_sha256)),
                'Bound body/original plan SHA required')
        required = _requirements(required_partition_sizes)
        identity = _held_lease(lease)
        require(isinstance(journal, InstallJournal), 'Original pre-RAM journal required')
        binding = dict(body_sha256=expected_body_sha256, plan_sha256=plan_sha256, model='ILCE-7M4')
        history = journal.events
        _context(lease, journal, binding, history, identity);_barrier(journal)
        if not injected:
            require(Path(lease.path).absolute() == DEFAULT_LOCK.absolute()
                    and journal.session_dir.parent.absolute() == DEFAULT_SESSIONS.absolute(), 'Canonical runtime lease/journal required')
            _safe_path(lease.path);_safe_path(journal.session_dir, directory=True);_source_only_runtime()
        folder = _safe_path(folder, directory=True)
        require(not any(folder.iterdir()), 'Fresh empty runtime group required')
        preflight = preflight_assets if preflight_fn is None else preflight_fn
        prepared = preflight(assets)
        review, review_ref = validate_review(review_path, review_sha256, prepared, expected_body_sha256, plan_sha256, required)
        def pin():
            _context(lease, journal, binding, history, identity)
        def guard():
            pin();_barrier(journal)
            require(validate_review(review_path, review_sha256, prepared, expected_body_sha256, plan_sha256, required)[1] == review_ref,
                    'Runtime review changed at collection boundary')
            if not injected:
                _source_only_runtime()
        guard()
        attempt = ATTEMPTS / (review_sha256 + '.json')
        require(all(not p.is_symlink() for p in (ATTEMPTS, *ATTEMPTS.parents))
                and not attempt.exists() and not attempt.is_symlink(), 'Runtime review already attempted')
        _unused_capture(prepared.reference)
        stage, claims_attempted = 'LOCAL_RUNTIME_RESERVATION', True
        ATTEMPTS.mkdir(mode=0o700, parents=True, exist_ok=True)
        durable_new(attempt, dict(scope=SCOPE, body_sha256=expected_body_sha256, plan_sha256=plan_sha256,
            runtime_review=review_ref, group_nonce=review['group_nonce'], evidence=str(folder), lease_identity=identity,
            journal_event_sha256=history[-1]['event_sha256'], automatic_retry=False))
        descriptor = dict(binding, schema='camera-capture-group/1', group_nonce=review['group_nonce'],
                          journal_session=str(journal.session_dir.absolute()), acquisition_phase='PRE_INSTALL', purpose=SCOPE)
        durable_new(folder / 'group.json', descriptor)
        evidence_files = [_file_reference(folder, folder / 'group.json')]
        metadata_folder = folder / 'runtime-metadata';metadata_folder.mkdir(mode=0o700)
        reserve = metadata.reserve_assets if reserve_fn is None else reserve_fn
        reservation = reserve(prepared.metadata_prepared, metadata_folder,
            lease=lease, journal=journal, body_sha256=expected_body_sha256, plan_sha256=plan_sha256)
        guard()
        rechecked = (preflight(assets) if preflight_fn is not None else
                     preflight_assets(assets, owned_metadata_reservation=reservation))
        require(rechecked == prepared, 'Runtime assets changed before authentication')
        _unused_capture(prepared.reference)
        _check_files(folder, evidence_files)
        if not injected:
            from camera_stream_usb_session import run_normal_session
            run_session, capture_fn, pdt_reader, metadata_fn = (run_normal_session, capture_one_authenticated,
                                                              read_pdt_bounded, metadata.capture_authenticated)
        events, terminal_ref, accepted, calls = [], None, None, 0
        def set_stage(value):
            nonlocal stage
            stage = value
        def work(device):
            nonlocal installed, terminal_ref, accepted, calls
            calls += 1
            require(calls == 1 and any(event.get('model') == 'ILCE-7M4' and event.get('body_matched') is True for event in events),
                    'One fresh same-body runtime callback required')
            guard()
            if hasattr(device, 'driver'):
                original = device.driver
                proxy = _PinnedDriver(original, pin)
                device.driver = proxy;installed = (device, original)
            else:
                require(injected, 'Actual service driver required')
            p1_folder = folder / 'runtime-pre-p1'
            p1_report = capture_fn(device, 'post_p1', p1_folder, source_is_hardware=not injected,
                                   assets=Path(prepared.reference['p1']['directory']),
                                   clock=clock, sleep=sleep)
            guard()
            require(type(p1_report) is dict and p1_report.get('nonce') == prepared.reference['p1']['nonce']
                    and p1_report.get('module_sha256') == prepared.reference['p1']['module_sha256'], 'Bound P1 native job required')
            report_path = p1_folder / 'firmware-capture.json'
            raw_report, persisted = _json(report_path)
            require(persisted == p1_report, 'P1 callback differs from persisted native evidence')
            p1_raw, p1_proof = postinstall._capture(folder, 'post_p1', str(report_path.relative_to(folder)), _sha(raw_report),
                binding, review['group_nonce'], not injected,
                {review['group_nonce'], review['pdt_nonce'], prepared.reference['metadata']['nonce']}, set())
            require(len(p1_raw) == P1_BYTES, 'Full pre-install P1 bytes required')
            p1_files = (report_path, Path(p1_report['capture']), p1_folder / 'launch-and-ready.json',
                        p1_folder / 'completed.json', p1_folder / 'capture/status.json')
            p1_references = [_file_reference(folder, path) for path in p1_files]
            require(p1_references[0]['sha256'] == _sha(raw_report)
                    and p1_references[1]['sha256'] == p1_proof['sha256']
                    and p1_references[1]['bytes'] == p1_proof['bytes'], 'Captured P1 evidence changed after validation')
            evidence_files.extend(p1_references)
            p1_reference = dict(path=str(report_path.relative_to(folder)), sha256=_sha(raw_report),
                technical_profile='post_p1', acquisition_phase='PRE_INSTALL', **binding, group_nonce=review['group_nonce'])
            guard()
            pdt_raw = pdt_reader(device, clock=clock)
            require(type(pdt_raw) is bytes and len(pdt_raw) == PDT_BYTES, 'Full raw PRE_INSTALL PDT required')
            runtime.record_map(pdt_raw)
            pdt_file = _save_raw(folder / 'before.bk4', pdt_raw)
            before = dict(binding, path=pdt_file['path'], sha256=pdt_file['sha256'], group_nonce=review['group_nonce'],
                          nonce=review['pdt_nonce'], source_is_hardware=not injected, acquisition_phase='PRE_INSTALL')
            durable_new(folder / 'before-reference.json', before)
            evidence_files.extend(_file_reference(folder, folder / name) for name in ('before.bk4', 'before-reference.json'))
            guard()
            observed_metadata = metadata_fn(device, metadata_folder, assets=assets.metadata_assets if isinstance(assets, RuntimeAssets) else None,
                reservation=reservation, lease=lease, journal=journal, body_sha256=expected_body_sha256,
                plan_sha256=plan_sha256, metadata_read_authorized=True, source_is_hardware=not injected,
                clock=clock, sleep=sleep)
            guard()
            require(type(observed_metadata.get('source_is_hardware')) is bool
                    and observed_metadata['source_is_hardware'] is (not injected), 'Metadata source context differs')
            metadata_proof = metadata.validate_receipt(observed_metadata, reference=prepared.reference['metadata'], reservation=reservation)
            metadata_path = metadata_folder / 'metadata-receipt.json'
            metadata_raw, persisted_metadata = _json(metadata_path)
            require(persisted_metadata == observed_metadata, 'Metadata callback differs from durable raw receipt')
            proc = bytes.fromhex(observed_metadata['partitions_raw_hex'])
            aliases = bytes.fromhex(observed_metadata['aliases_raw_hex'])
            proc_ref = _save_raw(folder / 'partitions.bin', proc)
            alias_ref = _save_raw(folder / 'aliases.bin', aliases)
            evidence_files.extend(_file_reference(folder, path) for path in
                                  (metadata_path, folder / 'partitions.bin', folder / 'aliases.bin'))
            _check_files(folder, evidence_files)
            decoded = runtime.decode_runtime(pdt_raw=pdt_raw, p1_raw=p1_raw, partitions_raw=proc,
                alias_targets=metadata_proof['alias_targets'], required_partition_sizes=required, normal_model_name='ILCE-7M4')
            accepted = dict(schema='camera-install-runtime-session-receipt/1', state='PRE_INSTALL_RUNTIME_TERMINAL_BEFORE_STOP',
                scope=SCOPE, acquisition_phase='PRE_INSTALL', **binding, current_review=review_ref,
                group_nonce=review['group_nonce'], pdt_nonce=review['pdt_nonce'], journal_event_sha256=history[-1]['event_sha256'],
                lease_identity=identity, asset_reference=prepared.reference, metadata_reservation=reservation,
                p1=dict(technical_profile='post_p1', acquisition_phase='PRE_INSTALL', reference=p1_reference, native_proof=p1_proof),
                before_reference=before, metadata_receipt=deepcopy(observed_metadata), metadata_proof=metadata_proof,
                metadata_artifact=dict(path=str(metadata_path), sha256=_sha(metadata_raw)),
                raw_inputs=dict(pdt=pdt_file, partitions=proc_ref, aliases=alias_ref), evidence_files=deepcopy(evidence_files),
                decoded_values=decoded,
                source_is_hardware=not injected, normal_body_verified=True, service_exit_completed=False,
                **dict.fromkeys(FALSE_CLAIMS, False))
            path = folder / 'runtime-terminal.json';durable_new(path, accepted)
            raw, saved = _json(path);require(saved == accepted, 'Runtime terminal host readback differs')
            guard();_check_files(folder, evidence_files)
            terminal_ref = dict(path=str(path), sha256=_sha(raw), payload_sha256=canonical_sha256(accepted))
            return deepcopy(accepted)
        stage, attempted = 'RUNTIME_SERVICE_ENTRY_MAY_HAVE_STARTED', True
        returned = run_session(expected_body_sha256, work, record_event=events.append, set_stage=set_stage)
        guard()
        require(calls == 1 and returned == accepted and terminal_ref is not None, 'Original runtime callback result required')
        _known_stop(events)
        _check_files(folder, evidence_files)
        raw, terminal = _json(terminal_ref['path'])
        require(_sha(raw) == terminal_ref['sha256'] and canonical_sha256(terminal) == terminal_ref['payload_sha256'],
                'Durable pre-STOP runtime terminal changed')
        result = terminal | dict(state='PRE_INSTALL_RUNTIME_KNOWN_SERVICE_EXIT', terminal_artifact=terminal_ref,
                                 service_events=deepcopy(events), service_exit_completed=True, original_journal_unchanged=True)
        durable_new(folder / 'runtime-session-exit.json', result)
        _, saved = _json(folder / 'runtime-session-exit.json');require(saved == result, 'Runtime exit receipt changed')
        guard();_check_files(folder, evidence_files);return result
    except BaseException as error:
        failure = dict(scope=SCOPE, acquisition_phase='PRE_INSTALL', state='RUNTIME_SESSION_UNKNOWN' if attempted else 'LOCAL_RUNTIME_REJECTED',
            stage=stage, error_type=type(error).__name__, authentication_may_have_started=attempted,
            claims_may_be_reserved=claims_attempted, installation_authorized=False, write_admission=False,
            automatic_retry=False, automatic_STOP=False, automatic_reset=False, automatic_reboot=False, automatic_restore=False)
        if attempted and isinstance(journal, InstallJournal):
            try:
                journal.advance('STOPPED_UNKNOWN', details=failure)
            except BaseException:
                pass
        try:
            if folder.is_dir() and all(not p.is_symlink() for p in (folder, *folder.parents)):
                durable_new(folder / 'runtime-session-unknown.json', failure)
        except BaseException:
            pass
        raise
    finally:
        if installed is not None:
            device, original = installed
            device.driver = original
