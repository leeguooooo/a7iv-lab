"""Own one current-read service session while preserving its original pending ledger."""
from copy import deepcopy
import hashlib
from pathlib import Path
import time

import camera_install_patch_read as contract
import camera_install_patch_read_execution as execution
from camera_device_lease import DEFAULT_LOCK
from camera_install_journal import InstallJournal
from camera_install_patch_session import (SOURCE_ONLY_RUNTIME, _source_only_runtime, _safe_path,
    _held_lease, _json, _known_stop, canonical_sha256, review_source_paths as preparation_sources)
from camera_operation_guard import DEFAULT_SESSIONS
from camera_stream_execution import durable_new

ROOT = Path(__file__).resolve().parent
REVIEW_SCHEMA = 'camera-install-patch-read-session-plan/1'
SCOPE = execution.SCOPE
PENDING_STATE = execution.PENDING_STATE
FALSE_CLAIMS = ('installation_authorized', 'firmware_installation_proven', 'RAM_restoration_proven',
                'cancellation_recorded', 'journal_cleared', 'original_mm_continuity_proven',
                'original_hardware_origin_proven', 'hardware_admission_proven')


def require(ok, message):
    if not ok:
        raise ValueError(message)


def review_source_paths(prepared):
    return tuple(sorted(set(preparation_sources(prepared)) | {
        'camera_install_patch_read_session.py', 'camera_install_patch_read_plan.py',
        'camera_install_patch_read_execution.py', 'camera_install_patch_read.py'}))


def validate_review(path, review_sha256, prepared):
    raw, review = _json(path)
    require(hashlib.sha256(raw).hexdigest() == review_sha256, 'Current-read review changed')
    ref = prepared.reference
    require(review.get('schema') == REVIEW_SCHEMA and review.get('scope') == SCOPE
            and review.get('model') == 'ILCE-7M4' and review.get('body_sha256') == ref['body_sha256']
            and review.get('original_plan_sha256') == ref['plan_sha256']
            and review.get('pending_reference') == ref['pending_reference']
            and review.get('asset_reference') == ref
            and review.get('target_spec_sha256') == contract.spec_sha256(prepared.spec)
            and review.get('source_only_runtime') == SOURCE_ONLY_RUNTIME
            and all(type(review['source_only_runtime'].get(name)) is bool for name in
                    ('dont_write_bytecode', 'ignore_environment', 'no_user_site', 'prefix_must_not_exist'))
            and review.get('execution_approval_received') is False
            and type(review.get('hardware_operations')) is int and review['hardware_operations'] == 0
            and all(review.get(name) is False for name in FALSE_CLAIMS), 'Current-read review scope/binding differs')
    sources = review.get('sources')
    require(isinstance(sources, dict) and set(review_source_paths(prepared)).issubset(sources)
            and all(sources.get(name) == value for name, value in prepared.manifest['sources'].items()),
            'Complete current host/SDK/native source closure required')
    snapshots = Path(path).absolute().parent / 'sources'
    require(review.get('source_snapshot_directory') == str(snapshots), 'Bound read source snapshots required')
    _safe_path(snapshots, directory=True)
    for name, digest in sources.items():
        relative = Path(name)
        require(not relative.is_absolute() and '..' not in relative.parts and isinstance(digest, str)
                and execution.SHA.fullmatch(digest), 'Invalid current-read source binding')
        require(hashlib.sha256(_safe_path(ROOT / name).read_bytes()).hexdigest() == digest,
                'Reviewed current-read source changed: ' + name)
        require(hashlib.sha256(_safe_path(snapshots / name).read_bytes()).hexdigest() == digest,
                'Current-read snapshot changed: ' + name)
    require(execution._reference(ref['pending_reference']).hex() == prepared.spec['pending_receipt_raw_hex'],
            'Original pending bytes changed')
    return dict(path=str(Path(path).absolute()), sha256=review_sha256, payload_sha256=canonical_sha256(review))


def _accepted(observed, prepared, reservation, hardware):
    ref = prepared.reference
    require(isinstance(observed, dict) and observed.get('state') == 'CURRENT_OBSERVATION_ONLY'
            and observed.get('scope') == SCOPE and observed.get('asset_reference') == ref
            and observed.get('reservation') == reservation and observed.get('service_exit_completed') is False
            and type(observed.get('source_is_hardware')) is bool, 'Bound current-read native receipt required')
    publications = observed.get('raw_publications')
    require(isinstance(publications, dict) and set(publications) == {'ready', 'result'}
            and all(type(value) is str for value in publications.values()), 'Complete current-read raw publications required')
    raws = {name: bytes.fromhex(value) for name, value in publications.items()}
    proof = contract.validate_publications(raws['ready'], raws['result'], nonce=bytes.fromhex(ref['nonce']),
        loader_pid=observed.get('loader_pid'), spec=prepared.spec)
    require(all(observed.get(name) == value for name, value in proof.items() if name != 'source_is_hardware')
            and all(observed.get(name) is False for name in ('journal_cleared', 'cancellation_recorded')),
            'Current-read semantic receipt differs from raw bytes')
    return deepcopy(observed) | proof | dict(source_is_hardware=hardware and observed['source_is_hardware'])


def run_current_read_session(expected_body_sha256, evidence, *, plan_sha256, pending_reference,
        review_path, review_sha256, assets, journal, lease, read_authorized=False,
        run_session=None, start_fn=None, clock=time.monotonic, sleep=time.sleep):
    folder = Path(evidence).absolute()
    stage, claim_attempted, attempted = 'LOCAL_PREFLIGHT', False, False
    reservation, identity = None, None
    try:
        require(read_authorized is True, 'Explicit current-read-only consent required')
        require((run_session is None) == (start_fn is None), 'Session and read runner must both be injected or both default')
        require(run_session is None or (callable(run_session) and callable(start_fn)), 'Injected session/runner must be callable')
        injected = run_session is not None
        identity = _held_lease(lease)
        require(isinstance(journal, InstallJournal), 'Original pending journal required')
        if not injected:
            require(Path(lease.path).absolute() == DEFAULT_LOCK.absolute()
                    and journal.session_dir.parent.absolute() == DEFAULT_SESSIONS.absolute(),
                    'Default read session requires canonical lease and journal')
            _safe_path(lease.path)
            _safe_path(journal.session_dir, directory=True)
        folder = _safe_path(folder, directory=True)
        require(not any(folder.iterdir()), 'Fresh empty current-read evidence directory required')
        prepared = execution.preflight_assets(assets, pending_reference=pending_reference,
            expected_body_sha256=expected_body_sha256, plan_sha256=plan_sha256)
        history = journal.events
        require(execution._context(prepared, lease, journal) == identity, 'Original pending context changed')
        reviewed = validate_review(review_path, review_sha256, prepared)
        if not injected:
            require(prepared.spec['original_source_is_hardware'] is True
                    and not contract._modeled(contract._json(bytes.fromhex(prepared.spec['pending_receipt_raw_hex']))),
                    'Modeled prior context cannot enter default session')
            _source_only_runtime()
        def guard():
            require(execution._context(prepared, lease, journal) == identity and journal.events == history,
                    'Original pending history or held lease changed')
            require(validate_review(review_path, review_sha256, prepared) == reviewed, 'Read review changed during session')
            if not injected:
                _source_only_runtime()
        guard()
        stage, claim_attempted = 'LOCAL_READ_RESERVATION', True
        reservation = execution.reserve_assets(prepared, folder, lease=lease, journal=journal)
        guard()
        require(not any(folder.iterdir()), 'Read reservation added unexpected run-folder files')
        rechecked = execution._preflight(assets, pending_reference, expected_body_sha256, plan_sha256, reservation)
        require(rechecked == prepared, 'Read assets changed after reservation')
        require(validate_review(review_path, review_sha256, prepared) == reviewed, 'Read review changed before authentication')
        if run_session is None:
            from camera_stream_usb_session import run_normal_session
            run_session = run_normal_session
            start_fn = execution.start_authenticated
        events, accepted, terminal_ref, calls = [], None, None, 0
        def set_stage(value):
            nonlocal stage
            stage = value
        def work(device):
            nonlocal accepted, terminal_ref, calls
            calls += 1
            require(calls == 1, 'Current-read callback cannot be replayed')
            guard()
            observed = start_fn(device, folder, assets=assets, reservation=reservation,
                pending_reference=pending_reference, lease=lease, journal=journal,
                expected_body_sha256=expected_body_sha256, plan_sha256=plan_sha256,
                read_authorized=True, body_verified=True, source_is_hardware=not injected,
                clock=clock, sleep=sleep)
            guard()
            accepted = _accepted(observed, prepared, reservation, not injected)
            terminal = dict(schema='camera-install-patch-read-session-receipt/1',
                state='CURRENT_READ_TERMINAL_DURABLE_BEFORE_STOP', scope=SCOPE,
                body_sha256=expected_body_sha256, original_plan_sha256=plan_sha256,
                current_review=reviewed, original_pending_reference=dict(pending_reference),
                original_pending_event_sha256=history[-1]['event_sha256'],
                original_history_sha256=canonical_sha256(history), original_session_id=journal.session_dir.name,
                lease_identity=identity, asset_reference=prepared.reference, reservation=reservation,
                native_receipt=accepted, native_receipt_sha256=canonical_sha256(accepted),
                source_is_hardware=accepted['source_is_hardware'], service_exit_completed=False,
                original_source_declaration=prepared.spec['original_source_is_hardware'],
                **dict.fromkeys(FALSE_CLAIMS, False))
            path = folder / 'current-read-session-terminal.json'
            durable_new(path, terminal)
            raw, saved = _json(path)
            require(saved == terminal, 'Full read terminal changed before STOP')
            guard()
            terminal_ref = dict(path=str(path), sha256=hashlib.sha256(raw).hexdigest(), payload_sha256=canonical_sha256(terminal))
            return deepcopy(accepted)
        stage, attempted = 'CURRENT_READ_SERVICE_ENTRY_MAY_HAVE_STARTED', True
        returned = run_session(expected_body_sha256, work, record_event=events.append, set_stage=set_stage)
        guard()
        require(calls == 1 and returned == accepted and terminal_ref is not None, 'Original one-shot current-read result required')
        _known_stop(events)
        raw, terminal = _json(terminal_ref['path'])
        require(hashlib.sha256(raw).hexdigest() == terminal_ref['sha256']
                and canonical_sha256(terminal) == terminal_ref['payload_sha256'], 'Pre-STOP terminal changed')
        result = terminal | dict(state='CURRENT_READ_KNOWN_SERVICE_EXIT', terminal_artifact=terminal_ref,
            service_events=deepcopy(events), service_exit_completed=True, original_journal_unchanged=True)
        durable_new(folder / 'current-read-session-exit.json', result)
        _, saved = _json(folder / 'current-read-session-exit.json')
        require(saved == result, 'Read exit receipt changed')
        guard()
        return result
    except BaseException as error:
        failure = dict(scope=SCOPE, state='CURRENT_READ_SESSION_UNKNOWN' if claim_attempted or attempted else 'LOCAL_READ_REJECTED',
            stage=stage, error_type=type(error).__name__, authentication_may_have_started=attempted,
            claims_may_be_reserved=claim_attempted, reservation=reservation,
            pending_reference=pending_reference, current_review_sha256=review_sha256,
            original_journal_not_transitioned=True, automatic_retry=False, automatic_STOP=False,
            automatic_restore=False, automatic_reboot=False, **dict.fromkeys(FALSE_CLAIMS, False))
        try:
            durable_new(_safe_path(folder, directory=True) / 'current-read-session-unknown.json', failure)
        except BaseException:
            pass
        raise
