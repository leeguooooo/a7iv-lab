"""One authorized install-preparation session, without a firmware entry path.

A durable native receipt precedes the existing helper's success-only service
STOP. The resulting journal stays pending for a separately reviewed operator
reconnect. No restore, reboot, retry, FLASH admission or device-health proof is
provided. Injected callbacks always produce non-hardware evidence.
"""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import time

from camera_device_lease import CameraDeviceLease, DEFAULT_LOCK, inspect_lease
from camera_install_journal import InstallJournal, JournalError, assert_no_pending_installs
from camera_operation_guard import DEFAULT_SESSIONS, assert_operation_allowed
from camera_stream_execution import durable_new
from camera_install_volatile import validate_publications

ROOT = Path(__file__).resolve().parent
GLOBAL_SESSIONS = DEFAULT_SESSIONS
MAY_STATE = 'INSTALL_PATCH_MAY_BE_ACTIVE'
PENDING_STATE = 'INSTALL_PATCH_AWAITING_OPERATOR_RECONNECT'
CONSENT_SCOPE = 'INSTALL_PREPARATION_VOLATILE_PATCH_ONLY'
REVIEW_SCHEMA = 'camera-install-patch-session-plan/1'
SOURCE_ONLY_RUNTIME = dict(dont_write_bytecode=True, ignore_environment=True, no_user_site=True,
    pycache_prefix='output/workflow-absent-bytecode-cache', prefix_must_not_exist=True)
REQUIRED_SOURCES = frozenset(('camera_install_patch_session.py', 'camera_install_patch.py',
    'camera_install_patch_plan.py', 'camera_install_volatile.py', 'camera_install_journal.py',
    'camera_toolchain.py', 'camera_inventory.py', 'native/stream_backup.c',
    'camera_device_lease.py', 'camera_operation_guard.py', 'camera_stream_usb_session.py',
    'camera_stream_service.py', 'camera_stream_execution.py', 'camera_stream_channel.py',
    'camera_stream_senser.py', 'camera_stream_transport_bounds.py', 'camera_firmware_capture.py',
    'camera_stream_collect.py', 'camera_stream_receiver.py',
    'camera_backup_records.py', 'native/install_volatile_patch.c',
    'tools/install_volatile_profile.py', 'tools/build_install_volatile_offline.py',
    'tools/verify_install_volatile_offline.py', 'tools/emulate_install_volatile_offline.py',
    'tools/menu_window_profile.py', 'tools/verify_menu_window_offline.py',
    'tools/build_firmware_file_capture_offline.py', 'tools/emulate_firmware_file_capture_offline.py',
    'tools/firmware_file_capture_assets.py', 'tools/firmware_file_capture_bootstrap.py'))


def require(value, message):
    if not value:
        raise ValueError(message)


def canonical_sha256(value):
    raw = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode()
    return hashlib.sha256(raw).hexdigest()


def _safe_path(value, directory=False):
    path = Path(value).absolute()
    require('..' not in path.parts and all(not p.is_symlink() for p in (path, *path.parents)),
            'Non-symlink local path required')
    require(path.is_dir() if directory else path.is_file(), 'Regular local evidence required')
    return path


def _json(path):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'Duplicate JSON field')
            result[key] = value
        return result
    path = _safe_path(path)
    raw = path.read_bytes()
    value = json.loads(raw, object_pairs_hook=pairs)
    require(isinstance(value, dict), 'JSON object required')
    return raw, value


def review_source_paths(preparedassets=None):
    sdk = {str(p.relative_to(ROOT)) for p in (ROOT / 'Sony-PMCA-RE/pmca').rglob('*.py')}
    require(bool(sdk), 'SDK source closure missing')
    host = {str(p.relative_to(ROOT)) for p in ROOT.glob('camera_*.py')}
    helpers = {str(p.relative_to(ROOT)) for p in (ROOT / 'tools').glob('*firmware_file_capture*.py')}
    native = set(preparedassets.manifest['sources']) if preparedassets is not None else set()
    return tuple(sorted(REQUIRED_SOURCES | sdk | host | helpers | native))


def _asset_reference(reference):
    require(isinstance(reference, dict) and set(reference) == {'schema', 'patch', 'captures'}
            and reference['schema'] == 'camera-install-patch-assets/1', 'Complete prepared asset reference required')
    patch, captures = reference['patch'], reference['captures']
    require(isinstance(patch, dict) and set(patch) == {'directory', 'manifest_sha256', 'module_sha256',
            'native_model_sha256', 'bootstrap_model_sha256', 'nonce', 'job_dir'}
            and isinstance(captures, dict) and set(captures) == {'directory', 'pre_app', 'pre_ufp'},
            'Complete patch/capture closure required')
    rows = [patch]
    for name in ('pre_app', 'pre_ufp'):
        row = captures[name]
        require(isinstance(row, dict) and set(row) == {'manifest_sha256', 'module_sha256', 'nonce'},
                'Complete capture reference required')
        rows.append(row)
    for row in rows:
        require(isinstance(row['nonce'], str) and len(row['nonce']) == 32
                and all(c in '0123456789abcdef' for c in row['nonce']) and any(bytes.fromhex(row['nonce'])),
                'Bound nonzero asset nonce required')
        require(all(isinstance(value, str) and len(value) == 64
                    and all(c in '0123456789abcdef' for c in value)
                    for name, value in row.items() if name.endswith('_sha256')), 'Bound asset hashes required')
    require(len({row['nonce'] for row in rows}) == 3
            and patch['job_dir'] == '/tmp_wbshd/m4ivp_' + patch['nonce'], 'Distinct bound asset nonces required')
    require(all(isinstance(value, str) and Path(value).is_absolute() and '..' not in Path(value).parts
                for value in (patch['directory'], captures['directory'])), 'Absolute asset directories required')
    canonical_sha256(reference)


def validate_review(review_path, plan_sha256, expected_body, preparedassets):
    raw, review = _json(review_path)
    require(hashlib.sha256(raw).hexdigest() == plan_sha256, 'Reviewed plan changed')
    reference = preparedassets.reference
    _asset_reference(reference)
    require(review.get('schema') == REVIEW_SCHEMA and review.get('scope') == CONSENT_SCOPE
            and review.get('model') == 'ILCE-7M4' and review.get('body_sha256') == expected_body
            and review.get('asset_reference') == reference
            and review.get('installation_authorized') is False
            and review.get('hardware_admission_proven') is False
            and review.get('flash_authorized') is False
            and review.get('source_only_runtime') == SOURCE_ONLY_RUNTIME
            and all(type(review['source_only_runtime'].get(name)) is bool for name in
                    ('dont_write_bytecode', 'ignore_environment', 'no_user_site', 'prefix_must_not_exist'))
            and review.get('execution_approval_received') is False
            and type(review.get('hardware_operations')) is int and review['hardware_operations'] == 0,
            'Reviewed install-preparation scope/body/assets differ')
    sources = review.get('sources')
    require(isinstance(sources, dict) and set(review_source_paths(preparedassets)).issubset(sources),
            'Complete reviewed source closure required')
    require(all(sources.get(name) == digest for name, digest in preparedassets.manifest['sources'].items()),
            'Reviewed native source bindings differ')
    for name, digest in sources.items():
        relative = Path(name)
        require(not relative.is_absolute() and '..' not in relative.parts
                and isinstance(digest, str) and len(digest) == 64, 'Invalid reviewed source binding')
        path = _safe_path(ROOT / relative)
        require(hashlib.sha256(path.read_bytes()).hexdigest() == digest, 'Reviewed source changed: ' + name)
    body_reference = review.get('body_reference')
    require(isinstance(body_reference, dict) and set(body_reference) == {'path', 'sha256', 'historical_only'}
            and body_reference['historical_only'] is True, 'Bound historical body reference required')
    body_raw, body_report = _json(body_reference['path'])
    require(hashlib.sha256(body_raw).hexdigest() == body_reference['sha256']
            and isinstance(body_report.get('body'), dict)
            and body_report['body'].get('model') == 'ILCE-7M4'
            and body_report['body'].get('usb_serial_sha256') == expected_body,
            'Historical body reference changed')
    snapshots = Path(review_path).absolute().parent / 'sources'
    require(review.get('source_snapshot_directory') == str(snapshots), 'Bound source snapshot directory required')
    _safe_path(snapshots, directory=True)
    for name, digest in sources.items():
        require(hashlib.sha256(_safe_path(snapshots / name).read_bytes()).hexdigest() == digest,
                'Reviewed source snapshot changed: ' + name)
    return dict(path=str(Path(review_path).absolute()), sha256=plan_sha256,
                payload_sha256=canonical_sha256(review))


def _source_only_runtime():
    prefix = ROOT / SOURCE_ONLY_RUNTIME['pycache_prefix']
    require(sys.dont_write_bytecode is True and sys.flags.ignore_environment == 1
            and sys.flags.no_user_site == 1 and sys.pycache_prefix == str(prefix)
            and not prefix.exists() and not prefix.is_symlink(),
            'Source-only production Python startup required')


def _held_lease(lease):
    require(isinstance(lease, CameraDeviceLease) and lease.fd is not None
            and isinstance(lease.metadata, dict) and lease.metadata.get('state') == 'HELD',
            'Caller-held CameraDeviceLease required')
    descriptor = os.fstat(lease.fd)
    location = os.stat(lease.path, follow_symlinks=False)
    require(stat.S_ISREG(descriptor.st_mode) and stat.S_ISREG(location.st_mode)
            and (descriptor.st_dev, descriptor.st_ino) == (location.st_dev, location.st_ino),
            'Live caller lease descriptor required')
    raw = os.pread(lease.fd, 8193, 0)
    require(len(raw) <= 8192 and json.loads(raw) == lease.metadata
            and lease.metadata.get('pid') == os.getpid(), 'Held lease ownership record changed')
    inspected = inspect_lease(lease.path)
    require(inspected['live_host_lock'] is True and inspected['owner_metadata'] == lease.metadata,
            'Held caller lease lock required')
    return dict(device=descriptor.st_dev, inode=descriptor.st_ino, instance=lease.metadata['instance'])


def _barrier(journal, states):
    assert_operation_allowed(journal, allowed_states=states)
    if journal.session_dir.parent.resolve() != Path(GLOBAL_SESSIONS).resolve():
        assert_no_pending_installs(GLOBAL_SESSIONS)


def _known_stop(events):
    require(isinstance(events, list) and all(isinstance(event, dict) for event in events),
            'Service event list required')
    stops = [event for event in events if event.get('event') == 'STOP_RESPONSE']
    require(len(stops) == 1 and stops[0].get('mode') == 'service'
            and (stops[0].get('success') is True or stops[0].get('known_pipe_response') is True),
            'Known service STOP response required')


def _native_receipt(observed, reference, reservation, hardware, binding):
    require(isinstance(observed, dict) and observed.get('state') == 'VOLATILE_PATCH_APPLIED_NOT_RESTORED'
            and observed.get('asset_reference') == reference and observed.get('reservation') == reservation
            and all(observed.get(key) == value for key, value in binding.items())
            and observed.get('scope') == CONSENT_SCOPE and observed.get('service_exit_completed') is False,
            'Bound complete native receipt required')
    nonce = reference['patch']['nonce']
    require(observed.get('nonce') == nonce, 'Native receipt nonce changed')
    publications = observed.get('raw_publications')
    require(isinstance(publications, dict) and set(publications) == {'ready', 'patched', 'result'}
            and all(type(value) is str for value in publications.values()), 'Complete native publication bytes required')
    raws = {name: bytes.fromhex(value) for name, value in publications.items()}
    proof = validate_publications(raws['ready'], raws['patched'], raws['result'],
                                  nonce=bytes.fromhex(nonce), loader_pid=observed.get('loader_pid'))
    return deepcopy(observed) | proof | dict(source_is_hardware=hardware and observed.get('source_is_hardware') is True,
                                           raw_publications={name: value.hex() for name, value in raws.items()})


def validate_pending_receipt(reference, binding, history):
    """Revalidate a blocking receipt; never admit firmware or clear a journal."""
    require(isinstance(reference, dict) and set(reference) == {'path', 'sha256'}, 'Pending artifact reference required')
    raw, receipt = _json(reference['path'])
    require(hashlib.sha256(raw).hexdigest() == reference['sha256'], 'Pending artifact changed')
    require(history and history[-1]['state'] == MAY_STATE, 'Original install-patch MAY intent required')
    intent = history[-1]
    details = intent['details']
    require(details.get('operation') == 'install-volatile-patch'
            and details.get('consent_scope') == CONSENT_SCOPE
            and details.get('patches_remain_acknowledged') is True
            and details.get('installation_authorized') is False, 'Bound preparation-only consent required')
    require(receipt.get('schema') == 'camera-install-patch-session-receipt/1'
            and receipt.get('state') == PENDING_STATE
            and all(receipt.get(key) == value for key, value in binding.items())
            and receipt.get('session_id') == intent['session_id']
            and receipt.get('intent_event_sha256') == intent['event_sha256']
            and receipt.get('consent_scope') == CONSENT_SCOPE
            and receipt.get('patches_remain_acknowledged') is True
            and receipt.get('asset_reference') == details.get('asset_reference')
            and receipt.get('review_artifact') == details.get('review_artifact')
            and receipt.get('lease_identity') == details.get('lease_identity'),
            'Pending receipt differs from its complete MAY intent')
    for key in ('installation_authorized', 'firmware_installation_proven', 'RAM_restoration_proven',
                'normal_body_reappearance_verified', 'device_execution_proven', 'hardware_admission_proven'):
        require(receipt.get(key) is False, 'Pending receipt cannot confer admission: ' + key)
    _known_stop(receipt.get('service_events'))
    require(receipt.get('service_exit_completed') is True and type(receipt.get('source_is_hardware')) is bool,
            'Known service exit required')
    native = _native_receipt(receipt.get('native_receipt'), receipt['asset_reference'],
                             receipt.get('reservation'), receipt['source_is_hardware'], binding)
    require(native == receipt['native_receipt']
            and receipt['source_is_hardware'] is native['source_is_hardware']
            and receipt.get('native_receipt_sha256') == canonical_sha256(native),
            'Native receipt payload changed')
    terminal_reference = receipt.get('terminal_artifact')
    require(isinstance(terminal_reference, dict) and set(terminal_reference) == {'path', 'sha256', 'payload_sha256'},
            'Durable pre-STOP terminal artifact required')
    terminal_raw, terminal = _json(terminal_reference['path'])
    require(hashlib.sha256(terminal_raw).hexdigest() == terminal_reference['sha256']
            and canonical_sha256(terminal) == terminal_reference['payload_sha256'], 'Terminal artifact changed')
    expected = deepcopy(receipt)
    for key in ('service_events', 'service_exit_completed', 'terminal_artifact'):
        expected.pop(key)
    expected['state'] = 'INSTALL_PATCH_TERMINAL_DURABLE_BEFORE_STOP'
    require(terminal == expected, 'Complete pre-STOP receipt differs from pending receipt')
    return receipt


def run_install_patch_session(expected_body_sha256, evidence, *, plan_sha256, review_path, journal, lease,
        volatile_patch_authorized=False, formal_preparation_authorized=False, patches_remain_acknowledged=False,
        assets=None, capture_assets=None, preflight_fn=None, reserve_fn=None, run_session=None, start_fn=None,
        clock=time.monotonic, sleep=time.sleep):
    """Prepare one volatile patch and leave a blocking operator-reconnect ledger.

    Both consents cover preparation only. Patches intentionally remain until a
    separate cleanup or reboot; this function authorizes neither such action.
    """
    folder = Path(evidence).absolute()
    phase = 'LOCAL_PREFLIGHT'
    intent_persisted = intent_persistence_attempted = attempted = False
    try:
        require(volatile_patch_authorized is True and formal_preparation_authorized is True
                and patches_remain_acknowledged is True, 'Explicit volatile preparation consent required')
        injected = any(value is not None for value in (preflight_fn, reserve_fn, run_session, start_fn))
        require(not injected or run_session is not None, 'Injected callbacks require an injected session')
        lease_identity = _held_lease(lease)
        require(isinstance(journal, InstallJournal), 'InstallJournal required')
        binding = dict(plan_sha256=plan_sha256, body_sha256=expected_body_sha256, model='ILCE-7M4')
        require(journal.binding == binding, 'Journal plan/body/model mismatch')
        current = InstallJournal.open(journal.session_dir)
        require(current.events == journal.events and current.state == 'SD_STAGED', 'Fresh SD_STAGED journal required')
        _barrier(journal, ('SD_STAGED',))
        if not injected:
            require(journal.session_dir.parent.absolute() == DEFAULT_SESSIONS.absolute()
                    and Path(lease.path).absolute() == DEFAULT_LOCK.absolute(),
                    'Production session requires the global journal and device lease')
            _safe_path(journal.session_dir, directory=True)
            _safe_path(lease.path)
        folder = _safe_path(folder, directory=True)
        require(not any(folder.iterdir()), 'Fresh empty evidence directory required')
        from camera_install_patch import preflight_assets, reserve_assets, start_authenticated
        preflight = preflight_fn or preflight_assets
        reserve = reserve_fn or reserve_assets
        start = start_fn or start_authenticated
        prepared = preflight(assets, capture_assets)
        reference = deepcopy(prepared.reference)
        review_reference = validate_review(review_path, plan_sha256, expected_body_sha256, prepared)
        if not injected:
            _source_only_runtime()
        require(_held_lease(lease) == lease_identity, 'Held lease changed during local checks')
        _barrier(journal, ('SD_STAGED',))
        phase = 'LOCAL_INSTALL_PATCH_INTENT_PERSISTENCE'
        intent_persistence_attempted = True
        intent = journal.advance(MAY_STATE, details=dict(operation='install-volatile-patch',
            consent_scope=CONSENT_SCOPE, patches_remain_acknowledged=True, asset_reference=reference,
            review_artifact=review_reference, lease_identity=lease_identity, installation_authorized=False,
            automatic_retry=False))
        intent_persisted = True
        phase = MAY_STATE
        reservation = reserve(prepared, folder, lease=lease, journal=journal,
                              expected_body_sha256=expected_body_sha256, plan_sha256=plan_sha256)
        require(_held_lease(lease) == lease_identity, 'Held lease changed before device entry')
        _barrier(journal, (MAY_STATE,))
        require(prepared.reference == reference
                and validate_review(review_path, plan_sha256, expected_body_sha256, prepared) == review_reference,
                'Local review changed before device entry')
        if run_session is None:
            from camera_stream_usb_session import run_normal_session
            run_session = run_normal_session
        events, terminal_reference, accepted = [], None, None
        work_calls = 0
        def set_stage(value):
            nonlocal phase
            phase = value
        def work(device):
            nonlocal work_calls, terminal_reference, accepted
            work_calls += 1
            require(work_calls == 1, 'One-shot patch work cannot be replayed')
            observed = start(device, folder, assets=assets, capture_assets=capture_assets,
                reservation=reservation, lease=lease, journal=journal,
                expected_body_sha256=expected_body_sha256, plan_sha256=plan_sha256,
                volatile_patch_authorized=True, body_verified=True, source_is_hardware=not injected,
                clock=clock, sleep=sleep)
            accepted = _native_receipt(observed, reference, reservation, not injected, binding)
            terminal = dict(schema='camera-install-patch-session-receipt/1',
                state='INSTALL_PATCH_TERMINAL_DURABLE_BEFORE_STOP', **binding,
                session_id=journal.session_dir.name, intent_event_sha256=intent['event_sha256'],
                consent_scope=CONSENT_SCOPE, patches_remain_acknowledged=True,
                review_artifact=review_reference, lease_identity=lease_identity, asset_reference=reference,
                reservation=reservation, native_receipt=accepted, native_receipt_sha256=canonical_sha256(accepted),
                source_is_hardware=accepted['source_is_hardware'], installation_authorized=False,
                firmware_installation_proven=False, RAM_restoration_proven=False,
                normal_body_reappearance_verified=False, device_execution_proven=False, hardware_admission_proven=False)
            path = folder / 'install-patch-terminal.json'
            durable_new(path, terminal)
            raw, persisted = _json(path)
            require(persisted == terminal, 'Durable terminal receipt changed before STOP')
            terminal_reference = dict(path=str(path), sha256=hashlib.sha256(raw).hexdigest(),
                                      payload_sha256=canonical_sha256(terminal))
            return deepcopy(accepted)
        attempted = True
        returned = run_session(expected_body_sha256, work, record_event=events.append, set_stage=set_stage)
        phase = 'KNOWN_INSTALL_PATCH_SERVICE_EXIT'
        require(work_calls == 1 and returned == accepted and terminal_reference is not None,
                'Original completed one-shot callback required')
        _known_stop(events)
        _, terminal = _json(terminal_reference['path'])
        result = terminal | dict(state=PENDING_STATE, terminal_artifact=terminal_reference,
                                 service_events=deepcopy(events), service_exit_completed=True)
        path = folder / 'install-patch-awaiting-reconnect.json'
        durable_new(path, result)
        journal.record_install_patch_awaiting_reconnect(path)
        return result
    except BaseException as error:
        uncertain = intent_persistence_attempted or attempted
        stopped = dict(state='STOPPED_UNKNOWN' if uncertain else 'LOCAL_REJECTED_NO_DEVICE_SESSION',
            phase=phase, error_type=type(error).__name__, device_session_started=attempted,
            intent_persisted=intent_persisted, intent_persistence_attempted=intent_persistence_attempted,
            journal_may_have_partial_intent=intent_persistence_attempted and not intent_persisted,
            installation_authorized=False,
            automatic_STOP=False, automatic_retry=False, automatic_reset=False,
            automatic_reboot=False, automatic_restore=False)
        if uncertain:
            try:
                journal.advance('STOPPED_UNKNOWN', details=stopped)
            except BaseException:
                pass
        try:
            if folder.is_dir() and all(not p.is_symlink() for p in (folder, *folder.parents)):
                durable_new(folder / 'install-patch-stopped.json', stopped)
        except BaseException:
            pass
        raise
