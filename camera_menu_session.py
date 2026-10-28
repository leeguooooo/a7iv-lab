"""Injected volatile-window orchestration; no CLI or automatic recovery.

A patch publication alone never authorizes unplug or installation. The existing
normal-session helper owns its success-only STOP. This adapter adds no STOP,
reset, reboot, authentication retry, or card activation operation.
"""
import contextlib
import hashlib
import io
import json
import math
import os
import stat
from pathlib import Path
import sys
import time

from camera_device_lease import CameraDeviceLease
from camera_install_journal import InstallJournal
from camera_operation_guard import assert_operation_allowed
from camera_stream_execution import durable_new

ROOT = Path(__file__).resolve().parent


def require(ok, message):
    if not ok:
        raise ValueError(message)


def _require_held_lease(lease):
    require(isinstance(lease, CameraDeviceLease) and lease.fd is not None
            and isinstance(lease.metadata, dict) and lease.metadata.get('state') == 'HELD',
            'Caller-held CameraDeviceLease required')
    descriptor = os.fstat(lease.fd)
    location = os.stat(lease.path, follow_symlinks=False)
    require(stat.S_ISREG(descriptor.st_mode) and stat.S_ISREG(location.st_mode)
            and (descriptor.st_dev, descriptor.st_ino) == (location.st_dev, location.st_ino),
            'Live caller lease descriptor required')


def _probe_normal(expected):
    """One read-only normal enumeration/info query; SDK imports remain lazy."""
    require(isinstance(expected, str) and len(expected) == 64
            and all(c in '0123456789abcdef' for c in expected), 'Reference body SHA-256 required')
    from camera_stream_usb_session import _finite_timeout
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        sdk_path = str(ROOT / 'Sony-PMCA-RE')
        if sdk_path not in sys.path:
            sys.path.insert(0, sdk_path)
        from pmca.commands.usb import importDriver, listDevices
        from pmca.usb.sony import SonyMscExtCmdDevice, SonyExtCmdCamera
        from pmca.usb.driver.generic import GenericUsbDriver
        with importDriver('libusb') as driver:
            devices = list(listDevices(driver, quiet=True))
            if not devices:
                return None
            require(len(devices) == 1, 'Ambiguous normal-mode USB identity')
            normal = devices[0]
            if not isinstance(normal, SonyMscExtCmdDevice):
                return None
            require(isinstance(normal.driver, GenericUsbDriver)
                    and normal.driver.getId() == (0x054c, 0x0da5), 'Unsupported normal USB path')
            require(_finite_timeout(normal.driver), 'Finite normal libusb timeout required')
            require(SonyExtCmdCamera(normal).getCameraInfo().modelName == 'ILCE-7M4', 'Normal model changed')
            serial = normal.driver.backend.dev.serial_number
            require(isinstance(serial, str) and bool(serial)
                    and hashlib.sha256(serial.encode()).hexdigest() == expected, 'Normal reference body mismatch')
            return dict(model='ILCE-7M4', body_sha256=expected, body_matched=True,
                        usb_vendor=0x054c, usb_product=0x0da5, finite_driver_timeout=True)


def wait_for_normal(expected_body_sha256, *, timeout=30, clock=time.monotonic, sleep=time.sleep):
    require(type(timeout) in (int, float) and math.isfinite(timeout) and 0 < timeout <= 30,
            'Bounded normal-mode wait required')
    deadline = clock() + timeout
    while clock() < deadline:
        result = _probe_normal(expected_body_sha256)
        if result is not None:
            return result
        sleep(0.25)
    raise TimeoutError('Same-body normal MSC did not reappear; RAM state remains unknown')


def run_menu_session(expected_body_sha256, evidence, *, plan_sha256, journal, lease,
                     ram_authorized=False, run_session=None, wait_normal=None,
                     start_fn=None, window_assets=None, capture_assets=None,
                     clock=time.monotonic, sleep=time.sleep):
    """Caller holds a lease and supplies a fresh, body-bound SD_STAGED ledger.

    Injection is for offline testing and reviewed host integration. No countdown
    is a restore receipt. Unknown outcomes never trigger another device request.
    """
    folder = Path(evidence)
    phase = 'LOCAL_PREFLIGHT'
    started = clock()
    ram_intent_persisted = device_session_started = intent_persistence_attempted = False
    try:
        require(ram_authorized is True, 'Explicit RAM authorization required')
        _require_held_lease(lease)
        require(isinstance(journal, InstallJournal), 'InstallJournal required')
        require(journal.binding == dict(plan_sha256=plan_sha256, body_sha256=expected_body_sha256,
                                       model='ILCE-7M4'), 'Journal plan/body binding mismatch')
        fresh = InstallJournal.open(journal.session_dir)
        require(fresh.events == journal.events and fresh.state == 'SD_STAGED',
                'Fresh SD_STAGED journal required')
        assert_operation_allowed(journal,allowed_states=('SD_STAGED',))
        require(folder.is_dir() and not folder.is_symlink(), 'Local evidence directory required')
        phase = 'LOCAL_RAM_INTENT_PERSISTENCE'
        intent_persistence_attempted = True
        journal.advance('RAM_MAY_BE_ACTIVE', details={'operation': 'menu-window', 'automatic_retry': False})
        ram_intent_persisted = True
        phase = 'RAM_MAY_BE_ACTIVE'
        hardware = run_session is None and start_fn is None and wait_normal is None
        if run_session is None:
            from camera_stream_usb_session import run_normal_session
            run_session = run_normal_session
        if start_fn is None:
            from camera_menu_window import start_authenticated
            start_fn = start_authenticated
        if wait_normal is None:
            wait_normal = wait_for_normal
        events = []
        observed_at = None
        def set_stage(value):
            nonlocal phase
            phase = value
        def work(device):
            nonlocal observed_at
            options={}
            if window_assets is not None:options['assets']=window_assets
            if capture_assets is not None:options['capture_assets']=capture_assets
            observed = start_fn(device, folder, ram_authorized=True, body_verified=True,
                                source_is_hardware=hardware, clock=clock, sleep=sleep,**options)
            require(isinstance(observed, dict)
                    and observed.get('state') == 'PATCH_OBSERVED_AWAITING_KNOWN_EXIT_AND_NORMAL_BODY'
                    and type(observed.get('source_is_hardware')) is bool
                    and observed.get('installation_authorized') is False, 'Validated patch observation required')
            budget = observed.get('conservative_seconds_remaining')
            require(type(budget) in (int, float) and math.isfinite(budget) and budget >= 120,
                    'Insufficient patch window before service exit')
            observed = dict(observed, source_is_hardware=hardware and observed['source_is_hardware'])
            observed_at = clock()
            require(math.isfinite(observed_at) and observed_at >= started,
                    'Monotonic clock regressed during patch observation')
            return observed
        device_session_started = True
        patch = run_session(expected_body_sha256, work, record_event=events.append, set_stage=set_stage)
        phase = 'KNOWN_SERVICE_EXIT_AWAITING_NORMAL'
        require(isinstance(patch, dict)
                and patch.get('state') == 'PATCH_OBSERVED_AWAITING_KNOWN_EXIT_AND_NORMAL_BODY'
                and type(patch.get('source_is_hardware')) is bool
                and patch.get('installation_authorized') is False, 'Validated patch observation required')
        patch = dict(patch, source_is_hardware=hardware and patch['source_is_hardware'])
        remaining = patch.get('conservative_seconds_remaining')
        require(type(remaining) in (int, float) and math.isfinite(remaining), 'Finite patch budget required')
        normal = wait_normal(expected_body_sha256, timeout=30, clock=clock, sleep=sleep)
        require(isinstance(normal, dict) and normal.get('model') == 'ILCE-7M4'
                and normal.get('body_sha256') == expected_body_sha256
                and normal.get('body_matched') is True and normal.get('usb_vendor') == 0x054c
                and normal.get('usb_product') == 0x0da5 and normal.get('finite_driver_timeout') is True,
                'Same-body normal MSC proof required')
        now = clock()
        require(observed_at is not None and math.isfinite(now) and now >= observed_at >= started,
                'Monotonic clock regressed during handoff')
        elapsed = now - observed_at
        require(math.isfinite(elapsed) and remaining - elapsed >= 90,
                'Insufficient conservative window after service exit and normal reappearance')
        result = dict(state='VOLATILE_WINDOW_HANDOFF', plan_sha256=plan_sha256,
                      body_sha256=expected_body_sha256, model='ILCE-7M4',
                      patch_observation=patch, normal_body=normal, service_exit_completed=True,
                      source_is_hardware=patch['source_is_hardware'],
                      normal_body_reappearance_verified=True, conservative_seconds_remaining=remaining-elapsed,
                      budget_basis='patch_report_remaining_minus_post_observation_elapsed',
                      patch_observed_monotonic=observed_at, post_observation_elapsed_seconds=elapsed,
                      installation_authorized=False, firmware_installation_proven=False,
                      RAM_original_state_verified=False, timer_is_independent_watchdog=False,
                      automatic_retry=False, automatic_STOP=False, automatic_reboot=False)
        journal.advance('READY_FOR_CONFIRMATION', details={
            'state': result['state'], 'conservative_seconds_remaining': remaining-elapsed,
            'budget_basis': result['budget_basis'],
            'window_nonce':patch['nonce'],
            'patch_observation_sha256':hashlib.sha256(json.dumps(patch,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
            'installation_authorized': False})
        durable_new(folder / 'session-handoff.json', result)
        return result
    except BaseException as error:
        # Preserve the original exception even when local report/ledger persistence fails.
        uncertain = ram_intent_persisted or device_session_started
        stopped = dict(state='STOPPED_UNKNOWN' if uncertain else 'LOCAL_REJECTED_NO_DEVICE_SESSION',
                       phase=phase, error_type=type(error).__name__,
                       device_session_started=device_session_started,
                       ram_intent_persisted=ram_intent_persisted,
                       intent_persistence_attempted=intent_persistence_attempted,
                       journal_may_have_partial_intent=intent_persistence_attempted and not ram_intent_persisted,
                       RAM_original_state_verified=False, installation_authorized=False,
                       automatic_STOP=False, automatic_reboot=False, automatic_retry=False)
        try:
            durable_new(folder / 'session-stopped.json', stopped)
        except BaseException:
            # A rejected missing evidence directory cannot contain its own report.
            # Keep the refusal next to it when its parent is a safe local directory.
            if not uncertain:
                try:
                    if folder.parent.is_dir() and not folder.parent.is_symlink():
                        durable_new(folder.parent / (folder.name + '-local-rejected.json'), stopped)
                except BaseException:
                    pass
        if uncertain and isinstance(journal, InstallJournal):
            try:
                journal.advance('STOPPED_UNKNOWN', details=stopped)
            except BaseException:
                pass
        raise


def _restoration_native_proof(observation, proof):
    """Recheck the fixed record ABI and original worker/targets locally."""
    from camera_menu_window import FIELDS, FRAME, decode, ready_proof, patched_proof, terminal_proof
    nonce = bytes.fromhex(observation['nonce'])
    def checked(row):
        require(isinstance(row, dict) and set(row) == set(FIELDS), 'Complete native identity record required')
        raw = FRAME.pack(b'M4DWL002', nonce, *(row[name] for name in FIELDS))
        return decode(raw, nonce)
    ready, patched, native = (checked(row) for row in
                              (observation['ready'], observation['patched'], proof['native']))
    ready_proof(ready, ready['loader_pid'])
    patched_proof(patched, ready)
    verified = terminal_proof(native, ready, patched)
    require(proof.get('both_RAM_targets_proven_safe') is True
            and proof.get('native_terminal_observed') is True
            and verified['both_RAM_targets_proven_safe'] is True,
            'Both RAM targets require an original native restoration receipt')
    return verified, native


def collect_menu_restoration(expected_body_sha256, evidence, handoff, *, plan_sha256,
                             journal, lease, collection_authorized=False,
                             firmware_never_started_confirmed=False, run_session=None,
                             collect_fn=None, assets=None, clock=time.monotonic, sleep=time.sleep):
    """Collect the old window receipt once; never upload, START or infer restore.

    A new authenticated normal session is authorized only for reading the old
    publications. A known success STOP belongs exclusively to run_normal_session.
    Model declarations are preserved and cannot close a hardware ledger.
    """
    folder = Path(evidence)
    phase, attempted = 'LOCAL_PREFLIGHT', False
    try:
        require(collection_authorized is True and firmware_never_started_confirmed is True,
                'Explicit collection and no-firmware-start confirmations required')
        _require_held_lease(lease)
        require(isinstance(journal, InstallJournal), 'InstallJournal required')
        binding = dict(plan_sha256=plan_sha256, body_sha256=expected_body_sha256, model='ILCE-7M4')
        require(journal.binding == binding, 'Journal plan/body binding mismatch')
        fresh = InstallJournal.open(journal.session_dir)
        require(fresh.events == journal.events and fresh.state in ('READY_FOR_CONFIRMATION', 'RAM_MAY_BE_ACTIVE'),
                'Fresh open volatile RAM journal required')
        assert_operation_allowed(journal, allowed_states=('READY_FOR_CONFIRMATION', 'RAM_MAY_BE_ACTIVE'))
        require(not any(event['state'] == 'FLASH_MAY_HAVE_STARTED' for event in fresh.events),
                'Collection forbidden after possible firmware flash')
        require(isinstance(handoff, dict) and all(handoff.get(key) == value for key, value in binding.items()),
                'Original handoff plan/body binding required')
        observation = handoff['patch_observation']
        require(isinstance(observation, dict)
                and observation.get('state') == 'PATCH_OBSERVED_AWAITING_KNOWN_EXIT_AND_NORMAL_BODY'
                and type(observation.get('source_is_hardware')) is bool,
                'Original patch observation and evidence kind required')
        # Reject inconsistent/missing original evidence before a default real
        # session. Model callbacks remain useful for pure host tests only.
        require(observation['source_is_hardware'] is True
                or (run_session is not None and collect_fn is not None),
                'Hardware original observation required before a real collection session')
        from camera_menu_window import FIELDS,FRAME,decode,ready_proof,patched_proof
        nonce=bytes.fromhex(observation['nonce'])
        def original(row):
            require(isinstance(row,dict) and set(row)==set(FIELDS),'Complete original native record required')
            return decode(FRAME.pack(b'M4DWL002',nonce,*(row[name] for name in FIELDS)),nonce)
        original_ready,original_patched=original(observation['ready']),original(observation['patched'])
        ready_proof(original_ready,original_ready['loader_pid']);patched_proof(original_patched,original_ready)
        require(folder.is_dir() and not folder.is_symlink(), 'Local evidence directory required')
        hardware = run_session is None and collect_fn is None and observation['source_is_hardware']
        if run_session is None:
            from camera_stream_usb_session import run_normal_session
            run_session = run_normal_session
        if collect_fn is None:
            from camera_menu_window import collect_authenticated
            collect_fn = collect_authenticated
        events = []
        def set_stage(value):
            nonlocal phase
            phase = value
        def work(device):
            collected = collect_fn(device, folder/'native-collection', observation,
                body_verified=True, firmware_never_started_confirmed=True,
                assets=assets, clock=clock, sleep=sleep)
            # Invalid or unknown callback receipts must not trigger success STOP.
            _restoration_native_proof(observation, collected)
            return collected
        attempted = True
        collected = run_session(expected_body_sha256, work, record_event=events.append, set_stage=set_stage)
        phase = 'KNOWN_COLLECTION_SERVICE_EXIT'
        verified, native = _restoration_native_proof(observation, collected)
        result = dict(state='RAM_RESTORATION_RECEIPT_OBSERVED', scope='VOLATILE_RAM_WINDOW_ONLY',
            **binding, source_is_hardware=hardware, all_passed=True,
            both_RAM_targets_proven_safe=verified['both_RAM_targets_proven_safe'],
            native_terminal_observed=True, native=native, nonce=observation['nonce'],
            firmware_flash_was_never_started=True,
            firmware_never_started_operator_confirmed=True,
            firmware_installation_proven=False, installation_authorized=False,
            service_exit_completed=True, module_uploads=0, START_attempts=0,
            timer_is_independent_watchdog=False, elapsed_time_is_not_restoration_proof=True,
            automatic_retry=False, automatic_STOP=False, automatic_reboot=False)
        artifact = folder/'ram-restoration.json'
        durable_new(artifact, result)
        # This specialized API checks hardware provenance declaration and RAM-only
        # scope. Ordinary advance is never allowed to manufacture this endpoint.
        journal.record_ram_restoration_verified(artifact)
        return result
    except BaseException as error:
        stopped = dict(state='STOPPED_UNKNOWN' if attempted else 'LOCAL_REJECTED_NO_DEVICE_SESSION',
            phase=phase, error_type=type(error).__name__, device_session_started=attempted,
            firmware_installation_proven=False, installation_authorized=False,
            automatic_retry=False, automatic_STOP=False, automatic_reboot=False,
            elapsed_time_is_not_restoration_proof=True)
        try:
            durable_new(folder/'restoration-stopped.json', stopped)
        except BaseException:
            pass
        if attempted and isinstance(journal, InstallJournal):
            try:
                journal.advance('STOPPED_UNKNOWN', details=stopped)
            except BaseException:
                pass
        raise
