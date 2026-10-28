"""Injected before/after collection groups; no CLI, flash or recovery actions.

Caller holds CameraDeviceLease and the bound InstallJournal. Real normal-session
callbacks prove body context; injected sessions/readers/capturers are models and
are always labelled non-hardware. Finite blocking timeouts remain an underlying
normal-session driver requirement; a Python deadline cannot interrupt native I/O.
A successful service STOP response does not prove normal USB reappearance,
physical health, photography, other MCU or real NOR content.
"""
import hashlib
import json
import os
from pathlib import Path
from camera_operation_guard import assert_operation_allowed
import re
import secrets
import stat
import struct
import time

from camera_backup_records import record_map
from camera_device_lease import CameraDeviceLease
from camera_install_journal import InstallJournal
from camera_stream_execution import durable_new

PDT_BYTES = 2369436
MODEL = 'ILCE-7M4'
NONCE = re.compile(r'[0-9a-f]{32}\Z')
SHA = re.compile(r'[0-9a-f]{64}\Z')
PROFILES = ('post_app', 'post_cp', 'post_p1')


def require(ok, message):
    if not ok:
        raise ValueError(message)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _path(path, *, directory=False):
    path = Path(path).absolute()
    require(all(not p.is_symlink() for p in (path, *path.parents)), 'Symlink evidence forbidden')
    if directory:
        require(path.is_dir(), 'Group directory required')
    else:
        require(stat.S_ISREG(path.stat().st_mode), 'Regular evidence required')
    return path


def _inside(group, value):
    require(isinstance(value, str), 'Evidence path must be a string')
    path = _path(group / value)
    require(path.resolve().is_relative_to(group.resolve()), 'Evidence outside collection group')
    return path


def _json(path):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'Duplicate JSON field')
            result[key] = value
        return result
    value = json.loads(_path(path).read_text(), object_pairs_hook=pairs)
    require(isinstance(value, dict), 'JSON object required')
    return value


def _preflight(expected, plan, journal, lease, states):
    require(isinstance(expected, str) and SHA.fullmatch(expected)
            and isinstance(plan, str) and SHA.fullmatch(plan), 'Plan/body SHA required')
    require(isinstance(lease, CameraDeviceLease) and lease.fd is not None
            and isinstance(lease.metadata, dict) and lease.metadata.get('state') == 'HELD',
            'Caller-held CameraDeviceLease required')
    metadata = os.fstat(lease.fd)
    location = os.stat(lease.path, follow_symlinks=False)
    require(stat.S_ISREG(metadata.st_mode) and (metadata.st_dev, metadata.st_ino) ==
            (location.st_dev, location.st_ino), 'Live caller lease descriptor required')
    require(isinstance(journal, InstallJournal), 'InstallJournal required')
    binding = dict(plan_sha256=plan, body_sha256=expected, model=MODEL)
    require(journal.binding == binding, 'Journal plan/body/model mismatch')
    current = InstallJournal.open(journal.session_dir)
    require(current.events == journal.events and current.state in states, 'Fresh declared journal phase required')
    assert_operation_allowed(journal,allowed_states=states)
    return binding


def _stop(group, journal, phase, error):
    stopped = dict(state='STOPPED_UNKNOWN', phase=phase, error_type=type(error).__name__,
                   automatic_retry=False, automatic_STOP=False, automatic_reset=False,
                   automatic_reboot=False, automatic_rollback=False)
    try:
        folder = Path(group).absolute()
        require(all(not p.is_symlink() for p in (folder, *folder.parents)), 'Unsafe stopped evidence path')
        if not folder.exists():
            folder.mkdir(mode=0o700)
        durable_new(folder / ('capture-' + phase.lower() + '-stopped.json'), stopped)
    except BaseException:
        pass
    if isinstance(journal, InstallJournal):
        try:
            journal.advance('STOPPED_UNKNOWN', details=stopped)
        except BaseException:
            pass


def read_pdt_bounded(device, *, clock=time.monotonic, send_packet=None):
    """One reviewed PDT-from-memory read. No SDK getBackupPresetData buffering.

    Sony.py: SONY_PFUNC_AdjustControl=0x40, CommandHeader two LE16 fields,
    SONY_ADJUST_BACKUP_PDT_READ=(0x603,5), fromMemory=01, response=0.
    """
    from camera_stream_channel import _DriverProxy
    from camera_stream_transport_bounds import BoundedSink
    if send_packet is None:
        from camera_stream_senser import send_senser_packet
        send_packet = send_senser_packet
    original = device.driver
    try:
        device.driver = _DriverProxy(original, clock() + 120, clock)
        with BoundedSink(PDT_BYTES) as sink:
            response, _ = send_packet(device, 0x40, struct.pack('<HH', 0x603, 5) + b'\x01', sink)
            require(response == 0, 'PDT response rejected')
            raw = sink.getvalue()
        require(len(raw) == PDT_BYTES, 'PDT length changed')
        record_map(raw)
        return raw
    finally:
        # Pure host pointer restoration only. No STOP/reset/cleanup device I/O.
        device.driver = original


def _save_pdt(group, phase, nonce, binding, group_nonce, source, device, reader, clock):
    raw = reader(device, clock=clock)
    require(isinstance(raw, bytes) and len(raw) == PDT_BYTES, 'PDT length changed')
    record_map(raw)
    file = group / (phase + '.bk4')
    fd = os.open(file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    with os.fdopen(fd, 'wb') as output:
        require(output.write(raw) == len(raw), 'Short local PDT write')
        output.flush(); os.fsync(output.fileno())
    require(_sha(file.read_bytes()) == _sha(raw), 'PDT host readback mismatch')
    return dict(binding, path=file.name, sha256=_sha(raw), group_nonce=group_nonce,
                nonce=nonce, source_is_hardware=source,
                acquisition_phase='PRE_INSTALL' if phase == 'before' else 'POST_INSTALL')


def _session(expected, callback, *, run_session, hardware, phase):
    events = []
    stages = []
    observed = None
    normal = False
    used = False
    def event(value):
        nonlocal normal
        require(isinstance(value, dict), 'Invalid normal-session event')
        if value.get('model') == MODEL and value.get('body_matched') is True:
            normal = True
        events.append(value)
    def work(device):
        nonlocal used, observed
        require(not used and normal, 'One verified normal-body callback required')
        used = True
        observed = callback(device, hardware)
        return observed
    result = run_session(expected, work, record_event=event, set_stage=stages.append)
    require(used and result is observed, 'Session did not return its verified callback result')
    require(any(e.get('event') == 'STOP_RESPONSE' and e.get('mode') == 'service'
                and (e.get('success') is True or e.get('known_pipe_response') is True) for e in events),
            'Known service STOP response required before publishing collection')
    return result


def capture_settings_before(expected_body_sha256, group, *, plan_sha256, journal, lease,
                            group_nonce=None, run_session=None, pdt_reader=None,
                            clock=time.monotonic):
    """Capture PRE_INSTALL PDT while PLANNED/SD_STAGED, before any RAM window.

    group must not exist. Returns bound group/before references after known STOP.
    Injected dependencies are for offline models and never establish hardware.
    """
    folder = Path(group).absolute()
    phase = 'BEFORE'
    session_attempted = False
    try:
        binding = _preflight(expected_body_sha256, plan_sha256, journal, lease, {'PLANNED', 'SD_STAGED'})
        require(all(not p.is_symlink() for p in (folder, *folder.parents)), 'Symlink group forbidden')
        folder.mkdir(mode=0o700)
        group_nonce = secrets.token_hex(16) if group_nonce is None else group_nonce
        require(isinstance(group_nonce, str) and NONCE.fullmatch(group_nonce), 'Group nonce required')
        nonce = secrets.token_hex(16)
        require(nonce != group_nonce, 'Settings nonce must differ from group nonce')
        hardware = run_session is None and pdt_reader is None
        if run_session is None:
            from camera_stream_usb_session import run_normal_session
            run_session = run_normal_session
        reader = read_pdt_bounded if pdt_reader is None else pdt_reader
        descriptor = dict(binding, schema='camera-capture-group/1', group_nonce=group_nonce,
                          journal_session=str(journal.session_dir.absolute()))
        durable_new(folder / 'group.json', descriptor)
        durable_new(folder / 'before-attempt.json', dict(descriptor, nonce=nonce, automatic_retry=False))
        session_attempted = True
        before = _session(expected_body_sha256,
            lambda device, source: _save_pdt(folder, 'before', nonce, binding, group_nonce,
                                              source, device, reader, clock),
            run_session=run_session, hardware=hardware, phase=phase)
        durable_new(folder / 'before-reference.json', before)
        return dict(descriptor, group=str(folder), before=before, normal_body_verified=True,
                    source_is_hardware=hardware)
    except BaseException as error:
        if session_attempted:
            _stop(folder, journal, phase, error)
        # Local rejection keeps journal history and partial local intent evidence.
        raise


def capture_after_install(expected_body_sha256, group, *, plan_sha256, journal, lease,
                          run_session=None, capture_fn=None, pdt_reader=None,
                          assets=None, clock=time.monotonic, sleep=time.sleep):
    """Post-completion app/CP/P1 then PDT; publish run only after known STOP.

    No phase advances toward flashing and no CONTENT_VERIFIED assertion here.
    Any failure preserves the original exception and stops the journal locally.
    """
    folder = Path(group).absolute()
    phase = 'AFTER'
    session_attempted = False
    try:
        binding = _preflight(expected_body_sha256, plan_sha256, journal, lease, {'DEVICE_COMPLETION_REPORTED'})
        _path(folder, directory=True)
        descriptor = _json(folder / 'group.json')
        require(all(descriptor.get(k) == v for k, v in binding.items())
                and descriptor.get('schema') == 'camera-capture-group/1'
                and descriptor.get('journal_session') == str(journal.session_dir.absolute()), 'Group binding mismatch')
        group_nonce = descriptor['group_nonce']
        require(isinstance(group_nonce, str) and NONCE.fullmatch(group_nonce), 'Invalid group nonce')
        before = _json(folder / 'before-reference.json')
        require(all(before.get(k) == v for k, v in binding.items())
                and before.get('group_nonce') == group_nonce
                and before.get('acquisition_phase') == 'PRE_INSTALL', 'Before reference binding/phase mismatch')
        before_path = _inside(folder, before['path'])
        raw = before_path.read_bytes()
        require(len(raw) == PDT_BYTES and _sha(raw) == before['sha256'], 'Before PDT changed')
        record_map(raw)
        hardware = run_session is None and pdt_reader is None and capture_fn is None
        require(before.get('source_is_hardware') is hardware, 'Before/after trusted source context mismatch')
        seen = {group_nonce}
        nonce = before['nonce']
        require(isinstance(nonce, str) and NONCE.fullmatch(nonce) and nonce not in seen, 'Before nonce invalid/reused')
        seen.add(nonce)
        after_nonce = secrets.token_hex(16)
        require(after_nonce not in seen, 'After nonce reused')
        seen.add(after_nonce)
        expected_nonces = {}
        asset_options={} if assets is None else {'assets':assets}
        if capture_fn is None:
            from camera_firmware_capture import capture_one_authenticated, checked_capture_assets
            capture_fn = capture_one_authenticated
            for name in PROFILES:
                nonce = checked_capture_assets(name,**asset_options)['nonce'].hex()
                require(nonce not in seen, 'Prepared firmware nonce reused in group')
                seen.add(nonce)
                expected_nonces[name] = nonce
            # During collection each returned nonce must match its reviewed job.
        if run_session is None:
            from camera_stream_usb_session import run_normal_session
            run_session = run_normal_session
        reader = read_pdt_bounded if pdt_reader is None else pdt_reader
        durable_new(folder / 'after-attempt.json', dict(descriptor, nonce=after_nonce, automatic_retry=False))
        def work(device, source):
            references = {}
            returned_nonces = {group_nonce, before['nonce'], after_nonce}
            for name in PROFILES:
                report = capture_fn(device, name, folder / name, source_is_hardware=source,
                                    clock=clock, sleep=sleep,**asset_options)
                require(isinstance(report, dict) and report.get('profile') == name
                        and report.get('name') == name and report.get('source_is_hardware') is source,
                        'Firmware capture report/context mismatch')
                nonce = report.get('nonce')
                require(isinstance(nonce, str) and NONCE.fullmatch(nonce)
                        and nonce not in returned_nonces, 'Firmware nonce invalid/reused')
                require(name not in expected_nonces or nonce == expected_nonces[name], 'Prepared capture nonce changed')
                returned_nonces.add(nonce)
                path = _inside(folder, name + '/firmware-capture.json')
                require(_json(path) == report, 'Firmware result differs from persisted report')
                references[name] = dict(binding, path=str(path.relative_to(folder)), sha256=_sha(path.read_bytes()),
                                        group_nonce=group_nonce)
            after = _save_pdt(folder, 'after', after_nonce, binding, group_nonce, source, device, reader, clock)
            return dict(binding, schema='camera-postinstall-capture-run/1', group_nonce=group_nonce,
                        normal_body_verified=True, source_is_hardware=source, captures=references,
                        critical_settings={'before': before, 'after': after}, known_service_STOP=True,
                        photo_verified=False, video_verified=False, actual_NOR_verified=False)
        session_attempted = True
        run = _session(expected_body_sha256, work, run_session=run_session, hardware=hardware, phase=phase)
        durable_new(folder / 'capture-run.json', run)
        return dict(run, path=str(folder / 'capture-run.json'))
    except BaseException as error:
        if session_attempted:
            _stop(folder, journal, phase, error)
        # Local rejection keeps journal history and partial local intent evidence.
        raise
