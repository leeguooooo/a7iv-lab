"""Record explicit operator FL23 reports and selected local media identities.

No device, SDK, restart, firmware action or journal transition is provided.
Operator reports are not hardware attestations or precise color measurements.
"""
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat

import camera_postinstall_verify as verifier
from camera_install_journal import InstallJournal
from camera_install_completion import validate_completion_receipt
from camera_install_post_session import _read_reference, _sha, _reference
from camera_install_patch_session import _json, _safe_path, _known_stop, canonical_sha256
from camera_install_runtime_session import _check_files
from camera_stream_execution import durable_new
from camera_toolchain import PACKAGE_SHA

LOOKS = ('FL2', 'FL3')
KINDS = ('photo', 'video')
MEDIA_KEYS = tuple(look + '_' + kind for look in LOOKS for kind in KINDS)
SHA = re.compile(r'[0-9a-f]{64}\Z')
ASSERTIONS = ('shooting_completed', 'saved', 'playback_confirmed', 'menu_selection_confirmed', 'parameters_retained')
FALSE_CLAIMS = ('installation_authorized', 'write_admission', 'READY', 'device_execution_proven',
    'hardware_origin_proven', 'actual_NOR_verified', 'other_MCU_verified',
    'whole_device_recovery_proven', 'precise_color_accuracy_proven', 'real_cold_cycle_proven',
    'linux_epoch_change_proven', 'journal_changed', 'automatic_reboot')


def require(value, message):
    if not value:
        raise ValueError(message)


def _text(value, maximum=4096):
    return type(value) is str and 0 < len(value.strip()) <= maximum and '\x00' not in value


def validate_content_evidence(journal, content_reference, completion_reference, candidate_sha256):
    """Recompute the bound post-install content artifact from its actual inputs."""
    require(isinstance(journal, InstallJournal), 'Completed InstallJournal required')
    current = InstallJournal.open(journal.session_dir)
    history = current.events
    require(history == journal.events and current.state == 'CONTENT_VERIFIED', 'Fresh CONTENT_VERIFIED journal required')
    require(candidate_sha256 == PACKAGE_SHA, 'Fixed FL23 candidate SHA required')
    require(history[-1]['details'].get('verification_artifact') == content_reference,
            'Content artifact is not the journal CONTENT_VERIFIED reference')
    binding = current.binding
    completions = [(i, e) for i, e in enumerate(history) if e['state'] == 'DEVICE_COMPLETION_REPORTED']
    require(len(completions) == 1 and completions[0][1]['details'].get('device_completion_artifact') == completion_reference,
            'Original device completion artifact required')
    index, event = completions[0]
    completion = validate_completion_receipt(completion_reference, binding, history[:index], journal.session_dir)
    require(completion['candidate_sha256'] == candidate_sha256, 'Completion candidate differs')
    content_raw, content = _read_reference(content_reference)
    require(content.get('source_is_hardware') is True and content.get('all_passed') is True
            and all(content.get(k) == v for k, v in binding.items())
            and content.get('verification_scope') == 'FIRMWARE_FILES_AND_CRITICAL_SETTINGS',
            'Hardware-context scoped content verification required')
    group = _safe_path(content_reference['path']).parent
    _, descriptor = _json(group / 'group.json')
    require(descriptor.get('journal_session') == str(journal.session_dir.absolute())
            and all(descriptor.get(k) == v for k, v in binding.items()), 'Original capture group differs')
    exit_raw, exited = _json(group / 'post-session-exit.json')
    require(exited.get('state') == 'POST_KNOWN_SERVICE_EXIT'
            and exited.get('completion_reference') == completion_reference
            and exited.get('source_is_hardware') is True and exited.get('service_exit_completed') is True
            and all(exited.get(k) == v for k, v in binding.items()), 'Known post-capture service exit required')
    _known_stop(exited.get('service_events'))
    ref = exited['terminal_artifact']
    require(_safe_path(ref['path']) == group / 'post-terminal.json', 'Post terminal outside content group')
    raw, terminal = _json(ref['path'])
    require(_sha(raw) == ref['sha256'] and canonical_sha256(terminal) == ref['payload_sha256'], 'Post terminal changed')
    expected = deepcopy(exited)
    for key in ('terminal_artifact', 'service_events'):
        expected.pop(key)
    expected.update(state='POST_TERMINAL_DURABLE_BEFORE_STOP', service_exit_completed=False)
    require(terminal == expected, 'Post terminal payload differs')
    _check_files(group, terminal['evidence_files'])
    capture_raw, capture_run = _json(group / 'capture-run.json')
    expected_capture = deepcopy(terminal['capture_run'])
    expected_capture['known_service_STOP'] = True
    require(capture_run == expected_capture and capture_run.get('group_nonce') == content.get('group_nonce'),
            'Content capture-run differs from durable transaction')
    computed = verifier.verify_capture_run(group / 'capture-run.json', **binding,
        group_nonce=content['group_nonce'], source_is_hardware=True,
        plain_path=verifier.PLAIN, factory_p1_path=verifier.FACTORY_P1)
    require(computed == content and computed['all_passed'] is True, 'Content artifact does not recompute')
    require(InstallJournal.open(journal.session_dir).events == history
            and _read_reference(content_reference)[0] == content_raw, 'Content context changed during validation')
    return dict(**binding, session_id=journal.session_dir.name, candidate_sha256=candidate_sha256,
        content_reference=deepcopy(content_reference), completion_reference=deepcopy(completion_reference),
        content_event_sha256=history[-1]['event_sha256'], history_sha256=canonical_sha256(history),
        capture_run_sha256=_sha(capture_raw), post_exit_sha256=_sha(exit_raw))


def _identity(value):
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def _media(reference, kind):
    require(type(reference) is dict and set(reference) == {'path', 'sha256', 'bytes'}
            and type(reference['sha256']) is str and SHA.fullmatch(reference['sha256'])
            and type(reference['bytes']) is int and 0 < reference['bytes'] <= 0x7fffffffffffffff,
            'Exact positive local media reference required')
    path = _safe_path(reference['path'])
    require(str(path) == reference['path'], 'Canonical media path required')
    require(path.suffix.lower() in (('.jpg', '.jpeg', '.arw') if kind == 'photo' else ('.mp4', '.mov')),
            'Expected selected media extension required')
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_size == reference['bytes']
                and _identity(before) == _identity(path.stat()), 'Regular media identity or size differs')
        prefix = os.read(fd, min(32, reference['bytes']))
        if kind == 'photo':
            require(prefix.startswith(b'\xff\xd8\xff') or prefix.startswith((b'II*\0', b'MM\0*')), 'Recognized photo header required')
        else:
            require(len(prefix) >= 12 and prefix[4:8] == b'ftyp', 'Recognized video header required')
        digest = hashlib.sha256();digest.update(prefix);count = len(prefix)
        while True:
            raw = os.read(fd, min(4 << 20, reference['bytes'] - count + 1))
            if not raw:
                break
            count += len(raw);require(count <= reference['bytes'], 'Media grew during read')
            digest.update(raw)
        require(count == reference['bytes'] and digest.hexdigest() == reference['sha256'], 'Media full hash differs')
        after = os.fstat(fd)
        require(_identity(before) == _identity(after) == _identity(path.stat()) and not path.is_symlink(),
                'Media changed during read')
        return dict(reference, media_kind=kind, filesystem_identity=list(_identity(after))), (before.st_dev, before.st_ino)
    finally:
        os.close(fd)


def assess_functional_acceptance(*, journal, content_reference, completion_reference,
        candidate_sha256, operator_report, media_references):
    """Return operator-only observations; ordinary OFF/ON is partial retention evidence."""
    context = validate_content_evidence(journal, content_reference, completion_reference, candidate_sha256)
    require(type(operator_report) is dict and operator_report.get('explicit_operator_confirmation') is True
            and _text(operator_report.get('statement')) and _text(operator_report.get('reported_at_utc'), 128),
            'Explicit bounded operator statement and observation time required')
    try:
        reported_time = datetime.fromisoformat(operator_report['reported_at_utc'].replace('Z', '+00:00'))
    except ValueError as error:
        raise ValueError('Explicit ISO UTC observation time required') from error
    require(reported_time.tzinfo is not None and reported_time.utcoffset() == timezone.utc.utcoffset(reported_time),
            'Explicit UTC observation time required')
    entries = operator_report.get('looks')
    require(type(entries) is dict and set(entries) == set(LOOKS), 'Both FL2 and FL3 reports required')
    require(type(media_references) is dict and set(media_references) == set(MEDIA_KEYS), 'Four separate photo/video media references required')
    observed = {};identities=set();digests=set()
    for look in LOOKS:
        require(type(entries[look]) is dict and set(entries[look]) == set(KINDS), 'Separate photo and video reports required')
        observed[look] = {}
        for kind in KINDS:
            entry = entries[look][kind]
            key = look + '_' + kind
            require(type(entry) is dict and entry.get('media_key') == key
                    and all(entry.get(name) is True for name in ASSERTIONS), 'Complete explicit shooting/save/playback/menu/parameter report required')
            media, identity = _media(media_references[key], kind)
            require(identity not in identities and media['sha256'] not in digests, 'Media cannot be reused between FL23 tests')
            identities.add(identity);digests.add(media['sha256'])
            observed[look][kind] = dict(operator_assertions={name: True for name in ASSERTIONS}, media=media)
    restart = operator_report.get('restart')
    require(type(restart) is dict and restart.get('kind') in ('ORDINARY_OFF_ON', 'OPERATOR_REPORTED_UNPOWERED_CYCLE')
            and _text(restart.get('statement')), 'Explicit restart classification and statement required')
    retention_fields = ('performed', 'completed', 'camera_requested_steps_followed', 'menu_usable_after',
                        'FL2_retained_after', 'FL3_retained_after', 'parameters_retained_after')
    require(set(restart).issubset({'kind', 'statement', *retention_fields, 'power_removed_confirmed', 'power_restored_confirmed'})
            and all(type(restart.get(name)) is bool for name in retention_fields), 'Explicit restart observation fields required')
    require(all(type(restart[name]) is bool for name in ('power_removed_confirmed', 'power_restored_confirmed') if name in restart),
            'Restart power observations must be explicit Booleans')
    retention_complete = all(restart[name] is True for name in retention_fields)
    unpowered_reported = restart['kind'] == 'OPERATOR_REPORTED_UNPOWERED_CYCLE'
    if unpowered_reported:
        require(type(restart.get('power_removed_confirmed')) is bool and type(restart.get('power_restored_confirmed')) is bool,
                'Explicit unpowered-cycle observations required')
        retention_complete &= restart['power_removed_confirmed'] is True and restart['power_restored_confirmed'] is True
    all_accepted = retention_complete and unpowered_reported
    for entry in observed.values():
        for item in entry.values():
            media = item['media'];path = _safe_path(media['path'])
            require(list(_identity(path.stat())) == media['filesystem_identity'], 'Media changed after its readback')
    require(validate_content_evidence(journal, content_reference, completion_reference, candidate_sha256) == context,
            'Content context changed while reading media')
    result = dict(schema='camera-install-operator-functional-report/1',
        state='OPERATOR_REPORTED_FUNCTIONAL_ACCEPTANCE' if all_accepted else 'PARTIAL_OPERATOR_ACCEPTANCE', source_kind='EXPLICIT_OPERATOR_FUNCTIONAL_REPORT',
        **context, operator_statement=operator_report['statement'], reported_at_utc=operator_report['reported_at_utc'],
        looks=observed, photo_and_video_reported_complete=True, restart=deepcopy(restart),
        operator_reported_retention_complete=retention_complete, operator_partial_retention=not all_accepted,
        unpowered_cycle_reported=unpowered_reported, cold_cycle_not_verified=True,
        ALL_ACCEPTED=all_accepted, acceptance_scope='OPERATOR_ASSERTIONS_AND_SELECTED_LOCAL_MEDIA_IDENTITIES_ONLY',
        source_is_hardware=False, **dict.fromkeys(FALSE_CLAIMS, False),
        limitations=['Media hashes and headers do not prove the selected look, camera origin or precise color rendering',
                     'Ordinary OFF/ON does not establish a new Linux epoch or an unpowered cold cycle',
                     'An operator-reported unpowered cycle is not independent hardware cold-boot proof'])
    return result | dict(receipt_sha256=canonical_sha256(result))


def record_functional_acceptance(output, **options):
    """Persist a new local operator report without changing its journal."""
    output = Path(output).absolute()
    require('..' not in output.parts and all(not p.is_symlink() for p in (output, *output.parents))
            and output.parent.is_dir() and not output.exists(), 'Fresh nonsymlink local report path required')
    result = assess_functional_acceptance(**options)
    durable_new(output, result)
    raw, saved = _json(output)
    require(saved == result, 'Operator report host readback differs')
    return dict(path=str(output), sha256=_sha(raw), report=result, journal_changed=False)
