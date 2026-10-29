"""Assess cancellation evidence without clearing a ledger or issuing card writes.

The filesystem observer is explicitly injected. This module has no discovery,
SDK, reboot, restoration, withdrawal, journal transition, or hardware entry.
"""
from contextlib import ExitStack
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat

from camera_sd_stage import DIGEST as CANDIDATE_SHA256, SIZE as CANDIDATE_BYTES, staged_relative_path

STABLE_KEYS = ('body_sha256', 'volume_uuid', 'filesystem', 'volume_bytes')
HANDLE_KEYS = STABLE_KEYS + ('device', 'parent', 'mount', 'registry_id')


def require(value, message):
    if not value:
        raise ValueError(message)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def _safe_path(value):
    path = Path(value).absolute()
    require('..' not in path.parts and all(not p.is_symlink() for p in (path, *path.parents)),
            'Canonical nonsymlink evidence path required')
    return path


def _json_reference(reference):
    require(isinstance(reference, dict) and set(reference) == {'path', 'sha256'}, 'Exact artifact reference required')
    path = _safe_path(reference['path'])
    require(path.is_file(), 'Regular evidence artifact required')
    raw = path.read_bytes()
    require(_sha(raw) == reference['sha256'], 'Evidence artifact hash differs')
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'Duplicate evidence field')
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=pairs)
    require(isinstance(value, dict), 'Evidence object required')
    return path, raw, value


def _identity(value, body):
    require(isinstance(value, dict) and value.get('body_matched') is True
            and value.get('body_sha256') == body, 'Same-body card observation required')
    require(isinstance(value.get('volume_uuid'), str) and value['volume_uuid']
            and value.get('filesystem') in ('exfat', 'msdos')
            and type(value.get('volume_bytes')) is int and value['volume_bytes'] > 0,
            'Stable card identity required')
    require(isinstance(value.get('mount'), str) and Path(value['mount']).is_absolute(), 'Absolute card mount required')
    require(all(key in value for key in HANDLE_KEYS), 'Complete current card handles required')
    return {key: value[key] for key in HANDLE_KEYS}


def _stat_identity(value):
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def _hash_open_file(path, stack, expected_bytes, mount, mount_fd):
    _safe_path(path)
    require(path.is_file() and not path.is_symlink(), 'Regular card file required')
    relative = path.relative_to(mount)
    directory_fd = mount_fd
    for part in relative.parts[:-1]:
        directory_fd = os.open(part, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0)
                               | getattr(os, 'O_NOFOLLOW', 0), dir_fd=directory_fd)
        stack.callback(os.close, directory_fd)
    fd = os.open(relative.name, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0), dir_fd=directory_fd)
    stack.callback(os.close, fd)
    before = os.fstat(fd)
    require(stat.S_ISREG(before.st_mode) and _stat_identity(before) == _stat_identity(path.stat()),
            'Opened card file differs from pathname')
    require(before.st_size == expected_bytes, 'Card file size differs before readback')
    if hasattr(fcntl, 'F_NOCACHE'):
        fcntl.fcntl(fd, fcntl.F_NOCACHE, 1)
    digest = hashlib.sha256()
    count = 0
    while True:
        raw = os.read(fd, min(4 << 20, expected_bytes - count + 1))
        if not raw:
            break
        digest.update(raw)
        count += len(raw)
        require(count <= expected_bytes, 'Card file grew during readback')
    after = os.fstat(fd)
    require(_stat_identity(before) == _stat_identity(after)
            and not path.is_symlink() and _stat_identity(after) == _stat_identity(path.stat()),
            'Card file changed during read')
    return dict(path=str(path), bytes=count, sha256=digest.hexdigest(),
                descriptor_identity=list(_stat_identity(after)), _descriptor=fd)


def observe_inactive_card(stage_reference, *, body_sha256, discover):
    """Read an already inactive candidate using an injected filesystem observer.

    Reconnect may change handles before the initial observation. All handles
    and opened file identities are pinned for the duration of this read.
    """
    require(callable(discover), 'Explicit filesystem observer required; no real discovery entry')
    require(isinstance(body_sha256, str) and len(body_sha256) == 64
            and all(c in '0123456789abcdef' for c in body_sha256), 'Exact body SHA256 required')
    stage_path, stage_raw, stage = _json_reference(stage_reference)
    require(stage.get('state') == 'STAGED_UNRECOGNIZED_FILE_VERIFIED_NOT_ACTIVATED'
            and stage.get('source_sha256') == CANDIDATE_SHA256 and stage.get('bytes') == CANDIDATE_BYTES
            and stage.get('existing_root_update_unchanged') is True
            and stage.get('BODYDATA_DAT_created_or_replaced') is False
            and stage.get('camera_internal_firmware_modified') is False
            and stage.get('updater_invoked') is False, 'Complete inactive stage receipt required')
    old = _identity(stage.get('volume_identity'), body_sha256)
    relative = staged_relative_path(stage.get('target'), old['mount'], CANDIDATE_SHA256)
    pinned = _identity(dict(discover()), body_sha256)
    require(all(pinned[key] == old[key] for key in STABLE_KEYS), 'Stable card identity changed since staging')
    mount = _safe_path(pinned['mount'])
    candidate = _safe_path(mount / relative)
    root_update = mount / 'BODYDATA.DAT'
    require(mount.is_dir() and candidate != root_update and candidate.parent.parent == mount / '.camera-use-staging',
            'Inactive staged candidate path required')
    existing = stage.get('existing_root_update')
    require(isinstance(existing, dict) and type(existing.get('exists')) is bool, 'Original root snapshot required')
    if existing['exists']:
        require(set(existing) == {'exists', 'bytes', 'sha256'} and type(existing['bytes']) is int
                and existing['bytes'] >= 0 and isinstance(existing['sha256'], str) and len(existing['sha256']) == 64,
                'Complete original root snapshot required')
        require(existing['sha256'] != CANDIDATE_SHA256, 'Original root snapshot already names active candidate')
    else:
        require(existing == {'exists': False}, 'Exact absent-root baseline required')
    observations = [pinned]
    with ExitStack() as stack:
        mount_fd = os.open(mount, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0) | getattr(os, 'O_NOFOLLOW', 0))
        stack.callback(os.close, mount_fd)
        mount_identity = os.fstat(mount_fd)
        def unchanged():
            current = _identity(dict(discover()), body_sha256)
            observations.append(current)
            require(current == pinned, 'Camera/card handles changed during read')
            location = mount.stat()
            require(not mount.is_symlink() and (location.st_dev, location.st_ino) ==
                    (mount_identity.st_dev, mount_identity.st_ino), 'Mounted directory changed during read')
        unchanged()
        candidate_read = _hash_open_file(candidate, stack, CANDIDATE_BYTES, mount, mount_fd)
        require(candidate_read['bytes'] == CANDIDATE_BYTES and candidate_read['sha256'] == CANDIDATE_SHA256,
                'Inactive candidate full readback differs')
        unchanged()
        require(not root_update.is_symlink(), 'Unsafe root BODYDATA path')
        if existing['exists']:
            root_read = _hash_open_file(root_update, stack, existing['bytes'], mount, mount_fd)
            require(root_read['bytes'] == existing['bytes'] and root_read['sha256'] == existing['sha256'],
                    'Root BODYDATA differs from original stage snapshot')
        else:
            require(not root_update.exists(), 'Root BODYDATA appeared after absent baseline')
            root_read = dict(path=str(root_update), exists=False)
        unchanged()
        for readback in (candidate_read, root_read) if existing['exists'] else (candidate_read,):
            path = _safe_path(readback['path'])
            fd = readback.pop('_descriptor')
            require(list(_stat_identity(os.fstat(fd))) == readback['descriptor_identity']
                    and list(_stat_identity(path.stat())) == readback['descriptor_identity'],
                    'Pinned card file changed after readback')
            require(os.fstat(fd).st_dev == mount_identity.st_dev, 'Same-volume card file required')
        require(not root_update.is_symlink() and (root_update.exists() if existing['exists'] else not root_update.exists()),
                'Root BODYDATA state changed during read')
    evidence = dict(schema='camera-install-inactive-card-observation/1', stage_path=str(stage_path),
        stage_sha256=_sha(stage_raw), candidate=candidate_read, root_update=root_read,
        original_root_snapshot=existing, volume_identity=pinned, identity_observations=observations,
        stable_identity_matches_stage=True, root_matches_original_stage=True, candidate_inactive=True,
        source_is_hardware=False, observer_kind='INJECTED_FILESYSTEM_OBSERVER',
        default_device_discovery_used=False, explicit_card_writes=False,
        card_contents_or_names_modified=False)
    return evidence | dict(evidence_sha256=_sha(_canonical(evidence)))


def assess_cancellation(*, journal, pending_reference, stage_reference, ready_raw, result_raw,
                        probe_nonce, loader_pid, discover, operator_never_started_confirmed=False,
                        operator_health_confirmed=False):
    """Assess supplied probe and inactive-card evidence, without recording cancellation.

    Eligibility is a semantic checklist result. It never certifies hardware
    origin, original-mm continuity, restoration, or a safe journal transition.
    """
    from camera_install_journal import InstallJournal
    import camera_install_patch_read as current
    require(callable(discover), 'Explicit filesystem observer required; no real discovery entry')
    require(isinstance(journal, InstallJournal), 'Validated pending InstallJournal required')
    reopened = InstallJournal.open(journal.session_dir)
    require(reopened.events == journal.events and reopened.state == 'INSTALL_PATCH_AWAITING_OPERATOR_RECONNECT',
            'Fresh pending install-patch journal required')
    history = reopened.events
    require(not any(event['state'] == 'FLASH_MAY_HAVE_STARTED' for event in history), 'Possible FLASH history forbids cancellation assessment')
    require(history[-1]['details'].get('install_patch_artifact') == pending_reference,
            'Original pending artifact binding differs')
    pending_path, pending_raw, pending = _json_reference(pending_reference)
    require(isinstance(stage_reference, dict) and set(stage_reference) == {'path', 'sha256'},
            'Exact stage artifact reference required')
    stage_events = [event for event in history if event['state'] == 'SD_STAGED']
    require(len(stage_events) == 1 and stage_events[0]['details'].get('stage_report') == stage_reference.get('path')
            and stage_events[0]['details'].get('stage_report_sha256') == stage_reference.get('sha256'),
            'Original SD_STAGED artifact binding differs')
    binding = reopened.binding
    spec = current.derive_target_spec(pending_raw, body_sha256=binding['body_sha256'], plan_sha256=binding['plan_sha256'])
    require(type(probe_nonce) is bytes and len(probe_nonce) == 16 and any(probe_nonce), 'Fresh probe nonce required')
    used = {pending['asset_reference']['patch']['nonce']} | {
        row['nonce'] for name, row in pending['asset_reference']['captures'].items() if name != 'directory'}
    require(probe_nonce.hex() not in used, 'Probe nonce reuses a preparation job')
    proof = current.validate_publications(ready_raw, result_raw, nonce=probe_nonce, loader_pid=loader_pid, spec=spec)
    card = observe_inactive_card(stage_reference, body_sha256=binding['body_sha256'], discover=discover)
    require(InstallJournal.open(journal.session_dir).events == history
            and _json_reference(pending_reference)[1] == pending_raw, 'Pending context changed during assessment')
    _json_reference(stage_reference)
    both_original = proof['observation'] == 'ORIGINAL' and all(
        proof['targets'][name]['observation'] == 'ORIGINAL' for name in ('lib', 'app'))
    eligible = both_original and operator_never_started_confirmed is True and operator_health_confirmed is True
    checklist = dict(both_original_in_supplied_probe=both_original, original_inactive_card_verified=True,
                     no_FLASH_history=True, operator_never_started_confirmed=operator_never_started_confirmed is True,
                     operator_health_confirmed=operator_health_confirmed is True)
    result = dict(schema='camera-install-cancellation-evidence-assessment/1',
        state='CANCELLATION_EVIDENCE_ASSESSED_ONLY', **binding, session_id=journal.session_dir.name,
        pending_receipt_path=str(pending_path), pending_receipt_sha256=_sha(pending_raw),
        stage_sha256=stage_reference['sha256'], probe_nonce=probe_nonce.hex(),
        probe_publication_sha256=dict(ready=_sha(ready_raw), result=_sha(result_raw)),
        probe_sha256=_sha(ready_raw + result_raw),
        probe_proof=proof, probe_proof_sha256=_sha(_canonical(proof)),
        card_evidence=card, card_evidence_sha256=card['evidence_sha256'], checklist=checklist,
        eligible_for_separately_reviewed_cancellation=eligible,
        cancellation_recorded=False, journal_cleared=False, restore=False, RAM_restoration_proven=False,
        RAM_original_state_verified=False, restoration_performed=False, ready=False,
        installation_authorized=False, hardware_admission_proven=False, device_execution_proven=False,
        source_is_hardware=False, explicit_card_writes=False, card_contents_or_names_modified=False,
        automatic_reboot=False, automatic_restore=False,
        limitations=['Injected filesystem observer and supplied raw frames do not establish hardware origin',
                     'Current-word observations do not prove original-mm continuity or indefinite persistence',
                     'This unit neither withdraws an active candidate nor clears any pending journal',
                     'Read-only application calls can still update filesystem access metadata'])
    return result | dict(assessment_sha256=_sha(_canonical(result)))
