"""Observe the activated candidate and preserved original; never rename or flash.

The default filesystem discovery requires the held global device lease and a
bound staged journal. Injected discovery always produces non-hardware evidence.
"""
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path

from camera_device_lease import DEFAULT_LOCK
from camera_operation_guard import DEFAULT_SESSIONS, assert_operation_allowed
from camera_install_journal import InstallJournal
from camera_install_patch_session import _held_lease
from camera_install_cancel import (_identity, _safe_path, _json_reference,
    _hash_open_file, _stat_identity, STABLE_KEYS)
from camera_sd_stage import DIGEST, SIZE, staged_relative_path


def require(value, message):
    if not value:
        raise ValueError(message)


def observe_active_card(stage_reference, activation_reference, *, body_sha256,
                        lease, journal, card_read_authorized=False, discover=None):
    """Fully read the active root candidate and retained original under one lease.

    Reconnect may change handles before this observation. During it, card handles,
    open-file identities, pending history and lease instance must remain fixed.
    No returned flag authorizes an updater, proves installation or guarantees a
    later card state. Callers must recheck at their action boundary.
    """
    require(card_read_authorized is True, 'Explicit active-card read authorization required')
    require(discover is None or callable(discover), 'Filesystem observer must be callable')
    identity = _held_lease(lease)
    require(isinstance(journal, InstallJournal), 'Bound install journal required')
    injected = discover is not None
    if not injected:
        require(Path(lease.path).absolute() == DEFAULT_LOCK.absolute()
                and journal.session_dir.parent.absolute() == DEFAULT_SESSIONS.absolute(),
                'Default card discovery requires canonical device lease and journal')
        _safe_path(lease.path)
        _safe_path(journal.session_dir)
        from camera_sd_stage import discover as default_discover
        discover = default_discover
    history = journal.events
    require(journal.binding['body_sha256'] == body_sha256 and journal.binding['model'] == 'ILCE-7M4',
            'Same-body journal required')
    states = ('SD_STAGED', 'INSTALL_PATCH_AWAITING_OPERATOR_RECONNECT')
    require(journal.state in states, 'Staged or pending preparation journal required')
    stage_path, stage_raw, stage = _json_reference(stage_reference)
    activation_path, activation_raw, activation = _json_reference(activation_reference)
    stages = [e for e in history if e['state'] == 'SD_STAGED']
    require(len(stages) == 1 and stages[0]['details'].get('stage_report') == str(stage_path)
            and stages[0]['details'].get('stage_report_sha256') == stage_reference['sha256'],
            'Original staged artifact must match journal')
    require(stage.get('state') == 'STAGED_UNRECOGNIZED_FILE_VERIFIED_NOT_ACTIVATED'
            and stage.get('source_sha256') == DIGEST and stage.get('bytes') == SIZE
            and stage.get('existing_root_update_unchanged') is True
            and stage.get('BODYDATA_DAT_created_or_replaced') is False
            and stage.get('camera_internal_firmware_modified') is False
            and stage.get('updater_invoked') is False, 'Complete stage receipt required')
    old = _identity(stage.get('volume_identity'), body_sha256)
    relative = staged_relative_path(stage.get('target'), old['mount'], DIGEST)
    active_volume = _identity(activation.get('volume_identity'), body_sha256)
    require(all(active_volume[k] == old[k] for k in STABLE_KEYS), 'Activation card differs from staged card')
    require(activation.get('state') == 'ACTIVATED_PREVIEW_ONLY'
            and activation.get('source_sha256') == DIGEST and activation.get('bytes') == SIZE
            and activation.get('slot1_manually_confirmed') is True
            and activation.get('original_root_update') == stage.get('existing_root_update')
            and activation.get('updater_invoked') is False
            and activation.get('installation_authorized') is False
            and activation.get('camera_internal_firmware_modified') is False,
            'Complete filename-only activation receipt required')
    require(activation.get('target') == str(Path(active_volume['mount']) / 'BODYDATA.DAT')
            and activation.get('backup') == str(Path(active_volume['mount']) / relative.parent / 'original-BODYDATA.DAT'),
            'Activation paths differ from staged location')
    existing = stage.get('existing_root_update')
    require(isinstance(existing, dict) and type(existing.get('exists')) is bool, 'Original root snapshot required')
    if existing['exists']:
        require(set(existing) == {'exists', 'bytes', 'sha256'} and type(existing['bytes']) is int
                and existing['bytes'] >= 0 and isinstance(existing['sha256'], str)
                and len(existing['sha256']) == 64 and all(c in '0123456789abcdef' for c in existing['sha256'])
                and existing['sha256'] != DIGEST, 'Complete distinct original root snapshot required')
    else:
        require(existing == {'exists': False}, 'Exact absent original snapshot required')

    def context():
        require(_held_lease(lease) == identity, 'Active-card lease identity changed')
        require(InstallJournal.open(journal.session_dir).events == history, 'Install history changed during card read')
        assert_operation_allowed(journal, allowed_states=states)
        if journal.session_dir.parent.resolve() != DEFAULT_SESSIONS.resolve():
            assert_operation_allowed(sessions_root=DEFAULT_SESSIONS)

    context()
    pinned = _identity(dict(discover()), body_sha256)
    require(all(pinned[k] == old[k] for k in STABLE_KEYS), 'Current card differs from staged card')
    mount = _safe_path(pinned['mount'])
    require(mount.is_dir(), 'Mounted card directory required')
    root = _safe_path(mount / 'BODYDATA.DAT')
    staged = _safe_path(mount / relative)
    backup = _safe_path(staged.parent / 'original-BODYDATA.DAT')
    require(staged.parent.is_dir() and not staged.exists() and not staged.is_symlink(),
            'Original inactive candidate must remain absent after activation')
    observations = [pinned]
    with ExitStack() as stack:
        fd = os.open(mount, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0) | getattr(os, 'O_NOFOLLOW', 0))
        stack.callback(os.close, fd)
        mount_identity = os.fstat(fd)

        def unchanged():
            context()
            current = _identity(dict(discover()), body_sha256)
            observations.append(current)
            require(current == pinned, 'Camera/card handles changed during active read')
            location = mount.stat()
            require(not mount.is_symlink() and (location.st_dev, location.st_ino) ==
                    (mount_identity.st_dev, mount_identity.st_ino), 'Mounted directory changed during read')

        unchanged()
        candidate_read = _hash_open_file(root, stack, SIZE, mount, fd)
        require(candidate_read['sha256'] == DIGEST, 'Active root candidate differs')
        unchanged()
        if existing['exists']:
            original_read = _hash_open_file(backup, stack, existing['bytes'], mount, fd)
            require(original_read['sha256'] == existing['sha256'], 'Preserved original BODYDATA differs')
        else:
            require(not backup.exists() and not backup.is_symlink(), 'Unexpected original backup after absent baseline')
            original_read = dict(path=str(backup), exists=False)
        unchanged()
        for item in (candidate_read, original_read) if existing['exists'] else (candidate_read,):
            opened = item.pop('_descriptor')
            require(list(_stat_identity(os.fstat(opened))) == item['descriptor_identity']
                    and list(_stat_identity(_safe_path(item['path']).stat())) == item['descriptor_identity']
                    and os.fstat(opened).st_dev == mount_identity.st_dev, 'Pinned card file changed after read')
        require(not staged.exists() and not staged.is_symlink(), 'Inactive candidate reappeared during read')
        if not existing['exists']:
            require(not backup.exists() and not backup.is_symlink(), 'Original backup appeared during read')
        require(_json_reference(stage_reference)[1] == stage_raw
                and _json_reference(activation_reference)[1] == activation_raw, 'Card evidence changed during read')
        context()
    result = dict(schema='camera-install-active-card-observation/1', body_sha256=body_sha256,
        plan_sha256=journal.binding['plan_sha256'], model='ILCE-7M4', session_id=journal.session_dir.name,
        journal_event_sha256=history[-1]['event_sha256'], stage_reference=dict(stage_reference),
        activation_reference=dict(activation_reference), candidate=candidate_read, original_backup=original_read,
        volume_identity=pinned, identity_observations=observations, candidate_active_at_observation=True,
        original_preserved_at_observation=True, source_is_hardware=not injected,
        explicit_card_writes=False, updater_invoked=False, installation_authorized=False,
        ready_for_confirmation=False, journal_cleared=False, future_card_state_proven=False)
    raw = json.dumps(result, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    return result | dict(evidence_sha256=hashlib.sha256(raw).hexdigest())
