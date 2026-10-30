"""Explicit tiny-file round-trip probe and historical replacement evidence checks."""
import hashlib
import json
import os
import platform
from pathlib import Path
import re
import secrets

from tools import card_backup_replace as replace

SCHEMA = 'camera-card-backup-replace-probe/1'
STABLE_KEYS = ('body_sha256', 'volume_uuid', 'filesystem', 'volume_bytes')
IDENTITY_KEYS = ('body_sha256', 'volume_uuid', 'filesystem', 'volume_bytes',
                 'device', 'parent', 'mount', 'registry_id')
ORIGINAL = b'camera-use original scratch content\n' * 4096
CANDIDATE = b'camera-use replacement scratch content\n' * 4096


def require(value, message):
    if not value:
        raise ValueError(message)


def identity(volume):
    require(isinstance(volume, dict) and all(key in volume for key in IDENTITY_KEYS),
            'Complete stable body/card identity required')
    return {key: volume[key] for key in IDENTITY_KEYS}


def _path(path):
    path = Path(path).absolute()
    require('..' not in path.parts and all(not p.is_symlink() for p in (path, *path.parents)),
            'Canonical nonsymlink evidence path required')
    return path


def reference(path):
    path = _path(path)
    require(path.is_file(), 'Regular evidence required')
    return dict(path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest())


def read_reference(ref):
    require(isinstance(ref, dict) and set(ref) == {'path', 'sha256'}, 'Exact evidence reference required')
    path = _path(ref['path'])
    require(path.is_file() and path.stat().st_size <= 1 << 20, 'Bounded regular evidence required')
    raw = path.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == ref['sha256'], 'Evidence SHA256 differs')
    def pairs(values):
        result = {}
        for key, value in values:
            require(key not in result, 'Duplicate evidence key')
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=pairs)
    require(isinstance(value, dict), 'Evidence object required')
    return value


def validate_transaction(ref, *, operation, card_identity, source, target, preserved,
                         source_sha256, previous_target_sha256, intent_reference):
    value = read_reference(ref)
    stopped = Path(ref['path']).parent / 'stopped.json'
    require(not stopped.exists() and not stopped.is_symlink(), 'Contradictory stopped replacement evidence')
    protocol = replace.PROTOCOL if operation == 'ACTIVATE' else replace.Assurance.SINGLE_WRITER_BACKUP_RESTORE.value
    expected = dict(protocol=protocol, operation=operation, state='COMPLETED',
                    source_path=str(source), target_path=str(target), preserved_path=str(preserved),
                    source_sha256=source_sha256, previous_target_sha256=previous_target_sha256,
                    card_identity=identity(card_identity), execution_kind='PRODUCTION_HOST_FILESYSTEM')
    require(all(value.get(key) == item for key, item in expected.items()),
            'Completed replacement proof context differs')
    require(all(value.get(key) is True for key in ('single_writer_acknowledged',
                'requires_exclusive_cooperative_writer', 'target_name_continuously_present_by_posix_contract'))
            and all(value.get(key) is False for key in ('atomic_no_clobber', 'external_writers_excluded_by_module',
                'camera_native_execution_proven', 'firmware_update_authorized', 'automatic_retry',
                'automatic_rollback', 'updater_invoked', 'power_loss_atomicity_proven')),
            'Replacement proof contract differs')
    require(isinstance(intent_reference,dict), 'Independent replacement intent reference required')
    require(intent_reference.get('path') == str(Path(ref['path']).parent / 'replace-intent.json'),
            'Replacement intent reference path differs')
    intent = read_reference(intent_reference)
    require(intent.get('state') == 'REPLACE_MAY_HAVE_OCCURRED'
            and all(intent.get(key) == item for key, item in expected.items() if key != 'state')
            and intent.get('preserved_sha256') == previous_target_sha256,
            'Replacement intent differs')
    if operation == 'ACTIVATE':
        require(value.get('candidate_sha256') == source_sha256 and value.get('backup_sha256') == previous_target_sha256
                and value.get('backup_path') == str(preserved), 'Forward replacement proof differs')
    else:
        require(value.get('original_sha256') == source_sha256
                and value.get('inactive_candidate_sha256') == previous_target_sha256
                and value.get('inactive_candidate_path') == str(preserved)
                and value.get('original_backup_source_absent') is True, 'Inverse replacement proof differs')
    return value


def _save(path, value):
    raw = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        at = 0
        while at < len(raw):
            count = os.write(fd, raw[at:])
            require(count > 0, 'Evidence write made no progress')
            at += count
        os.fsync(fd)
    finally:
        os.close(fd)
    _sync(path.parent)


def _sync(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _write(path, content):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        at = 0
        while at < len(content):
            count = os.write(fd, content[at:])
            require(count > 0, 'Scratch write made no progress')
            at += count
        os.fsync(fd)
    finally:
        os.close(fd)
    _sync(path.parent)


def _host_identity():
    return dict(system=platform.system(), release=platform.release(), macos=platform.mac_ver()[0])


def _source_hashes():
    return {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in (Path(__file__), Path(replace.__file__))}


def probe(mount, evidence, *, expected_card_identity, identity_reader,
          scratch_authorized=False, single_writer_acknowledged=False):
    """Exercise both directions only inside a new owned scratch directory.

    Explicit authorization covers these scratch-file writes. No business update
    filename is touched. Caller must own the host lease and bind real discovery.
    Probe success does not prove power-loss safety or exclude other writers.
    """
    require(scratch_authorized is True and single_writer_acknowledged is True,
            'Explicit scratch and single-writer authorization required')
    expected = identity(expected_card_identity)
    sources = _source_hashes()
    host = _host_identity()
    mount, evidence = _path(mount), _path(evidence)
    require(expected['mount'] == str(mount) and mount.is_dir() and callable(identity_reader),
            'Bound card mount and discovery required')
    require(not evidence.exists() and not evidence.is_relative_to(mount), 'Fresh external probe evidence required')
    require(identity(identity_reader()) == expected, 'Probe card identity differs')
    evidence.mkdir(mode=0o700)
    scratch = mount / '.camera-use-probes' / ('pair-' + secrets.token_hex(8))
    _save(evidence / 'intent.json', dict(schema=SCHEMA, card_identity=expected,
        scratch_root=str(scratch), scratch_authorized=True, single_writer_acknowledged=True,
        source_sha256=sources, business_filenames_modified=False))
    parent = scratch.parent
    if parent.exists():
        require(parent.is_dir() and not parent.is_symlink(), 'Safe probe parent required')
    else:
        parent.mkdir(mode=0o700)
    scratch.mkdir(mode=0o700)
    _sync(parent)
    original_sha, candidate_sha = (hashlib.sha256(x).hexdigest() for x in (ORIGINAL, CANDIDATE))
    stage = scratch / '.camera-use-staging' / ('fl23-' + candidate_sha[:16] + '-' + secrets.token_hex(8))
    stage.mkdir(mode=0o700, parents=True)
    root, candidate, backup = scratch / 'BODYDATA.DAT', stage / 'candidate.staged', stage / 'original-BODYDATA.DAT'
    _write(root, ORIGINAL)
    _write(candidate, CANDIDATE)
    forward = replace.replace_with_backup(replace.ReplacementPlan(
        replace.FileExpectation(candidate, len(CANDIDATE), candidate_sha),
        replace.FileExpectation(root, len(ORIGINAL), original_sha), backup), evidence / 'activate',
        expected_card_identity=expected, identity_reader=lambda: identity(identity_reader()),
        assurance=replace.Assurance.SINGLE_WRITER_BACKUP_REPLACE, single_writer_acknowledged=True)
    reverse = replace.withdraw_with_backup(replace.WithdrawalPlan(
        replace.FileExpectation(root, len(CANDIDATE), candidate_sha),
        replace.FileExpectation(backup, len(ORIGINAL), original_sha), candidate), evidence / 'withdraw',
        expected_card_identity=expected, identity_reader=lambda: identity(identity_reader()),
        assurance=replace.Assurance.SINGLE_WRITER_BACKUP_RESTORE, single_writer_acknowledged=True)
    require(forward['state'] == reverse['state'] == 'COMPLETED'
            and identity(identity_reader()) == expected
            and _source_hashes() == sources and _host_identity() == host, 'Probe round trip incomplete')
    result = dict(schema=SCHEMA, state='ROUND_TRIP_COMPLETED', card_identity=expected,
        scratch_root=str(scratch), source_sha256=sources, host_identity=host,
        forward_reference=reference(evidence / 'activate/completed.json'),
        forward_intent_reference=reference(evidence / 'activate/replace-intent.json'),
        reverse_reference=reference(evidence / 'withdraw/completed.json'),
        reverse_intent_reference=reference(evidence / 'withdraw/replace-intent.json'),
        scratch_authorized=True, single_writer_acknowledged=True,
        business_filenames_modified=False, power_loss_atomicity_proven=False)
    _save(evidence / 'completed.json', result)
    return reference(evidence / 'completed.json')


def _flow_producer(ref, step, flow_directory, volume):
    """Require the reviewed controller to have recorded the actor's return."""
    import camera_install_flow as controller
    folder, header, config, events, binding = controller._open(flow_directory,_producer_step=step)
    require(header.get('injected_execution') is False
            and config.get('model_fixture_only',False) is False
            and config.get('card_activation_protocol') == replace.PROTOCOL,
            'Real reviewed replacement flow required')
    require(config['body_sha256'] == identity(volume)['body_sha256'], 'Producer flow body differs')
    completed=[event for event in events if event['step']==step and event['phase']=='COMPLETED']
    require(len(completed)==1 and completed[0].get('source_is_hardware') is True
            and controller._artifact(events,step)==ref, 'Successful enclosing actor flow required')
    return dict(flow_directory=str(folder),binding=binding,
                event_sha256=completed[0]['event_sha256'],result_reference=completed[0]['receipt_reference'])


def validate_probe(ref, volume, *, flow_directory=None):
    require(flow_directory is not None, 'Successful enclosing probe flow required')
    _flow_producer(ref,'probe',flow_directory,volume)
    value = read_reference(ref)
    current = identity(volume)
    expected = identity(value.get('card_identity'))
    require(all(expected[key] == current[key] for key in STABLE_KEYS), 'Probe body/card differs')
    require(value.get('schema') == SCHEMA and value.get('state') == 'ROUND_TRIP_COMPLETED'
            and value.get('card_identity') == expected and value.get('source_sha256') == _source_hashes()
            and value.get('host_identity') == _host_identity()
            and value.get('scratch_authorized') is True and value.get('single_writer_acknowledged') is True
            and value.get('business_filenames_modified') is False and value.get('power_loss_atomicity_proven') is False,
            'Completed matching filesystem probe required')
    scratch = Path(value['scratch_root']).absolute()
    require('..' not in scratch.parts, 'Canonical scratch evidence path required')
    require(scratch.parent == Path(expected['mount']) / '.camera-use-probes'
            and re.fullmatch('pair-[0-9a-f]{16}', scratch.name), 'Owned scratch layout required')
    original_sha, candidate_sha = (hashlib.sha256(x).hexdigest() for x in (ORIGINAL, CANDIDATE))
    forward = read_reference(value['forward_reference'])
    candidate = Path(forward['source_path'])
    root, backup = scratch / 'BODYDATA.DAT', candidate.parent / 'original-BODYDATA.DAT'
    require(candidate.parent.parent == scratch / '.camera-use-staging'
            and candidate.name == 'candidate.staged'
            and re.fullmatch('fl23-' + candidate_sha[:16] + '-[0-9a-f]{16}', candidate.parent.name),
            'Probe candidate layout differs')
    validate_transaction(value['forward_reference'], operation='ACTIVATE', card_identity=expected,
        source=candidate, target=root, preserved=backup, source_sha256=candidate_sha, previous_target_sha256=original_sha, intent_reference=value['forward_intent_reference'])
    validate_transaction(value['reverse_reference'], operation='WITHDRAW', card_identity=expected,
        source=backup, target=root, preserved=candidate, source_sha256=original_sha, previous_target_sha256=candidate_sha, intent_reference=value['reverse_intent_reference'])
    return value
