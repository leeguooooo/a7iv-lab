"""Pure fixed-target derivation and current-word receipt validation.

Source declarations are retained assertions, never hardware attestations. A
stable current observation does not establish the original mm, restoration,
cancellation eligibility, installation readiness or authorization. No device,
filesystem, SDK, journal mutation or execution capability is exposed.
"""
from copy import deepcopy
import hashlib
import json
import struct

import camera_install_volatile as prior

MAGIC = b'M4IPR001'
VERSION = 1
START_MAGIC = b'M4RSTART'
START_FRAME = struct.Struct('<8s16s16sQ')
READY_FLAGS = 13
COMPLETE_FLAGS = 1021
BASE_FIELDS = ('version', 'phase', 'error', 'euid', 'pid', 'ppid', 'loader_pid', 'cleanup',
               'flags', 'passes', 'lib_pid', 'lib_base_addr', 'lib_target_addr',
               'app_pid', 'app_base_addr', 'app_target_addr')
TARGET_SUFFIXES = ('maps_before_bytes', 'maps_after_bytes', 'start_before', 'start_after',
    'word_before', 'word_after', 'version_before', 'version_after', 'anchor_before_status',
    'anchor_after_status', 'maps_status', 'stat_status', 'mem_status', 'mem_closed')
FIELDS = BASE_FIELDS + tuple(f'{target}_{suffix}' for target in ('lib', 'app') for suffix in TARGET_SUFFIXES)
FRAME = struct.Struct('<8s16s16s32s44q')
WORKER_FIELDS = ('euid', 'pid', 'ppid', 'loader_pid', 'cleanup')
PROFILES = {
    'lib': dict(patch_offset=8016, stock_version=0x0602, original_hex='00c84479', patch_hex='00c08052',
        anchor_offset=8004, anchor_hex='a0000090012044792001009000c844793f00006b',
        global_version_offset=152164, version_bytes=2),
    'app': dict(patch_offset=40219336, stock_version=0x00060002, original_hex='e3050054', patch_hex='2f000014',
        anchor_offset=40219316,
        anchor_hex='010040b9a05f40b9e80313aa3f00006ba03740f9e30500544a6ffc9740008052',
        global_version_offset=134261208, version_bytes=4),
}
_FALSE_CLAIMS = ('installation_authorized', 'firmware_installation_proven', 'RAM_restoration_proven',
                 'normal_body_reappearance_verified', 'device_execution_proven', 'hardware_admission_proven')


def _require(value, message):
    if not value:
        raise ValueError(message)


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode()


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def spec_sha256(spec):
    return _sha(canonical_bytes(spec))


def _hex(value, size):
    return (type(value) is str and len(value) == size * 2
            and all(c in '0123456789abcdef' for c in value))


def _pid(value):
    return type(value) is int and 1 < value <= 0x7fffffff


def _json(raw):
    _require(type(raw) is bytes, 'Complete pending receipt bytes required')
    def pairs(items):
        result = {}
        for key, value in items:
            _require(key not in result, 'Duplicate pending receipt field')
            result[key] = value
        return result
    try:
        value = json.loads(raw, object_pairs_hook=pairs)
        _require(isinstance(value, dict), 'Pending receipt must be an object')
        canonical_bytes(value)
        return value
    except (TypeError, UnicodeError, ValueError, RecursionError) as error:
        raise ValueError('Invalid complete pending receipt') from error


def _reference(reference, payload=False):
    keys = {'path', 'sha256', 'payload_sha256'} if payload else {'path', 'sha256'}
    _require(isinstance(reference, dict) and set(reference) == keys
             and type(reference['path']) is str and reference['path'].startswith('/')
             and '..' not in reference['path'].split('/')
             and all(_hex(reference[name], 32) for name in keys - {'path'}), 'Bound artifact reference required')


def _modeled(value):
    if isinstance(value, dict):
        return value.get('model_fixture_only') is True or any(_modeled(item) for item in value.values())
    return isinstance(value, list) and any(_modeled(item) for item in value)


def derive_target_spec(pending_raw, *, body_sha256, plan_sha256):
    """Derive both targets from a complete prior receipt, without attesting it."""
    _require(_hex(body_sha256, 32) and _hex(plan_sha256, 32), 'Expected body and plan SHA256 required')
    pending = _json(pending_raw)
    binding = dict(body_sha256=body_sha256, plan_sha256=plan_sha256, model='ILCE-7M4')
    _require(pending.get('schema') == 'camera-install-patch-session-receipt/1'
             and pending.get('state') == 'INSTALL_PATCH_AWAITING_OPERATOR_RECONNECT'
             and all(pending.get(key) == value for key, value in binding.items())
             and pending.get('consent_scope') == 'INSTALL_PREPARATION_VOLATILE_PATCH_ONLY'
             and pending.get('patches_remain_acknowledged') is True
             and all(pending.get(key) is False for key in _FALSE_CLAIMS)
             and pending.get('service_exit_completed') is True,
             'Complete preparation-only pending receipt required')
    _require(type(pending.get('source_is_hardware')) is bool
             and type(pending.get('session_id')) is str and bool(pending['session_id'])
             and _hex(pending.get('intent_event_sha256'), 32), 'Pending session/source binding required')
    events = pending.get('service_events')
    _require(isinstance(events, list) and all(isinstance(event, dict) for event in events), 'Known STOP event required')
    stops = [event for event in events if event.get('event') == 'STOP_RESPONSE']
    _require(len(stops) == 1 and stops[0].get('mode') == 'service'
             and (stops[0].get('success') is True or stops[0].get('known_pipe_response') is True),
             'Known STOP event required')
    modeled = _modeled(pending)
    _require(not modeled or pending['source_is_hardware'] is False, 'Modeled receipt cannot declare hardware origin')
    lease = pending.get('lease_identity')
    _require(isinstance(lease, dict) and set(lease) == {'device', 'inode', 'instance'}
             and type(lease['device']) is int and lease['device'] >= 0
             and type(lease['inode']) is int and lease['inode'] >= 0 and _hex(lease['instance'], 16)
             and isinstance(pending.get('reservation'), dict) and bool(pending['reservation']),
             'Complete original lease/reservation metadata required')
    _reference(pending.get('review_artifact'), payload=True)
    _require(pending['review_artifact']['sha256'] == plan_sha256, 'Original review/plan hash differs')
    _reference(pending.get('terminal_artifact'), payload=True)
    terminal = deepcopy(pending)
    for name in ('terminal_artifact', 'service_events', 'service_exit_completed'):
        terminal.pop(name)
    terminal['state'] = 'INSTALL_PATCH_TERMINAL_DURABLE_BEFORE_STOP'
    _require(pending['terminal_artifact']['payload_sha256'] == _sha(canonical_bytes(terminal)),
             'Canonical pre-STOP payload binding differs')
    assets, native = pending.get('asset_reference'), pending.get('native_receipt')
    _require(isinstance(assets, dict) and assets.get('schema') == 'camera-install-patch-assets/1'
             and isinstance(assets.get('patch'), dict) and isinstance(assets.get('captures'), dict)
             and isinstance(native, dict), 'Complete original asset/native binding required')
    _require(all(type(directory) is str and directory.startswith('/') and '..' not in directory.split('/')
                 for directory in (assets['patch'].get('directory'), assets['captures'].get('directory'))),
             'Complete original asset directories required')
    patch = assets['patch']
    nonce = patch.get('nonce')
    _require(_hex(nonce, 16) and any(bytes.fromhex(nonce))
             and patch.get('job_dir') == '/tmp_wbshd/m4ivp_' + nonce
             and all(_hex(patch.get(key), 32) for key in
                     ('manifest_sha256', 'module_sha256', 'native_model_sha256', 'bootstrap_model_sha256')),
             'Original patch asset nonce/hash binding required')
    for name in ('pre_app', 'pre_ufp'):
        capture = assets['captures'].get(name)
        _require(isinstance(capture, dict) and _hex(capture.get('nonce'), 16)
                 and _hex(capture.get('manifest_sha256'), 32) and _hex(capture.get('module_sha256'), 32),
                 'Original capture asset binding required')
    _require(len({nonce, *(assets['captures'][name]['nonce'] for name in ('pre_app', 'pre_ufp'))}) == 3,
             'Original asset nonces collide')
    _require(native.get('asset_reference') == assets and native.get('nonce') == nonce
             and native.get('reservation') == pending.get('reservation')
             and native.get('source_is_hardware') is pending['source_is_hardware']
             and native.get('scope') == 'INSTALL_PREPARATION_VOLATILE_PATCH_ONLY'
             and native.get('service_exit_completed') is False
             and all(native.get(key) == value for key, value in binding.items())
             and pending.get('native_receipt_sha256') == _sha(canonical_bytes(native)),
             'Original native receipt binding differs')
    publications = native.get('raw_publications')
    _require(isinstance(publications, dict) and set(publications) == {'ready', 'patched', 'result'}
             and all(_hex(value, prior.FRAME.size) for value in publications.values()),
             'Three complete original v2 publications required')
    proof = prior.validate_publications(*(bytes.fromhex(publications[name]) for name in ('ready', 'patched', 'result')),
        nonce=bytes.fromhex(nonce), loader_pid=native.get('loader_pid'))
    _require(all(native.get(key) == value for key, value in proof.items()), 'Original semantic receipt differs from raw bytes')
    target_rows = {}
    for name, prefix, pid_name in (('lib', '', 'loader_pid'), ('app', 'app_', 'app_pid')):
        row = proof['result']
        target_rows[name] = dict(pid=row[pid_name], base_addr=row[prefix + 'base_addr'],
                                target_addr=row[prefix + 'target_addr'], **PROFILES[name])
    return dict(schema='camera-install-patch-read-targets/1', **binding,
        pending_receipt_sha256=_sha(pending_raw), pending_payload_sha256=_sha(canonical_bytes(pending)),
        original_patch_nonce=nonce, original_source_is_hardware=pending['source_is_hardware'],
        original_hardware_origin_proven=False, original_asset_reference=deepcopy(assets),
        pending_receipt_raw_hex=pending_raw.hex(), targets=target_rows)


target_spec = derive_target_spec


def validate_target_spec(spec):
    payload = spec.get('pending_receipt_raw_hex') if isinstance(spec, dict) else None
    _require(type(payload) is str and bool(payload) and len(payload) % 2 == 0
             and _hex(payload, len(payload) // 2), 'Derived complete target specification required')
    try:
        expected = derive_target_spec(bytes.fromhex(spec['pending_receipt_raw_hex']),
                                      body_sha256=spec['body_sha256'], plan_sha256=spec['plan_sha256'])
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError('Invalid target derivation') from error
    _require(expected == spec, 'Target specification differs from prior native receipts')
    return deepcopy(spec)


def decode_record(raw, nonce, spec):
    """Decode forensic error records as well as structurally valid observations."""
    validate_target_spec(spec)
    _require(type(nonce) is bytes and len(nonce) == 16 and any(nonce), 'Fresh 16-byte read nonce required')
    old_nonces = {spec['original_patch_nonce'], *(spec['original_asset_reference']['captures'][name]['nonce']
                                                for name in ('pre_app', 'pre_ufp'))}
    _require(nonce.hex() not in old_nonces, 'Read nonce must differ from all original job nonces')
    _require(type(raw) is bytes and len(raw) == FRAME.size, 'Complete 424-byte current-read record required')
    magic, got, original, digest, *values = FRAME.unpack(raw)
    _require(magic == MAGIC and got == nonce and original.hex() == spec['original_patch_nonce']
             and digest.hex() == spec_sha256(spec), 'Current-read nonce/spec identity differs')
    row = dict(zip(FIELDS, values))
    _require(row['version'] == VERSION and row['phase'] in (1, 2, 3, 7, 90)
             and ((row['phase'] == 90 and -4095 <= row['error'] < 0)
                  or (row['phase'] != 90 and row['error'] == 0))
             and 0 <= row['flags'] <= COMPLETE_FLAGS and not row['flags'] & ~COMPLETE_FLAGS
             and 0 <= row['passes'] <= 2, 'Unsupported current-read contract')
    _require(all(row[f'{name}_mem_closed'] in (0, 1) for name in ('lib', 'app')),
             'Invalid memory-close Boolean')
    return row


def _context(row, spec, loader_pid):
    _require(row['euid'] == row['cleanup'] == 0 and row['ppid'] == 1
             and _pid(row['pid']) and _pid(row['loader_pid']) and row['pid'] != row['loader_pid']
             and row['loader_pid'] == loader_pid
             and row['pid'] not in {spec['targets'][name]['pid'] for name in ('lib', 'app')},
             'Current-read worker lifecycle rejected')
    _require(all(row[f'{name}_{field}'] == spec['targets'][name][field]
                 for name in ('lib', 'app') for field in ('pid', 'base_addr', 'target_addr')),
             'Current-read fixed targets differ')


def validate_publications(ready_raw, result_raw, *, nonce, loader_pid, spec):
    """Return current classifications only; no original-mm or hardware proof."""
    _require(_pid(loader_pid), 'Bound current loader PID required')
    ready, result = (decode_record(raw, nonce, spec) for raw in (ready_raw, result_raw))
    _context(ready, spec, loader_pid)
    _context(result, spec, loader_pid)
    _require(ready['phase'] == 1 and ready['flags'] == READY_FLAGS and ready['passes'] == 0
             and all(ready[f'{name}_{suffix}'] == 0 for name in ('lib', 'app') for suffix in TARGET_SUFFIXES),
             'Exact zero-observation readiness required')
    _require(result['phase'] == 7 and result['flags'] == COMPLETE_FLAGS and result['passes'] == 2
             and all(result[name] == ready[name] for name in WORKER_FIELDS), 'Complete bound current-read result required')
    targets = {}
    for name in ('lib', 'app'):
        row, profile = result, spec['targets'][name]
        value = lambda suffix: row[f'{name}_{suffix}']
        _require(0 < value('maps_before_bytes') <= 524288 and 0 < value('maps_after_bytes') <= 524288
                 and value('maps_before_bytes') == value('maps_after_bytes')
                 and value('start_before') > 0 and value('start_before') == value('start_after')
                 and 0 <= value('word_before') <= 0xffffffff and value('word_before') == value('word_after')
                 and value('version_before') == value('version_after') == profile['stock_version']
                 and value('mem_closed') == 1
                 and all(value(suffix) == 0 for suffix in ('anchor_before_status', 'anchor_after_status',
                                                          'maps_status', 'stat_status', 'mem_status')),
                 'Read context changed or a bounded read/close failed')
        word = value('word_before').to_bytes(4, 'little').hex()
        classification = 'ORIGINAL' if word == profile['original_hex'] else 'PATCHED' if word == profile['patch_hex'] else 'OTHER'
        targets[name] = dict(observation=classification, word_hex=word, start_ticks=value('start_before'),
                             pid=profile['pid'], base_addr=profile['base_addr'], target_addr=profile['target_addr'])
    states = {target['observation'] for target in targets.values()}
    observation = 'OTHER' if 'OTHER' in states else next(iter(states)) if len(states) == 1 else 'MIXED'
    return dict(schema='camera-install-patch-current-observation/1', state='CURRENT_OBSERVATION_ONLY',
        observation=observation, targets=targets, nonce=nonce.hex(), original_patch_nonce=spec['original_patch_nonce'],
        target_spec_sha256=spec_sha256(spec), pending_receipt_sha256=spec['pending_receipt_sha256'],
        pending_payload_sha256=spec['pending_payload_sha256'], body_sha256=spec['body_sha256'], plan_sha256=spec['plan_sha256'],
        original_source_is_hardware=spec['original_source_is_hardware'], original_hardware_origin_proven=False,
        ready=ready, result=result, loader_pid=loader_pid,
        raw_publications=dict(ready=ready_raw.hex(), result=result_raw.hex()),
        publication_sha256=dict(ready=_sha(ready_raw), result=_sha(result_raw)),
        flags_semantics='Bit8 is a bounded initial close pass, not absence of every inherited descriptor',
        evidence_kind='caller_supplied_current_read_bytes', source_is_hardware=False,
        original_mm_continuity_proven=False, RAM_restoration_proven=False, cancellation_authorized=False,
        device_execution_proven=False, hardware_admission_proven=False, firmware_installation_proven=False,
        installation_authorized=False, ready_for_confirmation=False, firmware_entry_authorized=False)


validate_result = validate_publications
