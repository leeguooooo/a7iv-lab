"""Pure receipt contract for a fixed stock-6.02 volatile patch publication.

Caller-supplied bytes establish consistency only. They cannot prove device
origin, execution, restoration, installation readiness or authorization.
"""
import hashlib
import struct

MAGIC = b'M4IVP001'
VERSION = 2
START_MAGIC = b'M4ISTART'
BASE_FIELDS = ('version', 'phase', 'error', 'euid', 'pid', 'ppid', 'loader_pid', 'cleanup',
               'maps_bytes', 'polls', 'target_addr', 'base_addr', 'machine_version',
               'patched', 'restored', 'hold_seconds', 'flags', 'mem_status', 'restore_status')
APP_FIELDS = ('app_pid', 'app_target_addr', 'app_base_addr', 'app_machine_version',
              'app_patched', 'app_restored', 'app_mem_status', 'app_restore_status', 'app_write_attempted')
STATUS_FIELDS = ('app_maps_bytes', 'proc_candidates', 'identity_checks', 'lib_identity_status',
                 'app_identity_status', 'snapshot_before_status', 'snapshot_end_status')
OBSERVATIONS = ('usb_stream', 'network_stream', 'slot1_mount', 'media_error',
                'target_version', 'query_error', 'inhibited', 'debug_exclusion')
SNAPSHOT_FIELDS = tuple(f'{phase}_{name}' for phase in ('before', 'end') for name in OBSERVATIONS)
FIELDS = BASE_FIELDS + APP_FIELDS + STATUS_FIELDS + SNAPSHOT_FIELDS
FRAME = struct.Struct('<8s16s51q')
WORKER_FIELDS = ('euid', 'pid', 'ppid', 'loader_pid', 'cleanup')
TARGET_FIELDS = ('app_pid', 'target_addr', 'base_addr', 'machine_version', 'app_target_addr',
                 'app_base_addr', 'app_machine_version', 'maps_bytes', 'app_maps_bytes',
                 'proc_candidates', 'polls')
ZERO_STATUSES = ('mem_status', 'app_mem_status', 'restore_status', 'app_restore_status',
                 'lib_identity_status', 'app_identity_status', 'snapshot_before_status', 'snapshot_end_status')


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _pid(value):
    return type(value) is int and 1 < value <= 0x7fffffff


def decode_record(raw, nonce):
    """Decode one complete v2 record without attributing its origin."""
    _require(type(raw) is bytes and len(raw) == FRAME.size, 'Complete 432-byte volatile record required')
    _require(type(nonce) is bytes and len(nonce) == 16, 'Exact 16-byte nonce required')
    magic, received_nonce, *values = FRAME.unpack(raw)
    _require(magic == MAGIC and received_nonce == nonce, 'Volatile record identity differs')
    row = dict(zip(FIELDS, values))
    _require(row['version'] == VERSION and row['phase'] in (1, 2, 3, 4, 5, 7, 90)
             and -4095 <= row['error'] <= 0
             and ((row['phase'] == 90 and row['error'] < 0)
                  or (row['phase'] != 90 and row['error'] == 0)),
             'Unsupported volatile result contract')
    _require(0 <= row['flags'] <= 1021 and not row['flags'] & ~1021, 'Unknown volatile flags')
    _require(all(row[name] in (0, 1) for name in
                 ('patched', 'restored', 'app_patched', 'app_restored', 'app_write_attempted')),
             'Invalid volatile Boolean')
    _require(bool(row['flags'] & 128) == bool(row['patched'])
             and bool(row['flags'] & 256) == bool(row['restored'])
             and (not row['patched'] or row['flags'] & 512)
             and (not row['restored'] or row['flags'] & 512)
             and (not row['app_patched'] or row['app_write_attempted'])
             and (not row['app_restored'] or row['app_write_attempted'])
             and (row['phase'] == 90 or row['restored'] == row['app_restored'] == 0),
             'Contradictory volatile write flags')
    return row


def _successful_lifecycle(row):
    _require(_pid(row['pid']) and _pid(row['loader_pid']) and row['pid'] != row['loader_pid']
             and row['euid'] == 0 and row['ppid'] == 1 and row['cleanup'] == 0
             and row['hold_seconds'] >= 0, 'Volatile process identity/lifecycle rejected')


def _ready(row, loader_pid):
    _successful_lifecycle(row)
    zero_fields = tuple(name for name in BASE_FIELDS[8:] + APP_FIELDS + STATUS_FIELDS[:5] if name != 'flags')
    _require(row['phase'] == 1 and row['error'] == 0 and row['flags'] == 13
             and row['loader_pid'] == loader_pid and all(row[name] == 0 for name in zero_fields)
             and row['snapshot_before_status'] == row['snapshot_end_status'] == -11
             and all(row[name] == -1 for name in SNAPSHOT_FIELDS),
             'Volatile readiness must be the exact zero-target publication')


def _applied(row, phase):
    _successful_lifecycle(row)
    _require(row['phase'] == phase and row['error'] == 0 and row['flags'] == 765
             and row['patched'] == row['app_patched'] == row['app_write_attempted'] == 1
             and row['restored'] == row['app_restored'] == row['hold_seconds'] == 0,
             'Applied volatile publication must retain both patches without restoration')
    _require(_pid(row['app_pid']) and row['app_pid'] != row['pid']
             and row['base_addr'] > 0 and row['app_base_addr'] > 0
             and row['base_addr'] % 4096 == row['app_base_addr'] % 4096 == 0
             and row['target_addr'] == row['base_addr'] + 8016
             and row['app_target_addr'] == row['app_base_addr'] + 40219336
             and row['target_addr'] % 4 == row['app_target_addr'] % 4 == 0
             and row['machine_version'] == 0x0602 and row['app_machine_version'] == 0x00060002,
             'Fixed stock-6.02 volatile target identity required')
    _require(0 < row['maps_bytes'] <= 524288 and 0 < row['app_maps_bytes'] <= 524288
             and row['polls'] > 0 and row['proc_candidates'] == 1 and row['identity_checks'] >= 6
             and all(row[name] == 0 for name in ZERO_STATUSES),
             'Complete bounded maps, identity checks and zero statuses required')
    for snapshot in ('before', 'end'):
        for index, name in enumerate(OBSERVATIONS):
            maximum = 0xffffffff if index < 6 else 255
            _require(0 <= row[f'{snapshot}_{name}'] <= maximum, 'Stock observation width differs')


def validate_publications(ready_raw, patched_raw, result_raw, *, nonce, loader_pid):
    """Validate three bound snapshots, without executing or authorizing actions."""
    _require(_pid(loader_pid), 'Bound loader PID required')
    ready, patched, result = (decode_record(raw, nonce) for raw in (ready_raw, patched_raw, result_raw))
    _ready(ready, loader_pid)
    _applied(patched, 5)
    _applied(result, 7)
    _require(all(patched[name] == ready[name] == result[name] for name in WORKER_FIELDS),
             'Worker identity changed between publications')
    _require(all(result[name] == patched[name] for name in TARGET_FIELDS + SNAPSHOT_FIELDS)
             and result['identity_checks'] >= patched['identity_checks'],
             'Volatile targets, maps or snapshots changed between publications')
    publications = dict(ready=ready_raw, patched=patched_raw, result=result_raw)
    return dict(state='VOLATILE_PATCH_APPLIED_NOT_RESTORED', nonce=nonce.hex(),
                ready=ready, patched=patched, result=result,
                publication_sha256={name: hashlib.sha256(raw).hexdigest() for name, raw in publications.items()},
                worker_identity={name: ready[name] for name in WORKER_FIELDS},
                target_identity={name: patched[name] for name in TARGET_FIELDS},
                evidence_kind='caller_supplied_publication_bytes',
                RAM_restoration_proven=False, firmware_installation_proven=False,
                installation_authorized=False, device_execution_proven=False,
                menu_readiness_proven=False, firmware_readiness_proven=False,
                installation_readiness_proven=False)
