"""Decode caller-supplied runtime bytes; no SDK, collector or admission actions."""
from dataclasses import asdict
import hashlib
import json
import re
import struct

from camera_backup_records import record_map
from camera_postinstall_verify import _fat
from tools.fl23_prewrite_guard import (PASS, guard_model, guard_region,
                                      guard_lsi_main, guard_nand_capacity)

PDT_BYTES = 2369436
P1_BYTES = 25100288
MAX_PARTITIONS_BYTES = 65536
PARTITION_UNIT_BYTES = 1024
POWER_IC_KEY = 0x00510001
EXPECTED_MODEL = 0x01030081
EXPECTED_REGION = 0
DEVICE = re.compile(r'nflasha(0|[1-9][0-9]*)\Z')
DECIMAL = re.compile(r'[0-9]+\Z')
NAME = re.compile(r'[A-Za-z0-9_.-]{1,128}\Z')


def require(ok, message):
    if not ok:
        raise ValueError(message)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def _partitions(raw):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_PARTITIONS_BYTES, 'Bounded raw partitions bytes required')
    try:
        lines = [line.split() for line in raw.decode('ascii').splitlines() if line.strip()]
    except UnicodeError as error:
        raise ValueError('Partitions must be ASCII') from error
    require(lines and lines[0] == ['major', 'minor', '#blocks', 'name'], 'Exact proc partitions header required')
    require(0 < len(lines) - 1 <= 4096, 'Bounded nonempty partition rows required')
    rows, device_ids = {}, set()
    for line in lines[1:]:
        require(len(line) == 4 and all(DECIMAL.fullmatch(value) for value in line[:3])
                and NAME.fullmatch(line[3]), 'Malformed partition row')
        major, minor, blocks = map(int, line[:3])
        name = line[3]
        require(major <= 0xffffffff and minor <= 0xffffffff
                and 0 < blocks <= 0x7fffffffffffffff // PARTITION_UNIT_BYTES, 'Invalid partition counts')
        require(name not in rows and (major, minor) not in device_ids, 'Duplicate partition row or device ID')
        device_ids.add((major, minor))
        rows[name] = dict(name=name, major=major, minor=minor, blocks=blocks, bytes=blocks * PARTITION_UNIT_BYTES)
    return rows


def decode_runtime(*, pdt_raw, p1_raw, partitions_raw, alias_targets, required_partition_sizes,
                   normal_model_name, expected_model=EXPECTED_MODEL, expected_region=EXPECTED_REGION):
    """Validate decoded numeric axes, never their hardware origin or freshness.

    Required keys are canonical nflashaN names. Alias values must be the actual
    caller-observed canonical /dev/cnflashaN or /dev/pnflashaN target for that N.
    Relative targets and implicit prefix-based mappings are not accepted.
    """
    require(type(expected_model) is int and expected_model == EXPECTED_MODEL
            and type(expected_region) is int and expected_region == EXPECTED_REGION,
            'Only the pinned package model and region are supported')
    require(type(normal_model_name) is str and normal_model_name == 'ILCE-7M4', 'Exact normal SDK model name required')
    require(type(pdt_raw) is bytes and len(pdt_raw) == PDT_BYTES, 'Exact full raw PDT length required')
    require(type(p1_raw) is bytes and len(p1_raw) == P1_BYTES, 'Exact full raw P1 length required')
    require(isinstance(required_partition_sizes, dict) and required_partition_sizes
            and all(type(key) is str and DEVICE.fullmatch(key) and type(value) is int
                    and 0 < value <= 0x7fffffffffffffff for key, value in required_partition_sizes.items()),
            'Canonical positive package partition requirements required')
    required = dict(required_partition_sizes)
    require(isinstance(alias_targets, dict) and set(alias_targets) == set(required), 'Exact required alias keyset required')
    aliases = dict(alias_targets)
    for name, target in aliases.items():
        require(type(target) is str and target in ('/dev/c' + name, '/dev/p' + name),
                'Actual alias target must name the corresponding partition without normalization')
    filesystem = _fat(p1_raw)
    dat2, dat3 = filesystem.read('DAT2'), filesystem.read('DAT3')
    require(len(dat2) == len(dat3) == 4, 'P1 DAT2 and DAT3 must each be exactly four bytes')
    model, region = struct.unpack('<I', dat2)[0], struct.unpack('<I', dat3)[0]
    records = record_map(pdt_raw)
    power = []
    for chip in (0, 1):
        item = records.get((chip, POWER_IC_KEY))
        require(item is not None and len(item[1]) == 1, 'Power IC record must be exactly one byte in both PDT chips')
        power.append(item[1][0])
    require(power[0] == power[1], 'Power IC values disagree across PDT chips')
    rows = _partitions(partitions_raw)
    capacities, views = {}, {}
    for name, want in required.items():
        cname, pname = 'c' + name, 'p' + name
        require(cname in rows and pname in rows, 'Both cn and pn partition views required: ' + name)
        cview, pview = rows[cname], rows[pname]
        require(cview['bytes'] == pview['bytes'], 'Partition views disagree: ' + name)
        capacities[name] = rows[aliases[name][5:]]['bytes']
        views[name] = dict(alias_target=aliases[name], cn=cview, pn=pview, required_bytes=want)
    checks = [guard_model(f'{expected_model:08x}', f'{model:08x}'), guard_region(expected_region, region),
              guard_lsi_main(power[0]), guard_nand_capacity(required, capacities)]
    require(all(item.status == PASS for item in checks), 'Decoded numeric checks failed: ' +
            '; '.join(item.name + '=' + item.status for item in checks))
    return dict(schema='camera-install-runtime-decoded-values/1',
        state='DECODED_VALUES_ONLY', normal_model_name=normal_model_name,
        values=dict(model_code=model, model_code_hex=f'{model:08x}', region=region,
                    power_ic_type=power[0], power_ic_by_chip=power),
        capacities=capacities, partition_views=views, partition_unit_bytes=PARTITION_UNIT_BYTES,
        partition_rows_seen=len(rows), decoded_value_checks=[asdict(item) for item in checks],
        raw_inputs=dict(pdt=dict(bytes=len(pdt_raw), sha256=_sha(pdt_raw)),
                        p1=dict(bytes=len(p1_raw), sha256=_sha(p1_raw)),
                        proc_partitions=dict(bytes=len(partitions_raw), sha256=_sha(partitions_raw))),
        alias_targets=aliases, alias_targets_sha256=_sha(_canonical(aliases)),
        required_partition_sizes=required, required_partition_sizes_sha256=_sha(_canonical(required)),
        evidence_kind='caller_supplied_raw_bytes_and_explicit_alias_targets',
        source_is_hardware=False, hardware_origin_proven=False, runtime_freshness_proven=False,
        alias_device_stat_proven=False, package_requirements_proven=False, READY=False,
        ready_for_confirmation=False, write_admission=False, installation_authorized=False,
        hardware_admission_proven=False, device_execution_proven=False,
        limitations=['Numeric PASS values do not authenticate source, capture time, device aliases or package lineage',
                     'P1 DAT2/DAT3 are decoded from supplied bytes; historical bytes remain historical',
                     'Power IC BKID00510001 is separate from the LSI backup record004b0000',
                     'No vendor getter, mount, SDK or device operation is performed'])
