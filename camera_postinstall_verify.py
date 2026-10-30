"""Read-only offline acceptance of firmware files and critical BK4 settings.

No device/SDK, USB, process probe, extraction executable, or recovery operation.
source_is_hardware comes from the caller's trusted acquisition context and must
match every recorded source flag. JSON/nonces/digests do not authenticate that
context or prove hardware provenance. A model run may pass content checks but
is never promoted to hardware. This scope excludes physical behavior and NOR.
"""
import hashlib
import importlib
import importlib.util
import json
from pathlib import Path
import re
import stat
import struct
import sys
import tarfile
import zlib

from camera_backup_records import COLOUR_KEYS, SLOTS, record_map, unique_record

ROOT = Path(__file__).resolve().parent
PLAIN = ROOT / 'output/fl23-stock-receiver-plain-01/plain.DO_NOT_INSTALL.bin'
FACTORY_P1 = ROOT / 'local/recovery/backup-01/cnflasha1.bin'
PLAIN_SHA = 'ebc7f537c21b685609f646670ab8b381db15d7283d259cbb587a2c0a008a51bf'
FACTORY_SHA = 'd415c4766c62b5b63bf106306e67b6a0512c4f97db834378e47ef79c40cf580b'
INITRD_SHA = '89d798faa7b57b9d06e04b6430635ff1c048d878d6f96fd498147aa5a822e203'
TEMPLATE = '0110_backup/SYSIPSX-DSLR/LS/CH89101_CN1.bin'
UPDATER_P1 = '0400_updater/dev/nflasha1'
BOOT_FILES = ('boot/CXD90057.DTB', 'boot/KEMCO.TXT', 'boot/LOADADDR.TXT')
PROFILES = {
    'post_app': (98212632, 'd17e61fb4ba193d8e7d802196edff5f578d5691b3fcc4abcd1cbbb6e58bdd8ff', '/usr/lib/appFw.so', 'REGULAR'),
    'post_cp': (16236816, '4551c73386c27a0a9b247fd3e05c3bd5e3425bdb9fe9f8374c201c96533b3479', '/cp/cpapp-b.bin', 'REGULAR'),
    'post_p1': (25100288, None, '/dev/cnflasha1', 'BLOCK'),
}
NONCE = re.compile(r'[0-9a-f]{32}\Z')
SHA = re.compile(r'[0-9a-f]{64}\Z')


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _regular(path):
    path = Path(path).absolute()
    # Check every existing component; resolving first would hide symlinks.
    for component in (path, *path.parents):
        require(not component.is_symlink(), 'Symlink evidence/reference is forbidden')
    require(stat.S_ISREG(path.stat().st_mode), 'Expected regular local file')
    return path


def _within(root, value):
    require(isinstance(value, str), 'Evidence path must be a string')
    value = Path(value)
    path = _regular(root / value if not value.is_absolute() else value)
    require(path.resolve().is_relative_to(root.resolve()), 'Evidence path escapes group directory')
    return path


def _json(path, expected_sha=None):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'Duplicate JSON field')
            result[key] = value
        return result
    raw = _regular(path).read_bytes()
    require(expected_sha is None or sha(raw) == expected_sha, 'Capture report SHA mismatch')
    result = json.loads(raw, object_pairs_hook=pairs)
    require(isinstance(result, dict), 'JSON report must be an object')
    return result


def _fat(raw):
    # Load only reference FAT + common (stdlib). fl23 imports offline crypto and
    # must not be imported here. Package isolation avoids an installed SDK.
    name = '_camera_postinstall_fat_reference'
    if name not in sys.modules:
        folder = ROOT / 'ref/sony-a7m4-custom-firmware/a7m4'
        spec = importlib.util.spec_from_file_location(name, folder / '__init__.py',
                                                    submodule_search_locations=[str(folder)])
        package = importlib.util.module_from_spec(spec)
        sys.modules[name] = package
        spec.loader.exec_module(package)
    return importlib.import_module(name + '.fat').Fat(raw)


def _same_binding(report, binding):
    require(all(report.get(key) == value for key, value in binding.items()), 'Plan/body/model binding mismatch')


def _source(report, expected):
    require(type(report.get('source_is_hardware')) is bool and
            report['source_is_hardware'] is expected, 'Source provenance flag mismatch')


def _nonce(value, seen):
    require(isinstance(value, str) and NONCE.fullmatch(value) and value not in seen,
            'Missing, reused, or invalid fresh nonce')
    seen.add(value)


def _not_candidate(path, forbidden):
    identity = path.stat()
    require((identity.st_dev, identity.st_ino) not in forbidden, 'Capture is an offline candidate inode')


def _reference_inputs(plain_path, factory_path):
    plain, factory = _regular(plain_path), _regular(factory_path)
    with plain.open('rb') as stream:
        require(hashlib.file_digest(stream, 'sha256').hexdigest() == PLAIN_SHA, 'Pinned new plaintext SHA mismatch')
        stream.seek(0)
        header = stream.read(512)
        require(len(header) == 512 and header[:8] == b'UDTRFIRM' and
                struct.unpack_from('<I', header, 8)[0] == zlib.crc32(header[12:]), 'New package header/CRC mismatch')
        start, length = struct.unpack_from('<II', header, 48)
        require(start >= 512 and start + length == plain.stat().st_size, 'New package archive bounds')
        stream.seek(start)
        members = {TEMPLATE: [], UPDATER_P1: []}
        with tarfile.open(fileobj=stream, mode='r|') as archive:
            for member in archive:
                name = member.name.removeprefix('./')
                require(not name.startswith('/') and '..' not in Path(name).parts, 'Unsafe archive member')
                require(member.offset_data + member.size <= length, 'Archive member outside package')
                if name in members:
                    require(member.isfile(), 'Selected template is not a regular member')
                    members[name].append(archive.extractfile(member).read())
        require(all(len(values) == 1 for values in members.values()),
                'Missing/duplicate selected settings template or updater P1')
        stream.seek(0)
        require(hashlib.file_digest(stream, 'sha256').hexdigest() == PLAIN_SHA,
                'Pinned plaintext changed during verification')
    factory_raw = factory.read_bytes()
    require(sha(factory_raw) == FACTORY_SHA, 'Pinned factory P1 SHA mismatch')
    package_p1 = _fat(members[UPDATER_P1][0])
    boot_files = {name: package_p1.read(name) for name in BOOT_FILES}
    return header, members[TEMPLATE][0], _fat(factory_raw).read('boot/vmlinux.bin'), boot_files


def _capture(root, profile, report_relative, report_sha256, binding, group_nonce, source, seen, forbidden):
    require(isinstance(report_relative, str) and not Path(report_relative).is_absolute(),
            'Capture report paths must be relative to group directory')
    report_path = _within(root, report_relative)
    report = _json(report_path, report_sha256)
    require(report.get('profile') == profile and report.get('name') == profile, 'Wrong capture profile')
    _source(report, source)
    if any(key in report for key in binding):
        _same_binding(report, binding)
    if 'group_nonce' in report:
        require(report['group_nonce'] == group_nonce, 'Capture report group nonce mismatch')
    _nonce(report.get('nonce'), seen)
    count, expected_sha, source_path, source_kind = PROFILES[profile]
    require(report.get('source_path') == source_path and report.get('targetpath') == source_path and
            report.get('source_kind') == source_kind, 'Wrong capture source')
    require(type(report.get('bytes')) is int and report['bytes'] == count, 'Capture geometry mismatch')
    require(report.get('expected_sha256') == expected_sha, 'Capture expected hash mismatch')
    capture = _within(root, report['capture'])
    _not_candidate(capture, forbidden)
    require(capture.stat().st_size == count, 'Captured file length mismatch')
    captured_raw = capture.read_bytes()
    require(len(captured_raw) == count, 'Captured file length changed')
    host_sha = sha(captured_raw)
    require(report.get('sha256') == host_sha and (expected_sha is None or host_sha == expected_sha),
            'Captured file SHA mismatch')
    status = _json(_within(root, str(report_path.parent / 'capture/status.json')))
    _source(status, source)
    require(status.get('nonce') == report['nonce'] and status.get('sha256') == host_sha and
            status.get('partition') == profile and status.get('bytes') == count and
            status.get('state') == 'TWO_READS_MATCHED' and status.get('source_reads_equal_at_capture') is True and
            status.get('hardware_source_read_verified') is source, 'Capture status mismatch')
    ready_record = _json(_within(root, str(report_path.parent / 'launch-and-ready.json')))
    completed = _json(_within(root, str(report_path.parent / 'completed.json')))
    native, ready = report['native'], ready_record['ready']
    require(isinstance(native, dict) and native == completed.get('native'), 'Native report mismatch')
    for value in (native, ready):
        require(all(type(value.get(key)) is int for key in
                    ('version', 'phase', 'error', 'euid', 'pid', 'ppid', 'loader_pid', 'cleanup', 'flags')),
                'Native identity fields must be integers')
        require(value['version'] == 1 and value['error'] == value['cleanup'] == value['euid'] == 0 and
                value['ppid'] == 1 and value['pid'] > 1 and value['loader_pid'] > 1 and
                value['pid'] != value['loader_pid'], 'Native worker identity invalid')
    require(all(native[key] == ready[key] for key in ('pid', 'ppid', 'euid', 'loader_pid')) and
            ready_record.get('loader_pid') == native['loader_pid'], 'Ready/final process identity changed')
    require(ready['phase'] == 1 and ready['flags'] == 3 and native['phase'] == 6 and native['flags'] == 63 and
            native.get('offset') == count and native.get('chunks') == (count + 8388607) // 8388608 and
            native.get('first_sha256') == native.get('second_sha256') == host_sha,
            'Native phase/double-source digest rejected')
    require(completed.get('partition') == profile and completed.get('bytes') == count and
            _within(root, completed['backup']) == capture, 'Completed capture target mismatch')
    return captured_raw, {'bytes': count, 'sha256': host_sha, 'nonce': report['nonce']}


def _critical_settings(root, references, binding, group_nonce, source, seen, forbidden, template):
    records = {}
    for name in ('before', 'after'):
        reference = references[name]
        require(reference.get('acquisition_phase') == ('PRE_INSTALL' if name == 'before' else 'POST_INSTALL'),
                'Settings acquisition phase mismatch')
        _same_binding(reference, binding)
        _source(reference, source)
        require(reference.get('group_nonce') == group_nonce, 'Settings group nonce mismatch')
        _nonce(reference.get('nonce'), seen)
        path = _within(root, reference['path'])
        _not_candidate(path, forbidden)
        raw = path.read_bytes()
        require(reference.get('sha256') == sha(raw), 'Settings capture SHA mismatch')
        records[name] = record_map(raw)
    before, after = records['before'], records['after']
    require(before.keys() == after.keys(), 'BK4 ids changed')
    require(all((attrs, len(value)) == (after[key][0], len(after[key][1]))
                for key, (attrs, value) in before.items()), 'BK4 attributes/length changed')
    require(unique_record(after, 0x004b0001)[1] == b'\x02', 'Condition key 004B0001 is not 02')
    for key in SLOTS:
        require(unique_record(before, key) == unique_record(after, key), 'Selected slot was not preserved')
    expected = record_map(template)
    for key in COLOUR_KEYS:
        require(unique_record(after, key) == unique_record(expected, key), 'Selected package colour record mismatch')
    return {'ids_attrs_lengths_preserved': True, 'condition_key_004b0001': '02',
            'six_slots_preserved': True, 'colour_template': TEMPLATE,
            'all_calibration_verified': False, 'all_attribute_merge_semantics_verified': False}


def verify_p1_semantics(raw, *, header, factory_kernel, boot_files):
    """Check the receiver boot files and body metadata, without asserting a write branch."""
    require(type(header) is bytes and len(header) == 512 and set(boot_files) == set(BOOT_FILES),
            'Complete pinned P1 semantic references required')
    p1 = _fat(raw)
    initrd, kernel = p1.read('boot/initrd.img'), p1.read('boot/vmlinux.bin')
    expected_sum = (hashlib.md5(kernel).hexdigest() + '  ./boot/vmlinux.bin\n' +
                    hashlib.md5(initrd).hexdigest() + '  ./boot/initrd.img\n').encode('ascii')
    require(sha(initrd) == INITRD_SHA and kernel == factory_kernel, 'P1 initrd/kernel mismatch')
    require(p1.read('P1CHKSUM') == expected_sum, 'P1CHKSUM mismatch')
    require(p1.read('DAT2') == header[36:40] and p1.read('DAT3') == header[40:44],
            'P1 DAT2/DAT3 model/region mismatch')
    require(all(p1.read(name) == expected for name, expected in boot_files.items()),
            'P1 device-tree or boot configuration mismatch')
    return dict(initrd_sha256=sha(initrd), kernel_sha256=sha(kernel),
                boot_files={name: sha(value) for name, value in boot_files.items()},
                model_bytes=header[36:40].hex(), region_bytes=header[40:44].hex(),
                nwu_branch_execution_proven=False)


def verify_capture_run(run_path, *, plan_sha256, body_sha256, model, group_nonce,
                       source_is_hardware=False, plain_path=PLAIN,
                       factory_p1_path=FACTORY_P1, offline_candidates=()):
    """Return fail-closed acceptance JSON; missing checks become pending.

    All input paths are read-only. ``run_path`` names capture-run.json in a
    dedicated evidence group. Reports must be group-contained, while two pinned
    references may be outside it. Caller must supply the expected fresh group
    nonce and trusted source context; the report cannot authenticate either.
    """
    binding = dict(plan_sha256=plan_sha256, body_sha256=body_sha256, model=model)
    result = dict(binding, verification_scope='FIRMWARE_FILES_AND_CRITICAL_SETTINGS',
                  source_is_hardware=source_is_hardware is True, all_passed=False,
                  group_nonce=group_nonce, checks={}, pending=[],
                  photo_verified=False, video_verified=False, actual_NOR_verified=False,
                  other_MCU_verified=False, whole_device_functional_installation_verified=False,
                  source_provenance='Requires a trusted collector and caller context; JSON does not prove hardware origin')
    try:
        require(type(source_is_hardware) is bool, 'Explicit bool source context required')
        require(isinstance(plan_sha256, str) and SHA.fullmatch(plan_sha256) and
                isinstance(body_sha256, str) and SHA.fullmatch(body_sha256) and
                isinstance(model, str) and bool(model.strip()), 'Invalid expected binding')
        require(isinstance(group_nonce, str) and NONCE.fullmatch(group_nonce), 'Invalid expected group nonce')
        path = _regular(run_path)
        root = path.parent
        run = _json(path)
        require(run.get('schema') == 'camera-postinstall-capture-run/1', 'Capture group schema mismatch')
        _same_binding(run, binding)
        _source(run, source_is_hardware)
        require(run.get('group_nonce') == group_nonce and run.get('normal_body_verified') is True,
                'Fresh group/normal body context mismatch')
        require(isinstance(run.get('captures'), dict) and set(run['captures']) == set(PROFILES),
                'Exactly three post-install capture profiles required')
        forbidden = set()
        for candidate in (plain_path, factory_p1_path, *offline_candidates):
            location = _regular(candidate)
            metadata = location.stat()
            forbidden.add((metadata.st_dev, metadata.st_ino))
        header, template, factory_kernel, boot_files = _reference_inputs(plain_path, factory_p1_path)
        result['checks']['pinned_package_and_factory'] = True
        seen, captures = {group_nonce}, {}
        # The mandatory group references bind each immutable report digest to
        # this plan/body/model and group; optional report binding must agree.
        for profile in PROFILES:
            reference = run['captures'][profile]
            require(isinstance(reference, dict), 'Capture reference must include path and report SHA')
            report_file = _within(root, reference['path'])
            require(isinstance(reference.get('sha256'), str) and SHA.fullmatch(reference['sha256']),
                    'Capture reference SHA required')
            _same_binding(reference, binding)
            require(reference.get('group_nonce') == group_nonce, 'Capture reference group mismatch')
            raw, summary = _capture(root, profile, reference['path'], reference['sha256'], binding, group_nonce,
                                    source_is_hardware, seen, forbidden)
            captures[profile] = raw
            result['checks'][profile] = summary
        semantics = verify_p1_semantics(captures['post_p1'], header=header,
                                       factory_kernel=factory_kernel, boot_files=boot_files)
        result['checks']['p1_boot_files'] = semantics['boot_files']
        result['checks']['p1_semantics'] = True
        result['checks']['critical_settings'] = _critical_settings(
            root, run['critical_settings'], binding, group_nonce, source_is_hardware, seen, forbidden, template)
        result['all_passed'] = True
    except Exception as error:
        # Filesystem/parse/reference unavailability all fail closed. No device
        # action, new dependency, or inferred success is attempted on failure.
        result['pending'].append({'check': 'remaining_acceptance', 'reason': type(error).__name__ + ': ' + str(error)})
    return result
