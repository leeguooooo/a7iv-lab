"""Stage one verified candidate under an unrecognized name on verified Sony media.

Host filesystem only. No SDK, service mode, block-device write or card format.
The separate authorized activation helper changes card filenames only; it never
invokes an updater or authorizes firmware installation.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import secrets
import stat
import subprocess
from camera_device_lease import CameraDeviceLease
from camera_operation_guard import assert_operation_allowed
from camera_device_lease import CameraDeviceLease as _LeaseType

ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / 'output/fl23-stock-receiver-container-01/BODYDATA.UNTESTED_DO_NOT_INSTALL.DAT'
DIGEST = 'fc8a7865c95059dcb4ac2a347a06b4a76f016b9c37dcc8412dfe9c2c2111de6a'
SIZE = 757480856
REPORT = ROOT / 'output/sd-candidate-stage-01'


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(path, uncached=False):
    with Path(path).open('rb') as f:
        if uncached and hasattr(fcntl, 'F_NOCACHE'):
            fcntl.fcntl(f.fileno(), fcntl.F_NOCACHE, 1)
        return hashlib.file_digest(f, 'sha256').hexdigest()


def save(path, value):
    with Path(path).open('x') as f:
        os.fchmod(f.fileno(), 0o600);json.dump(value, f, indent=2);f.write('\n');f.flush();os.fsync(f.fileno())


def disk_info(name):
    require(name.startswith('disk') and all(c.isdigit() or c == 's' for c in name[4:]), 'Invalid BSD disk name')
    return plistlib.loads(subprocess.check_output(['/usr/sbin/diskutil', 'info', '-plist', name]))


def discover():
    expected = json.loads((ROOT / 'output/backup-01/execution/run.json').read_text())['body']['usb_serial_sha256']
    raw = subprocess.check_output(['/usr/sbin/ioreg', '-r', '-c', 'IOUSBHostDevice', '-a', '-l'])
    tree = plistlib.loads(raw) if raw.strip() else []
    devices = {}
    def walk(node):
        if isinstance(node, dict):
            serial = node.get('USB Serial Number')
            if (node.get('IOObjectClass') == 'IOUSBHostDevice' and node.get('idVendor') == 0x054c
                    and node.get('idProduct') == 0x0da5 and isinstance(serial, str)
                    and hashlib.sha256(serial.encode()).hexdigest() == expected):
                devices[node['IORegistryEntryID']] = node
            for value in node.values():walk(value)
        elif isinstance(node, list):
            for value in node:walk(value)
    walk(tree)
    require(len(devices) == 1, 'Exactly one reference Sony MSC body must be present')
    registry_id, device = next(iter(devices.items()))
    media = {}
    def collect(node):
        if isinstance(node, dict):
            if node.get('IOObjectClass') == 'IOMedia' and 'BSD Name' in node:
                media[node['BSD Name']] = node
            for value in node.values():collect(value)
        elif isinstance(node, list):
            for value in node:collect(value)
    collect(device)
    candidates, ignored = [], []
    for name, node in media.items():
        if node.get('Whole') is not False:
            continue
        data = disk_info(name)
        if (data.get('Writable') is not True or data.get('TotalSize', 0) < SIZE + 67108864
                or not data.get('MountPoint')):
            ignored.append({'BSD': name, 'name': data.get('VolumeName'), 'bytes': data.get('TotalSize'),
                            'writable': data.get('Writable')})
            continue
        mount = Path(data['MountPoint'])
        require(mount.resolve() == mount and mount.parent == Path('/Volumes') and os.path.ismount(mount),
                'Expected a directly mounted external volume')
        require(data.get('ParentWholeDisk') in media and data.get('VolumeUUID')
                and data.get('FilesystemType') in ('exfat', 'msdos'), 'Unbound or unsupported camera volume')
        volume = dict(device=name, parent=data['ParentWholeDisk'], mount=str(mount),
                      volume_uuid=data['VolumeUUID'], volume_bytes=data['TotalSize'],
                      registry_id=registry_id, body_matched=True, body_sha256=expected, filesystem=data['FilesystemType'])
        candidates.append(volume)
    require(len(candidates) == 1, 'Need one unambiguous writable camera card; no automatic multi-card selection')
    volume = candidates[0];vfs=os.statvfs(volume['mount'])
    require(vfs.f_bavail*vfs.f_frsize >= SIZE + 67108864, 'Insufficient free card space')
    volume['free_bytes'] = vfs.f_bavail*vfs.f_frsize
    volume['excluded_media'] = ignored
    return volume


def snapshot_existing(mount):
    path = mount / 'BODYDATA.DAT'
    if not path.exists():return {'exists':False}
    require(not path.is_symlink() and stat.S_ISREG(path.stat().st_mode), 'Existing update filename is not a regular file')
    return {'exists':True, 'bytes':path.stat().st_size, 'sha256':digest(path, uncached=True)}


def staged_relative_path(target, mount, sha256):
    """Accept only receipt-bound legacy or isolated attempt candidate names."""
    require(isinstance(target, str) and isinstance(mount, str), 'Unsafe staged receipt path')
    base, path = Path(mount), Path(target)
    require(base.is_absolute() and path.is_absolute(), 'Unsafe staged receipt path')
    try:
        relative = path.relative_to(base)
    except ValueError:
        raise ValueError('Unsafe staged receipt path') from None
    parts = relative.parts
    require(len(parts) == 3 and parts[0] == '.camera-use-staging'
            and re.fullmatch('fl23-' + re.escape(sha256[:16]) + r'(?:-[0-9a-f]{16})?', parts[1])
            and parts[2] == 'candidate.staged' and str(base / relative) == target,
            'Unsafe staged receipt path')
    return relative


def _held_lease(lease):
    return (isinstance(lease, _LeaseType) and lease.fd is not None
            and isinstance(lease.metadata, dict) and lease.metadata.get('state') == 'HELD')


def stage(*, lease=None, journal=None, report_path=None):
    if lease is not None:
        require(_held_lease(lease), 'Caller-held CameraDeviceLease required')
        assert_operation_allowed(journal,allowed_states=('SD_STAGE_INTENT',))
        return _stage(report_path)
    with CameraDeviceLease('sd-stage'):
        assert_operation_allowed(journal,allowed_states=('SD_STAGE_INTENT',))
        return _stage(report_path)


def _stage(report_path=None):
    report = Path(report_path) if report_path is not None else REPORT
    require(all(not p.is_symlink() for p in (report, *report.parents)), 'Unsafe local stage report path')
    require(SOURCE.is_file() and not SOURCE.is_symlink() and SOURCE.stat().st_size == SIZE
            and digest(SOURCE) == DIGEST, 'Frozen candidate changed')
    volume = discover();mount=Path(volume['mount'])
    existing = snapshot_existing(mount)
    report.mkdir(mode=0o700)
    save(report/'preflight.json', {'volume':volume, 'source_sha256':DIGEST,
                                 'source_bytes':SIZE, 'existing_root_update':existing})
    # This second read-only discovery precedes the first card mutation.
    current=discover()
    require(all(current[k] == volume[k] for k in ('device','parent','mount','volume_uuid','registry_id','body_sha256')),
            'Camera/card changed during preflight')
    parent=mount/'.camera-use-staging'
    if parent.exists():require(parent.is_dir() and not parent.is_symlink(), 'Staging parent unsafe')
    else:parent.mkdir()
    folder=parent/('fl23-'+DIGEST[:16]+'-'+secrets.token_hex(8));folder.mkdir()
    target=folder/'candidate.staged'
    try:
        written=0
        with SOURCE.open('rb') as src, target.open('xb') as dst:
            while True:
                chunk=src.read(4<<20)
                if not chunk:break
                dst.write(chunk);written+=len(chunk)
                if written%(64<<20)==0:print(json.dumps({'phase':'copying_unrecognized_file','bytes':written,'total':SIZE}),flush=True)
            dst.flush();os.fsync(dst.fileno())
            fullsync=False
            if hasattr(fcntl,'F_FULLFSYNC'):
                try:fcntl.fcntl(dst.fileno(),fcntl.F_FULLFSYNC);fullsync=True
                except OSError:pass
        require(written==SIZE and target.stat().st_size==SIZE and digest(target,uncached=True)==DIGEST,
                'Card staged-file readback mismatch')
        require(snapshot_existing(mount)==existing, 'Existing root BODYDATA changed; stop for review')
        current=discover()
        require(all(current[k]==volume[k] for k in ('device','parent','mount','volume_uuid','registry_id','body_sha256')),
                'Card identity changed during copy')
        result={'state':'STAGED_UNRECOGNIZED_FILE_VERIFIED_NOT_ACTIVATED','target':str(target),
                'source_sha256':DIGEST,'bytes':SIZE,'volume_identity':volume,
                'existing_root_update_unchanged':True,'existing_root_update':existing,
                'full_fsync_supported':fullsync,'uncached_readback_requested':hasattr(fcntl,'F_NOCACHE'),
                'BODYDATA_DAT_created_or_replaced':False,'camera_internal_firmware_modified':False,
                'updater_invoked':False,'slot1_number_not_independently_inferred':True}
        save(report/'completed.json',result)
        print(json.dumps({'state':result['state'],'bytes':SIZE,'sha256':DIGEST,
                          'existing_update_preserved':True}),flush=True)
        return result
    except BaseException as error:
        save(report/'stopped.json',{'error_type':type(error).__name__,'target':str(target),
                                  'automatic_retry':False,'updater_invoked':False})
        raise


def rename_exclusive(source, target):
    """Darwin same-volume rename with atomic no-replace semantics.

    RENAME_EXCL=0x4 is defined by the installed macOS SDK sys/stdio.h.
    No exists()+rename fallback is safe against concurrent target creation.
    ctypes/libc are loaded only when explicitly executing this operation.
    """
    import ctypes
    import sys
    require(sys.platform == 'darwin', 'Darwin exclusive rename required')
    source, target = Path(source), Path(target)
    require(source.stat().st_dev == target.parent.stat().st_dev, 'Same-volume rename required')
    libc = ctypes.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True)
    rename = libc.renamex_np
    rename.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint)
    rename.restype = ctypes.c_int
    if rename(os.fsencode(source), os.fsencode(target), 0x00000004) != 0:
        number = ctypes.get_errno()
        raise OSError(number, os.strerror(number), str(target))


def _sync_directory(path):
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _path_state(path):
    # Reports do not follow a changed/symlinked target during failure handling.
    if path is None:
        return None
    try:
        value = path.lstat()
        return dict(path=str(path), exists=True, regular=stat.S_ISREG(value.st_mode),
                    symlink=stat.S_ISLNK(value.st_mode), bytes=value.st_size)
    except FileNotFoundError:
        return dict(path=str(path), exists=False)
    except OSError as error:
        return dict(path=str(path), error_type=type(error).__name__)


def activate_staged(*, activation_authorized=False, slot1_confirmed=False, lease=None, journal=None,
                    rename_fn=None):
    """Activate a reviewed staged file for preview only; no installation license.

    Caller must explicitly approve activation and independently confirm Slot 1.
    Unknown outcomes remain in place for manual review, never rollback/resume.
    ``rename_fn`` is an offline-test injection implementing exclusive rename.
    """
    require(activation_authorized is True, 'Explicit card activation approval required')
    require(slot1_confirmed is True, 'Manual Slot 1 confirmation required')
    if lease is not None:
        require(_held_lease(lease), 'Caller-held CameraDeviceLease required')
        assert_operation_allowed(journal,allowed_states=('SD_STAGE_INTENT','SD_STAGED'))
        return _activate_staged(rename_fn or rename_exclusive)
    with CameraDeviceLease('sd-activate'):
        assert_operation_allowed(journal,allowed_states=('SD_STAGE_INTENT','SD_STAGED'))
        return _activate_staged(rename_fn or rename_exclusive)


def _activate_staged(rename_fn):
    candidate = root_update = backup = None
    phase = 'LOCAL_COMPLETED_REPORT'
    try:
        completed_path = REPORT / 'completed.json'
        require(REPORT.is_dir() and not REPORT.is_symlink() and completed_path.is_file()
                and not completed_path.is_symlink(), 'Regular completed stage report required')
        completed = json.loads(completed_path.read_text())
        require(completed.get('state') == 'STAGED_UNRECOGNIZED_FILE_VERIFIED_NOT_ACTIVATED'
                and completed.get('source_sha256') == DIGEST and completed.get('bytes') == SIZE
                and completed.get('existing_root_update_unchanged') is True
                and completed.get('BODYDATA_DAT_created_or_replaced') is False
                and completed.get('updater_invoked') is False, 'Verified completed stage report required')
        volume = completed['volume_identity']
        body = volume.get('body_sha256')
        require(volume.get('body_matched') is True and isinstance(body, str) and len(body) == 64
                and all(c in '0123456789abcdef' for c in body), 'Completed report lacks bound body SHA')
        identity_keys = ('device', 'parent', 'mount', 'volume_uuid', 'registry_id', 'body_sha256')
        def verify_identity():
            current = discover()
            require(current.get('body_matched') is True
                    and all(current.get(key) == volume[key] for key in identity_keys),
                    'Camera/card identity changed before or during activation')
        verify_identity()
        mount = Path(volume['mount'])
        folder = (mount / staged_relative_path(completed.get('target'), str(mount), DIGEST)).parent
        candidate, root_update, backup = folder/'candidate.staged', mount/'BODYDATA.DAT', folder/'original-BODYDATA.DAT'
        require(mount.resolve() == mount and all(p.is_dir() and not p.is_symlink()
                for p in (mount, folder.parent, folder)), 'Unsafe staging path')
        require(completed.get('target') == str(candidate), 'Completed target differs from staged receipt path')
        def verify_candidate():
            require(candidate.is_file() and not candidate.is_symlink() and candidate.stat().st_size == SIZE
                    and digest(candidate, uncached=True) == DIGEST, 'Staged candidate changed')
        verify_candidate()
        require(not root_update.is_symlink(), 'Unsafe root BODYDATA path')
        existing = completed['existing_root_update']
        require(snapshot_existing(mount) == existing, 'Original root BODYDATA changed')
        require(not backup.exists() and not backup.is_symlink(), 'Original BODYDATA backup already exists')
        require(candidate.stat().st_dev == mount.stat().st_dev, 'Same-volume staged candidate required')
        save(REPORT/'activation-intent.json', dict(state='CARD_FILENAME_ACTIVATION_INTENT',
             source=str(candidate), target=str(root_update), backup=str(backup),
             volume_identity=volume, existing_root_update=existing,
             slot1_manually_confirmed=True, installation_authorized=False,
             updater_invoked=False, automatic_retry=False, automatic_rollback=False))
        _sync_directory(REPORT)
        phase = 'INTENT_DURABLE_BEFORE_CARD_RENAME'
        verify_identity(); verify_candidate()
        require(not root_update.is_symlink() and snapshot_existing(mount) == existing,
                'Original root BODYDATA changed after activation intent')
        if existing['exists']:
            phase = 'ORIGINAL_BACKUP_RENAME_MAY_HAVE_OCCURRED'
            rename_fn(root_update, backup)
            _sync_directory(mount); _sync_directory(folder)
            require(backup.is_file() and not backup.is_symlink()
                    and backup.stat().st_size == existing['bytes']
                    and digest(backup, uncached=True) == existing['sha256'], 'Original backup readback mismatch')
        verify_identity()
        phase = 'CANDIDATE_ROOT_RENAME_MAY_HAVE_OCCURRED'
        rename_fn(candidate, root_update)
        _sync_directory(mount); _sync_directory(folder)
        require(root_update.is_file() and not root_update.is_symlink()
                and root_update.stat().st_size == SIZE and digest(root_update, uncached=True) == DIGEST,
                'Activated root candidate readback mismatch')
        verify_identity()
        result = dict(state='ACTIVATED_PREVIEW_ONLY', target=str(root_update), backup=str(backup),
                      original_root_update=existing, source_sha256=DIGEST, bytes=SIZE,
                      volume_identity=volume, slot1_manually_confirmed=True,
                      updater_invoked=False, installation_authorized=False,
                      camera_internal_firmware_modified=False, automatic_retry=False)
        save(REPORT/'activated-preview-only.json', result)
        return result
    except BaseException as error:
        stopped = dict(state='ACTIVATION_STOPPED_UNKNOWN', phase=phase,
                       error_type=type(error).__name__, candidate=_path_state(candidate),
                       target=_path_state(root_update), backup=_path_state(backup),
                       updater_invoked=False, installation_authorized=False,
                       automatic_retry=False, automatic_rollback=False)
        try:
            save(REPORT/'activation-stopped.json', stopped)
        except BaseException:
            pass
        raise


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('inspect','stage','activate'))
    parser.add_argument('--activation-authorized', action='store_true')
    parser.add_argument('--slot1-confirmed', action='store_true')
    args=parser.parse_args()
    if args.action=='inspect':
        value=discover();value.pop('volume_uuid');print(json.dumps(value))
    elif args.action=='stage':stage()
    else:activate_staged(activation_authorized=args.activation_authorized, slot1_confirmed=args.slot1_confirmed)
