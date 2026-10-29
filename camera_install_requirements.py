"""Read capacity requirements from the pinned FL23 package, never device values."""
import hashlib
import os
import re
import struct
import tarfile

from camera_package_audit import audit_candidate, regular_path, safe_name, PLAIN_SHA

TARGETS = (1, 3, 5, 7, 8, 15)
MOUNT_CONFIG = '0100_config/mount.conf'
MAX_CONFIG = 65536
NUMBER = re.compile(r'[0-9]+\Z')
DEVICE = re.compile(r'/dev/nflasha([1-9][0-9]*)\Z')


def require(value, message):
    if not value:
        raise ValueError(message)


def _identity(value):
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def parse_mount_requirements(raw):
    """Return configured sizes for the six image targets, not the full write scope."""
    require(type(raw) is bytes and 0 < len(raw) <= MAX_CONFIG, 'Bounded mount.conf bytes required')
    rows = {}
    for line in raw.decode('ascii').splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        parts = line.split()
        require(len(parts) == 5 and DEVICE.fullmatch(parts[0])
                and NUMBER.fullmatch(parts[3]) and NUMBER.fullmatch(parts[4]), 'Malformed mount.conf row')
        name = parts[0][5:]
        require(name not in rows, 'Duplicate mount.conf device')
        size, cluster = int(parts[3]), int(parts[4])
        require(size <= 0x7fffffffffffffff and cluster <= 0xffffffff, 'Mount geometry overflow')
        rows[name] = size
    required = {'nflasha' + str(n): rows.get('nflasha' + str(n)) for n in TARGETS}
    require(all(type(size) is int and size > 0 for size in required.values()), 'Missing positive image target capacity')
    return required


def read_requirements(plaintext):
    """Verify the actual package and bind its model, region and six capacities.

    P1 is included even though the updater may skip its image write. Capacity
    requirements do not describe settings, logs, external MCU or NOR writes.
    """
    path = regular_path(plaintext)
    audit = audit_candidate(path)
    with path.open('rb') as stream:
        before = os.fstat(stream.fileno())
        require((before.st_dev, before.st_ino) == (path.stat().st_dev, path.stat().st_ino),
                'Candidate pathname differs from opened file')
        header = stream.read(512)
        require(len(header) == 512, 'Complete candidate header required')
        start, length = struct.unpack_from('<II', header, 48)
        require(start + length == before.st_size, 'Candidate archive bounds changed')
        stream.seek(start)
        configurations, images = [], {}
        image_names = {('0400_updater/dev/nflasha1' if n == 1 else '0700_part_image/dev/nflasha' + str(n)):
                       'nflasha' + str(n) for n in TARGETS}
        with tarfile.open(fileobj=stream, mode='r|') as archive:
            for member in archive:
                name = safe_name(member.name)
                require(member.offset_data + member.size <= length, 'Candidate member outside archive')
                if name == MOUNT_CONFIG:
                    require(member.isfile() and 0 < member.size <= MAX_CONFIG, 'Bounded regular mount.conf required')
                    configurations.append(archive.extractfile(member).read())
                if name in image_names:
                    require(member.isfile() and name not in images and member.size > 0, 'Unique regular image required')
                    images[name] = member.size
        require(len(configurations) == 1 and set(images) == set(image_names), 'Unique configuration and six images required')
        sizes = parse_mount_requirements(configurations[0])
        require(all(images[name] <= sizes[key] for name, key in image_names.items()), 'Image exceeds configured partition size')
        stream.seek(0)
        require(hashlib.file_digest(stream, 'sha256').hexdigest() == PLAIN_SHA, 'Candidate changed during requirements read')
        after = path.stat()
        require(_identity(before) == _identity(after), 'Candidate identity changed')
        require(_identity(os.fstat(stream.fileno())) == _identity(before), 'Opened candidate changed during read')
    return dict(schema='camera-install-package-requirements/1', plaintext_sha256=audit['plaintext_sha256'],
        model_code=struct.unpack_from('<I', header, 36)[0], region=struct.unpack_from('<I', header, 40)[0],
        required_partition_sizes=sizes, image_payload_bytes={image_names[name]: size for name, size in images.items()},
        mount_config_sha256=hashlib.sha256(configurations[0]).hexdigest(),
        scope='SIX_IMAGE_TARGET_CAPACITIES_NOT_COMPLETE_WRITE_SCOPE',
        device_values_observed=False, write_admission=False, installation_authorized=False)
