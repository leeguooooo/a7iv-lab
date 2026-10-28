"""Read-only checks of the actual plaintext tar; never extract or execute it.

CRC is corruption detection, not authenticity. The fixed candidate wrapper also
checks its complete SHA-256. No report from this module admits device writes.
"""
import csv
import hashlib
import io
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import tarfile
import zlib

PLAIN_SHA = 'ebc7f537c21b685609f646670ab8b381db15d7283d259cbb587a2c0a008a51bf'
PLAIN_BYTES = 754521088


def require(ok, message):
    if not ok:
        raise ValueError(message)


def regular_path(path):
    path = Path(path).absolute()
    require(all(not p.is_symlink() for p in (path, *path.parents)), 'Symlink input forbidden')
    require(stat.S_ISREG(path.stat().st_mode), 'Regular local input required')
    return path


def safe_name(name):
    require(isinstance(name, str) and name and '\x00' not in name and '\\' not in name,
            'Invalid archive name')
    while name.startswith('./'):
        name = name[2:]
    require(not name.startswith('/') and '..' not in PurePosixPath(name).parts,
            'Unsafe archive path')
    name = str(PurePosixPath(name))
    require(name != '.', 'Empty archive name')
    return name


def scan_plaintext(path):
    """Validate header, all CSV CRC rows and complete regular member coverage.

    This low-level parser accepts other packages for corruption tests. It does
    not assert they are the fixed FL23 candidate. No filesystem extraction.
    """
    path = regular_path(path)
    with path.open('rb') as f:
        initial = path.stat()
        digest = hashlib.file_digest(f, 'sha256').hexdigest()
        f.seek(0)
        header = f.read(512)
        require(len(header) == 512 and header[:8] == b'UDTRFIRM'
                and header[12:16] == b'0100', 'Invalid firmware header')
        require(struct.unpack_from('<I', header, 8)[0] == zlib.crc32(header[12:]), 'Header CRC mismatch')
        start, length = struct.unpack_from('<II', header, 48)
        require(start >= 512 and length > 0 and start + length == initial.st_size,
                'Invalid tar geometry')
        f.seek(start)
        index = {}
        with tarfile.open(fileobj=f, mode='r|') as archive:
            for item in archive:
                name = safe_name(item.name)
                require(name not in index, 'Duplicate tar name')
                require(item.isfile() or item.isdir() or item.issym(), 'Unsupported tar entry type')
                require(item.size >= 0 and item.offset_data + item.size <= length, 'Tar member outside bounds')
                index[name] = dict(offset=start+item.offset_data, size=item.size,
                                   type='0' if item.isfile() else '5' if item.isdir() else '2',
                                   linkname=item.linkname)

        def read(name, limit=1 << 20):
            row = index[name]
            require(row['type'] == '0' and row['size'] <= limit, 'Oversize or nonregular manifest')
            f.seek(row['offset'])
            raw = f.read(row['size'])
            require(len(raw) == row['size'], 'Truncated manifest')
            return raw

        tables, components = [], set()
        regular_rows, component_sums = 0, {}
        for name in sorted(index):
            match = re.fullmatch(r'(\d{4})_(.+)_sum/([^/]+)\.sum', name)
            if not match:
                continue
            prefix = f'{int(match[1])-1:04d}_{match[2]}/'
            require(prefix not in components, 'Duplicate component checksum table')
            components.add(prefix)
            covered, rows = set(), []
            for fields in csv.reader(io.StringIO(read(name).decode('ascii'))):
                require(len(fields) >= 11 and fields[0] in ('0', '2', '5'), 'Invalid checksum row')
                target = prefix + safe_name(fields[10])
                require(target in index and target not in covered, 'Missing or duplicate checksum target')
                covered.add(target)
                entry = index[target]
                require(entry['type'] == fields[0], 'Checksum target type mismatch')
                result = dict(member=target, type=entry['type'])
                if entry['type'] == '0':
                    require(entry['size'] == int(fields[2], 16), 'Checksum target length mismatch')
                    f.seek(entry['offset'])
                    left, crc, member_sha = entry['size'], 0, hashlib.sha256()
                    while left:
                        raw = f.read(min(left, 4 << 20))
                        require(bool(raw), 'Truncated CRC input')
                        left -= len(raw)
                        crc = zlib.crc32(raw, crc)
                        member_sha.update(raw)
                    require(crc == int(fields[1], 16), 'Checksum target CRC mismatch')
                    component_sums[target] = (fields[1], crc)
                    regular_rows += 1
                    result.update(bytes=entry['size'], crc32=f'{crc:08x}', sha256=member_sha.hexdigest())
                else:
                    # Type only; do not claim ownership/mode/link-target validation.
                    result['metadata_scope'] = 'tar_type_only'
                rows.append(result)
            all_regular = {n for n, e in index.items() if n.startswith(prefix) and e['type'] == '0'}
            require(all_regular == {n for n in covered if index[n]['type'] == '0'},
                    'Incomplete regular checksum coverage')
            tables.append(dict(manifest=name, component=prefix, rows=rows))
        require(tables and regular_rows > 0, 'No component checksum tables')
        unchecked = [n for n, row in index.items() if row['type'] == '0'
                     and not any(n.startswith(prefix) for prefix in components)
                     and not re.fullmatch(r'\d{4}_.+_sum/[^/]+\.sum', n)]
        require(not unchecked, 'Regular tar payload outside checksum components')
        final = path.stat()
        identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        require(identity(initial) == identity(final), 'Plaintext changed during audit')
    return dict(schema='camera-package-content-audit/1', plaintext_sha256=digest,
                plaintext_bytes=initial.st_size, table_count=len(tables), regular_CRC_rows=regular_rows,
                tables=tables, component_sums=component_sums, all_passed=True,
                camera_operations=0, installation_authorized=False,
                metadata_permissions_or_symlink_targets_verified=False)


def audit_candidate(path):
    report = scan_plaintext(path)
    require(report['plaintext_sha256'] == PLAIN_SHA and report['plaintext_bytes'] == PLAIN_BYTES,
            'Fixed FL23 plaintext differs')
    require(report['table_count'] == 10 and report['regular_CRC_rows'] == 115,
            'Fixed candidate checksum coverage differs')
    report['fixed_candidate_verified'] = True
    return report
