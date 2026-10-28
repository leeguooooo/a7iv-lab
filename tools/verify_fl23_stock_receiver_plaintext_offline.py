"""Independent header/tar/CRC audit and AP/CP extraction; never accesses a device."""
import hashlib
import io
import json
import os
from pathlib import Path
import struct
import sys
import tarfile
import zlib

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'output/fl23-stock-receiver-plain-01'
PLAIN = OUT / 'plain.DO_NOT_INSTALL.bin'
sys.path.insert(0, str(ROOT / 'ref/sony-a7m4-custom-firmware'))
from a7m4.fat import Fat
from dissect.extfs import ExtFS


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    with PLAIN.open('rb') as f:
        digest = hashlib.file_digest(f, 'sha256').hexdigest()
        require(digest == 'ebc7f537c21b685609f646670ab8b381db15d7283d259cbb587a2c0a008a51bf', 'Plaintext changed')
        f.seek(0);h = f.read(512)
        require(h[:8] == b'UDTRFIRM' and struct.unpack_from('<I', h, 8)[0] == zlib.crc32(h[12:]), 'Bad header CRC')
        start, length = struct.unpack_from('<II', h, 48)
        require(start + length == PLAIN.stat().st_size, 'Unexpected plaintext geometry')
        f.seek(start);members = {}
        with tarfile.open(fileobj=f, mode='r|') as archive:
            for item in archive:
                name = item.name.removeprefix('./')
                require(not name.startswith('/') and '..' not in Path(name).parts, 'Unsafe archive path')
                if item.isfile():
                    require(name not in members and item.offset_data + item.size <= length, 'Bad tar bounds/duplicate')
                    members[name] = start + item.offset_data, item.size
        def read(name):
            at, size = members[name];f.seek(at);raw = f.read(size)
            require(len(raw) == size, 'Truncated archive member')
            return raw
        checked = {}
        for manifest, prefix in (('0701_part_image_sum/part_image.sum', '0700_part_image/'),
                                 ('0401_updater_sum/updater.sum', '0400_updater/'),
                                 ('0111_backup_sum/backup.sum', '0110_backup/')):
            found = []
            for line in read(manifest).decode('ascii').splitlines():
                fields = line.split(',')
                if fields[0] != '0':
                    continue
                name = prefix + fields[10]
                require(name not in found and name in members, 'Ambiguous checksum entry')
                at, size = members[name]
                require(size == int(fields[2], 16), 'Member length/checksum manifest mismatch')
                f.seek(at);left, crc = size, 0
                while left:
                    raw = f.read(min(left, 4 << 20));require(bool(raw), 'Truncated CRC input')
                    crc = zlib.crc32(raw, crc);left -= len(raw)
                require(crc == int(fields[1], 16), 'Member CRC mismatch')
                found.append(name)
            require(set(found) == {n for n in members if n.startswith(prefix)}, 'Incomplete manifest coverage')
            checked[manifest] = found
        backups = checked['0111_backup_sum/backup.sum']
        require(sum(n.endswith('.bin') for n in backups) == 32
                and any(n.endswith('/MainDest.txt') for n in backups), '32 templates/MainDest coverage missing')
        updater = read('0400_updater/dev/nflasha1')
        require(sha(updater) == '4e9f1ba88ad31abab3debc02a26593cdca1fb64e384f32780f96885ab23064aa', 'Updater component differs')
        initrd = Fat(updater).read('boot/initrd.img')
        require(sha(initrd) == '89d798faa7b57b9d06e04b6430635ff1c048d878d6f96fd498147aa5a822e203', 'Updater software differs')
        cp = Fat(read('0700_part_image/dev/nflasha8')).read('CPAPP-B.BIN')
        require(sha(cp) == '4551c73386c27a0a9b247fd3e05c3bd5e3425bdb9fe9f8374c201c96533b3479', 'CP is not public v7')
        ap = ExtFS(io.BytesIO(read('0700_part_image/dev/nflasha15'))).get('lib/appFw.so').open().read()
        require(len(ap) == 98212632 and sha(ap) == 'd17e61fb4ba193d8e7d802196edff5f578d5691b3fcc4abcd1cbbb6e58bdd8ff',
                'AP differs from public stock6.02 FL23 target')
        require(read('0700_part_image/dev/nflasha5')[:4] == b'WBI3', 'Expected upstream cold-boot marker')
    result = dict(all_passed=True, plaintext_sha256=digest, header_crc_verified=True,
        complete_member_CRC_coverage=checked, AP_sha256=sha(ap), CP_sha256=sha(cp),
        generic_updater_sha256=sha(updater), updater_initrd_sha256=sha(initrd),
        original_public_key_preserving_component=True, experimental_RAW_patch_included=False,
        full_DAT_built=False, signature_verified=False, camera_operations=0, hardware_acceptance=False,
        verifier_sha256=sha(Path(__file__).read_bytes()))
    with (OUT / 'independent-root-audit.json').open('x') as f:
        os.fchmod(f.fileno(), 0o600);json.dump(result, f, indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
    print(json.dumps({'all_passed': True, 'CRC_rows': sum(map(len, checked.values())),
                      'AP_sha256': sha(ap), 'CP_sha256': sha(cp), 'camera_operations': 0}))


if __name__ == '__main__':
    main()
