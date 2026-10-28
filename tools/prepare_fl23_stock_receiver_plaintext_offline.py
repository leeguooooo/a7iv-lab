"""Bind existing FL23 v7 plaintext to the physically verified updater software.

Local files only. Produces no DAT, no signature, no installer and no camera I/O.
Personal P1 FAT bytes are never embedded in the generic updater volume.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import sys
import tarfile
import zlib

ROOT = Path(__file__).resolve().parents[1]
REF = ROOT / 'ref/sony-a7m4-custom-firmware'
sys.path.insert(0, str(REF))
from a7m4.fat import Fat
from a7m4.firmware import tar_index, update_sum

BEFORE = ROOT / 'output/fl23-sd-version-02-UNTESTED/work/plain.bin'
GENERIC = ROOT / 'output/stock-key-preserving-package-updater-01/nflasha1.candidate.component.bin'
CAPTURE = ROOT / 'output/stock-p1-install-bundle-01/execution/readback/capture/cnflasha1.bin'
OUT = ROOT / 'output/fl23-stock-receiver-plain-01'
P1 = '0400_updater/dev/nflasha1'
SUM = '0401_updater_sum/updater.sum'


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def file_sha(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def independent_index(path):
    with path.open('rb') as f:
        h = f.read(512)
        require(h[:8] == b'UDTRFIRM' and struct.unpack_from('<I', h, 8)[0] == zlib.crc32(h[12:]),
                'Invalid plaintext header CRC')
        start, size = struct.unpack_from('<II', h, 48)
        require(start + size <= path.stat().st_size, 'Firmware tar exceeds plaintext')
        f.seek(start)
        result = {}
        with tarfile.open(fileobj=f, mode='r|') as archive:
            for m in archive:
                name = m.name.removeprefix('./')
                require(name not in result and m.offset_data + m.size <= size, 'Duplicate or out-of-bounds tar member')
                if m.isfile():
                    result[name] = start + m.offset_data, m.size
        return result


def main():
    os.umask(0o077)
    require(file_sha(REF / 'a7m4/firmware.py') ==
            '102546f152d429300f4dc98e416f070592618b7fd40ae73fa7790080ef0abc94', 'Codec source changed')
    require(file_sha(BEFORE) == '5ad260ef52203bc3d8c2aacbb5c8dac17341c0a882033491fb6034fcd2adb6f2',
            'Existing v7 plaintext changed')
    require(file_sha(GENERIC) == '4e9f1ba88ad31abab3debc02a26593cdca1fb64e384f32780f96885ab23064aa'
            and file_sha(CAPTURE) == 'e3ac140c49bd81b74799da9051b47a12ed201931380df87f7c35bc122345275e',
            'Generic component or actual P1 capture changed')
    replacement = GENERIC.read_bytes()
    require(Fat(replacement).read('boot/initrd.img') == Fat(CAPTURE.read_bytes()).read('boot/initrd.img'),
            'Package updater software differs from physically verified P1')
    index = tar_index(BEFORE)
    require(index == independent_index(BEFORE), 'Independent tar parser disagrees')
    require(index[P1] == (77116416, 19377152) and index[SUM] == (96494592, 145), 'Fixed member bounds changed')
    with BEFORE.open('rb') as f:
        def read(name):
            at, n = index[name];f.seek(at);data = f.read(n)
            require(len(data) == n, 'Short source member')
            return data
        old, sums = read(P1), read(SUM)
        cp = Fat(read('0700_part_image/dev/nflasha8')).read('CPAPP-B.BIN')
    require(sha(old) == '15d5c3af60fc008e34787b60d2e403d10df962438b7b1a76e70580cbe85413ae'
            and len(old) == len(replacement), 'Unexpected old generic updater volume')
    require(sha(cp) == '4551c73386c27a0a9b247fd3e05c3bd5e3425bdb9fe9f8374c201c96533b3479',
            'Expected public direct-stock v7 CP, without experimental RAW adaptation')
    new_sums = update_sum(sums, {'dev/nflasha1': (old, replacement)})
    OUT.mkdir(mode=0o700)
    plain = OUT / 'plain.DO_NOT_INSTALL.bin'
    with BEFORE.open('rb') as src, plain.open('xb') as dst:
        shutil.copyfileobj(src, dst, 4 << 20);dst.flush();os.fsync(dst.fileno())
    changes = []
    with plain.open('r+b') as f:
        for name, before, after in ((P1, old, replacement), (SUM, sums, new_sums)):
            at, n = index[name]
            require(len(before) == len(after) == n, 'Fixed member size changed')
            f.seek(at);require(f.read(n) == before, 'Copy preimage differs')
            f.seek(at);f.write(after)
            changes.append(dict(member=name, offset=at, bytes=n, before_sha256=sha(before), after_sha256=sha(after)))
        f.flush();os.fsync(f.fileno())
    require(tar_index(plain) == independent_index(plain) == index, 'Tar layout changed')
    compared = 0
    with BEFORE.open('rb') as a, plain.open('rb') as b:
        cursor = 0
        for r in sorted(changes, key=lambda v: v['offset']):
            while cursor < r['offset']:
                n = min(4 << 20, r['offset'] - cursor)
                x, y = a.read(n), b.read(n)
                require(len(x) == n and x == y, 'Unexpected change outside exact two members')
                cursor += n;compared += n
            cursor += r['bytes'];a.seek(cursor);b.seek(cursor)
        while True:
            x, y = a.read(4 << 20), b.read(4 << 20)
            require(x == y, 'Unexpected tail change')
            if not x:
                break
            compared += len(x)
    require(plain.stat().st_size == BEFORE.stat().st_size == 754521088, 'Plaintext size changed')
    result = dict(status='OFFLINE_PLAINTEXT_ONLY_NOT_INSTALLABLE', source_plaintext_sha256=file_sha(BEFORE),
        plaintext_sha256=file_sha(plain), plaintext_bytes=plain.stat().st_size, changed_members=changes,
        all_other_bytes_compared=compared, independent_tar_index_agreed=True,
        updater_software_matches_physically_read_P1=True, personal_FAT_prefix_transplanted=False,
        CP_sha256=sha(cp), AP_CP_and_32_templates_unchanged_from_bound_source=True,
        experimental_RAW_patch_included=False, full_DAT_built=False, private_signing_keys_accessed=False,
        camera_operations=0, hardware_acceptance=False, post_P1_cold_boot_confirmation='PENDING',
        builder_sha256=file_sha(Path(__file__)))
    with (OUT / 'manifest.json').open('x') as f:
        json.dump(result, f, indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
    print(json.dumps({k: result[k] for k in ('status', 'plaintext_sha256', 'plaintext_bytes',
                     'all_other_bytes_compared', 'updater_software_matches_physically_read_P1', 'camera_operations')}))


if __name__ == '__main__':
    main()
