"""Offline-only SD container refinement; no transport or installation entry."""
from pathlib import Path
import hashlib
import json
import shutil
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT/'ref/sony-a7m4-custom-firmware'))
from a7m4.fat import Fat
from a7m4.firmware import tar_index, update_sum, encode, decode
from a7m4.offline import resign, sha256
from cryptography.hazmat.primitives import serialization


def main():
    previous = ROOT/'output/fl23-sd-UNTESTED'
    receiver = ROOT/'output/fl23-updater-personal-version-02'
    out = ROOT/'output/fl23-sd-version-02-UNTESTED'
    out.mkdir(mode=0o700, exist_ok=False)
    (out/'work').mkdir()
    original = previous/'work/plain.bin'
    assert sha256(original) == '5832e5fb271535685c56627268101c10902d5bf830970c50ccd79704edbcc0de'
    assert sha256(previous/'BODYDATA.DAT') == 'ce9dc07d32cca95e672666f5afd991e3f1210e48d9a49dc123f2941073408521'
    candidate = receiver/'nflasha1.candidate.bin'
    manifest = json.loads((receiver/'manifest.json').read_text())
    assert sha256(candidate) == manifest['output_sha256']
    replacement = Fat(candidate.read_bytes()).read('boot/initrd.img')
    plain = out/'work/plain.bin'
    shutil.copyfile(original, plain)
    index = tar_index(plain)
    member = '0400_updater/dev/nflasha1'
    sums = '0401_updater_sum/updater.sum'
    changes = {}
    with plain.open('r+b') as f:
        def read(name):
            offset, size = index[name]
            f.seek(offset)
            b = f.read(size)
            assert len(b) == size
            return b
        def write(name, before, after):
            offset, size = index[name]
            assert len(before) == len(after) == size
            f.seek(offset)
            f.write(after)
            changes[name] = dict(offset=offset, bytes=size,
                                before_sha256=hashlib.sha256(before).hexdigest(),
                                after_sha256=hashlib.sha256(after).hexdigest())
        old = read(member)
        fs = Fat(old)
        old_initrd = fs.read('boot/initrd.img')
        assert old_initrd == Fat((ROOT/'output/fl23-updater-personal-01/nflasha1.candidate.bin').read_bytes()).read('boot/initrd.img')
        checksum = fs.read('p1chksum')
        md5 = hashlib.md5(old_initrd).hexdigest().encode()
        assert checksum.count(md5) == 1
        fs.replace('boot/initrd.img', replacement)
        fs.replace('p1chksum', checksum.replace(md5, hashlib.md5(replacement).hexdigest().encode()))
        new = fs.bytes()
        assert Fat(new).read('boot/vmlinux.bin') == Fat(old).read('boot/vmlinux.bin')
        def logical_files(volume):
            fat, found = Fat(volume), {}
            def walk(first=None, prefix=''):
                for name, (_, cluster, _, attr) in fat.entries(first).items():
                    if name in ('.', '..'):
                        continue
                    if attr & 16:
                        walk(cluster, prefix+name+'/')
                    else:
                        found[prefix+name] = fat.read(prefix+name)
            walk()
            return found
        old_files, new_files = logical_files(old), logical_files(new)
        assert old_files.keys() == new_files.keys()
        assert {n for n in old_files if old_files[n] != new_files[n]} == {'BOOT/INITRD.IMG', 'P1CHKSUM'}
        write(member, old, new)
        old_sum = read(sums)
        write(sums, old_sum, update_sum(old_sum, {'dev/nflasha1': (old, new)}))
    assert tar_index(plain) == index
    # Compare the entire plaintext outside the two declared member intervals.
    with original.open('rb') as a, plain.open('rb') as b:
        cursor = 0
        for row in sorted(changes.values(), key=lambda r:r['offset']):
            end = row['offset']
            while cursor < end:
                n = min(4<<20, end-cursor)
                assert a.read(n) == b.read(n)
                cursor += n
            cursor += row['bytes']
            a.seek(cursor)
            b.seek(cursor)
        while True:
            x, y = a.read(4<<20), b.read(4<<20)
            assert x == y
            if not x:
                break
    print(json.dumps({'stage':'plaintext_refined','only_changed_members':list(changes)}), flush=True)
    unsigned = out/'work/UNSIGNED_DO_NOT_INSTALL.DAT'
    encoded = encode(previous/'BODYDATA.DAT', plain, unsigned)
    key = ROOT/'ref/sony-a7m4-custom-firmware/keys/published/A7M4_updater_private.pem'
    k = serialization.load_pem_private_key(key.read_bytes(), None)
    fingerprint = hashlib.sha256(k.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()
    assert fingerprint == 'eed3fd52e3adc60ef13b584bc0b50345ee96639be81efa02e0031a6eccc65e76'
    signed = resign(unsigned, key, out/'BODYDATA.DAT')
    checked = decode(out/'BODYDATA.DAT', compare=plain)
    assert checked['blocks_verified'] == 739727 and checked['compared_byte_for_byte']
    report = dict(status='OFFLINE_ONLY_NOT_INSTALLABLE', camera_io=False,
        camera_tested=False, receiver_version_gate=1, target_updater_version_gate=1,
        source_DAT_sha256=sha256(previous/'BODYDATA.DAT'), source_plain_sha256=sha256(original),
        output_DAT_sha256=sha256(out/'BODYDATA.DAT'), plaintext_sha256=sha256(plain),
        changed_members=changes, other_plaintext_bytes_unchanged=True,
        package_model_region_kernel_unchanged=True, full_personal_partition_embedded=False,
        template_and_AP_CP_content_unchanged_from_previous_candidate=True,
        public_key_fingerprint=fingerprint, signing_identity='existing_published_research_key_not_Sony',
        encoding=encoded, signing=signed, final_decoding=checked,
        remaining=['NOR independent readback and recovery', 'Normal menu preflight',
                   'Live install and cold-boot feature acceptance'])
    (out/'verification.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'status':report['status'],'output_DAT_sha256':report['output_DAT_sha256'],
                      'blocks_verified':checked['blocks_verified'],'signature_verified':signed['signature_verified']}),flush=True)


if __name__ == '__main__':
    main()
