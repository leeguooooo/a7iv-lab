"""Prepare a generic official-package updater component from saved local files.

Reuse only independently bound software initrd bytes. Never transplant a
per-camera FAT volume; no DAT assembly, signing, device writer or USB exists.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tarfile
import zlib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools import build_stock_key_receiver_offline as helper

PLAINTEXT = ROOT / 'local/firmware/a7m4-6.02/plaintext.bin'
PLAINTEXT_SHA = '4fd810b8d20ea239e0df01aded90687baef1ca2c8df208a7f58c4989f85799c3'
MEMBER = '0400_updater/dev/nflasha1'
MEMBER_OFFSET = 77116416
MEMBER_LENGTH = 19377152
MEMBER_SHA = '696992b67a8a962b9d5f1a5cf17108b1a5fb4e77d1389a359e7e73ac88c6a103'
SOFTWARE = ROOT / 'output/stock-key-preserving-receiver-01'
ORIGINAL_INITRD_SHA = '2aea454ee676c2019ea44026cb15421756ef0631ef45ce5311d168c0f8b318e5'
CANDIDATE_INITRD_SHA = '89d798faa7b57b9d06e04b6430635ff1c048d878d6f96fd498147aa5a822e203'
RECEIVER_BUILDER_SHA = 'bfa036de163cc05c49f29cfe1854069925752b91f1558cec6edcf9ab3a959ffc'
OUT = ROOT / 'output/stock-key-preserving-package-updater-01'
require, sha, file_sha, write, save = helper.require, helper.sha, helper.file_sha, helper.write, helper.save


def build():
    os.umask(0o077)
    require(not OUT.exists(), 'Choose a fresh fixed output directory')
    source_stat = PLAINTEXT.lstat()
    require(stat.S_ISREG(source_stat.st_mode) and not PLAINTEXT.is_symlink()
            and source_stat.st_size == 754521088, 'Expected saved official plaintext regular file')
    require(file_sha(PLAINTEXT) == PLAINTEXT_SHA, 'Official plaintext changed')
    require(file_sha(Path(helper.__file__)) == RECEIVER_BUILDER_SHA, 'Software builder source changed')
    require(file_sha(helper.PROFILE) == helper.PROFILE_SHA
            and file_sha(helper.UPSTREAM / 'a7m4/fat.py') == helper.FAT_SHA, 'Profile/FAT reader changed')
    require(subprocess.check_output(['git', '-C', str(helper.UPSTREAM), 'rev-parse', 'HEAD'], text=True).strip()
            == helper.COMMIT, 'Reference revision changed')
    require(not subprocess.check_output(['git', '-C', str(helper.UPSTREAM), 'status', '--porcelain']),
            'Reference checkout changed')
    original_software = (SOFTWARE / 'source.img').read_bytes()
    rebuilt = (SOFTWARE / 'candidate.img').read_bytes()
    require(sha(original_software) == ORIGINAL_INITRD_SHA and sha(rebuilt) == CANDIDATE_INITRD_SHA,
            'Pinned software images changed')
    receiver_manifest_sha = file_sha(SOFTWARE / 'manifest.json')
    receiver = json.loads((SOFTWARE / 'manifest.json').read_text())
    require(receiver['status'] == 'OFFLINE_CANDIDATE_NOT_WRITTEN'
            and receiver['builder_sha256'] == RECEIVER_BUILDER_SHA
            and receiver['source_initrd_sha256'] == ORIGINAL_INITRD_SHA
            and receiver['candidate_initrd_sha256'] == CANDIDATE_INITRD_SHA
            and receiver['stock_public_key_bytes_unchanged'] is True
            and receiver['all_four_original_verifyKey_entries_unchanged'] is True,
            'Software provenance differs from reviewed receiver component')
    # Read the exact generic member, not any prefix of a per-camera partition.
    with PLAINTEXT.open('rb') as source:
        header = source.read(512)
        require(len(header) == 512 and header[:8] == b'UDTRFIRM', 'Wrong plaintext framing')
        require(struct.unpack_from('<I', header, 8)[0] == zlib.crc32(header[12:]), 'Plaintext header CRC differs')
        firmware_offset, firmware_length, count = struct.unpack_from('<III', header, 48)
        require((firmware_offset, firmware_length) == (1253888, 753267200)
                and firmware_offset + firmware_length <= source_stat.st_size and count <= 28,
                'Unexpected firmware tar bounds')
        for index in range(count):
            _, offset, length, _ = struct.unpack_from('<4sIII', header, 64 + 16 * index)
            require(offset + length <= source_stat.st_size, 'Declared component outside plaintext')
        source.seek(firmware_offset)
        matches, raw = [], None
        with tarfile.open(fileobj=source, mode='r|') as archive:
            names = set()
            for member in archive:
                name = member.name.removeprefix('./')
                require(name not in names and not Path(name).is_absolute() and '..' not in Path(name).parts,
                        'Duplicate or unsafe official tar path')
                names.add(name)
                require(member.offset_data + member.size <= firmware_length, 'Tar member outside firmware bounds')
                if name == MEMBER:
                    require(member.isreg() and firmware_offset + member.offset_data == MEMBER_OFFSET
                            and member.size == MEMBER_LENGTH, 'Official member offset/type/length differs')
                    matches.append(name)
                    raw = archive.extractfile(member).read()
        require(len(matches) == 1 and raw is not None, 'Official updater member must occur exactly once')
    require(len(raw) == MEMBER_LENGTH and sha(raw) == MEMBER_SHA, 'Official updater volume differs')
    sys.path.insert(0, str(helper.UPSTREAM))
    from a7m4.fat import Fat
    fs = Fat(raw)
    require(fs.total == len(raw) == MEMBER_LENGTH, 'Expected standalone generic official FAT volume')
    initrd, kernel, sums = fs.read('boot/initrd.img'), fs.read('boot/vmlinux.bin'), fs.read('p1chksum')
    require(initrd == original_software, 'Official and receiver original software initrds differ; reuse forbidden')
    expected_sums = (hashlib.md5(kernel).hexdigest() + '  ./boot/vmlinux.bin\n' +
                     hashlib.md5(initrd).hexdigest() + '  ./boot/initrd.img\n').encode()
    require(sums == expected_sums, 'Original official P1CHKSUM differs')
    source_header, candidate_header = helper.squash_header(initrd), helper.squash_header(rebuilt)
    before = helper.fat_inventory(fs)
    official_dat_files = {name: row['sha256'] for name, row in before.items()
                          if name.rsplit('/', 1)[-1].startswith('DAT') and 'sha256' in row}
    entry, first, _, _ = fs.locate('boot/initrd.img')
    capacity = len(fs.chain(first)) * fs.cluster_size
    require(len(rebuilt) <= capacity, 'Software initrd exceeds official existing allocation')
    OUT.mkdir(mode=0o700)
    write(OUT / 'original-initrd.img', initrd)
    write(OUT / 'candidate-initrd.img', rebuilt)
    # Independent parser checks both source and reused software; no host extraction.
    require(file_sha(helper.UNSQUASHFS) == helper.UNSQUASHFS_SHA, 'Independent unsquashfs changed')
    profile = json.loads(helper.PROFILE.read_text())
    extracted, library_checks = {}, {}
    for filename, modified in [('original-initrd.img', False), ('candidate-initrd.img', True)]:
        contents = {}
        for name in [helper.PUBLIC, *('usr/lib/' + n for n in profile['libraries']), helper.CORE]:
            contents[name] = subprocess.run([str(helper.UNSQUASHFS), '-cat', str(OUT / filename), name],
                check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30).stdout
        require(sha(contents[helper.PUBLIC]) == profile['stock_public_key_sha256'], 'Official public key differs')
        library_checks[filename] = helper.verify_libraries(contents, profile, modified)
        extracted[filename] = contents
    require(extracted['original-initrd.img'][helper.PUBLIC] == extracted['candidate-initrd.img'][helper.PUBLIC],
            'Official public key bytes changed')
    old_md5 = hashlib.md5(initrd).hexdigest().encode()
    require(sums.count(old_md5) == 1, 'Ambiguous official initrd checksum')
    new_sums = sums.replace(old_md5, hashlib.md5(rebuilt).hexdigest().encode())
    fs.replace('boot/initrd.img', rebuilt)
    fs.replace('p1chksum', new_sums)
    candidate = fs.bytes()
    require(len(candidate) == MEMBER_LENGTH, 'Generic volume length changed')
    after = helper.fat_inventory(Fat(candidate))
    require(before.keys() == after.keys(), 'Official FAT paths changed')
    for name, original in before.items():
        if name == 'BOOT/INITRD.IMG':
            expected = copy.deepcopy(original)
            expected.update(size=len(rebuilt), sha256=sha(rebuilt))
            directory_entry = bytearray.fromhex(original['entry_hex'])
            struct.pack_into('<I', directory_entry, 28, len(rebuilt))
            expected['entry_hex'] = directory_entry.hex()
            require(after[name] == expected, 'Official initrd allocation/metadata changed unexpectedly')
        elif name == 'P1CHKSUM':
            require(after[name] == original | {'sha256': sha(new_sums)}, 'Official checksum allocation/entry changed')
        else:
            require(after[name] == original, 'Unrelated official FAT file/entry changed')
    original_fs = Fat(raw)
    spans = [(entry + 28, 4, 'initrd_size_word')]
    for name in ('boot/initrd.img', 'p1chksum'):
        _, first, _, _ = original_fs.locate(name)
        for cluster in original_fs.chain(first):
            spans.append((original_fs.offset(cluster), fs.cluster_size, name + '_existing_cluster'))
    spans.sort()
    cursor, inverse, evidence = 0, bytearray(candidate), []
    for offset, length, purpose in spans:
        require(cursor <= offset and offset + length <= len(raw), 'Overlapping/out-of-bounds patch span')
        require(candidate[cursor:offset] == raw[cursor:offset], 'Change outside official permitted spans')
        inverse[offset:offset + length] = raw[offset:offset + length]
        evidence.append({'offset': offset, 'length': length, 'purpose': purpose,
                         'before_sha256': sha(raw[offset:offset + length]),
                         'after_sha256': sha(candidate[offset:offset + length])})
        cursor = offset + length
    require(candidate[cursor:] == raw[cursor:] and candidate[:fs.root_start] == raw[:fs.root_start],
            'Official allocation tables/unlisted bytes changed')
    require(bytes(inverse) == raw and sha(inverse) == MEMBER_SHA, 'Exact generic-volume inverse failed')
    write(OUT / 'nflasha1.original.component.bin', raw)
    write(OUT / 'nflasha1.candidate.component.bin', candidate)
    write(OUT / 'nflasha1.inverse.component.bin', inverse)
    require(file_sha(OUT / 'nflasha1.original.component.bin') == MEMBER_SHA
            == file_sha(OUT / 'nflasha1.inverse.component.bin')
            and file_sha(OUT / 'nflasha1.candidate.component.bin') == sha(candidate), 'Component readback differs')
    save(OUT / 'original-fat-inventory.json', before)
    save(OUT / 'candidate-fat-inventory.json', after)
    require(file_sha(PLAINTEXT) == PLAINTEXT_SHA
            and file_sha(SOFTWARE / 'source.img') == ORIGINAL_INITRD_SHA
            and file_sha(SOFTWARE / 'candidate.img') == CANDIDATE_INITRD_SHA
            and file_sha(SOFTWARE / 'manifest.json') == receiver_manifest_sha
            and file_sha(Path(helper.__file__)) == RECEIVER_BUILDER_SHA
            and file_sha(helper.PROFILE) == helper.PROFILE_SHA
            and file_sha(helper.UPSTREAM / 'a7m4/fat.py') == helper.FAT_SHA
            and file_sha(helper.UNSQUASHFS) == helper.UNSQUASHFS_SHA, 'Input/dependency changed during build')
    manifest = {'schema': 'camera-stock-package-updater-component-offline/1',
        'status': 'OFFLINE_COMPONENT_ONLY_NOT_FULL_DAT', 'source_plaintext': str(PLAINTEXT.relative_to(ROOT)),
        'source_plaintext_sha256': PLAINTEXT_SHA, 'official_tar_member': MEMBER,
        'official_tar_member_data_offset': MEMBER_OFFSET, 'official_tar_member_bytes': MEMBER_LENGTH,
        'firmware_tar_offset': firmware_offset, 'firmware_tar_bytes': firmware_length, 'plaintext_header_crc_valid': True,
        'source_component_sha256': MEMBER_SHA, 'candidate_component_sha256': sha(candidate),
        'exact_inverse_sha256': sha(inverse), 'original': 'nflasha1.original.component.bin',
        'candidate': 'nflasha1.candidate.component.bin', 'inverse': 'nflasha1.inverse.component.bin',
        'generic_package_role': 'component for 0400_updater/dev/nflasha1; generic official FAT/dat retained',
        'per_camera_receiver_role': 'separate full saved personal P1 candidate; never used as package FAT bytes',
        'personal_p1_candidate_opened': False, 'personal_fat_prefix_transplanted': False,
        'shared_software_initrd_provenance': {'receiver_bundle': str(SOFTWARE.relative_to(ROOT)),
            'receiver_manifest_sha256': receiver_manifest_sha, 'receiver_builder_sha256': RECEIVER_BUILDER_SHA,
            'original_source_img_sha256': ORIGINAL_INITRD_SHA, 'candidate_img_sha256': CANDIDATE_INITRD_SHA,
            'official_original_initrd_exactly_matches_receiver_source_img': True},
        'profile_sha256': helper.PROFILE_SHA, 'fat_reader_sha256': helper.FAT_SHA,
        'builder_sha256': file_sha(Path(__file__)), 'upstream_revision': helper.COMMIT,
        'independent_unsquashfs_sha256': helper.UNSQUASHFS_SHA,
        'source_squashfs': source_header, 'candidate_squashfs': candidate_header,
        'original_initrd_bytes': len(initrd), 'candidate_initrd_bytes': len(rebuilt), 'original_initrd_capacity': capacity,
        'original_libraries': library_checks['original-initrd.img'],
        'candidate_libraries': library_checks['candidate-initrd.img'],
        'stock_public_key_bytes_unchanged': True, 'all_four_original_verifyKey_entries_unchanged': True,
        'all_official_dat_files_preserved': True, 'official_dat_file_sha256': official_dat_files,
        'official_dat_file_presence_or_absence_preserved': True, 'personal_dat_files_introduced': False,
        'all_other_official_fat_files_entries_preserved': True, 'official_fat_tables_allocation_unchanged': True,
        'allowed_spans': evidence, 'outside_spans_unchanged': True, 'exact_local_inverse_verified': True,
        'inputs_unchanged_before_after': True, 'output_files_sha256': {p.name: file_sha(p) for p in OUT.iterdir() if p.is_file()},
        'required_before_future_full_DAT_assembly': ['enclosing updater.sum update', 'container checksums update',
                                                   'explicit signature handling and independent validation'],
        'full_DAT_built': False, 'signature_validity_verified': False, 'camera_io': False, 'hardware_operations': 0,
        'private_signing_keys_accessed': False, 'installable': False, 'physical_restore_tested': False,
        'current_camera_identity_verified': False, 'product_release_validated': False, 'device_writer_present': False}
    save(OUT / 'manifest.json', manifest)
    require(all(stat.S_IMODE(p.stat().st_mode) == (0o700 if p.is_dir() else 0o600)
                for p in [OUT, *OUT.rglob('*')]), 'Output permissions differ')
    return manifest


def main():
    try:
        result = build()
        print(json.dumps({k: result[k] for k in ('status','source_component_sha256','candidate_component_sha256',
              'exact_inverse_sha256','candidate_initrd_bytes','original_initrd_capacity','hardware_operations')}))
    except BaseException as error:
        if OUT.is_dir() and not (OUT / 'manifest.json').exists() and not (OUT / 'failure.json').exists():
            save(OUT / 'failure.json', {'status': 'OFFLINE_COMPONENT_BUILD_FAILED', 'error_type': type(error).__name__,
                                      'reason': str(error) if isinstance(error, ValueError) else 'external operation failed',
                                      'camera_io': False})
        print(json.dumps({'status': 'OFFLINE_COMPONENT_BUILD_FAILED', 'error_type': type(error).__name__, 'camera_io': False}))
        raise SystemExit(1)


if __name__ == '__main__':
    main()
