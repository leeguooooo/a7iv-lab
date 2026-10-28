"""Build a saved-file-only, stock-key-preserving P1 research candidate.

No USB, firmware-container builder, device writer, or product-release approval.
Only a fixed saved full P1 and the reviewed Boolean-true profile are admitted.
"""
import copy
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import struct
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
UPSTREAM = ROOT / 'ref/sony-a7m4-custom-firmware'
SOURCE = ROOT / 'output/backup-01/execution/cnflasha1.bin'
OUT = ROOT / 'output/stock-key-preserving-receiver-01'
PROFILE = UPSTREAM / 'no-fastboot-install/software/app/profiles/profile.json'
TOOLS = ROOT / 'local/squashfs-resources/local/squashfs'
TOOL_MANIFEST = ROOT / 'local/squashfs-resources/manifest.local.json'
UNSQUASHFS = Path('/opt/homebrew/bin/unsquashfs')
COMMIT = 'caa29145644e1d7d0a41cef1e42f0c53368bd025'
SOURCE_SHA = 'd415c4766c62b5b63bf106306e67b6a0512c4f97db834378e47ef79c40cf580b'
PROFILE_SHA = '7b911416eed478c7a19e537a3f9a84ba9918eb886186f0c6a25091bc897b375c'
FAT_SHA = '574d1aeee03f2b20fe2424591fe6caf25680610909a029b9da76fc4c608f873d'
TOOL_SHAS = {'sqfs2tar.exe': '8be864edc740ab7ee0ee497a2593062e38a5c809b299d50654703f6319b961fe',
             'tar2sqfs.exe': '33091f168c07316708b17efe68f0559ce5025a8dfee743180dcad00091254b0b'}
UNSQUASHFS_SHA = 'c08418f073892b1d6873d263588fd55ce12ebfc84993c573aeb538c6985c3ba3'
SD = 'usr/lib/libsdfileinputupdaterapi.so'
CORE = 'usr/lib/libupdatercorecommon.so'
PUBLIC = 'etc/VerificationKey.pem'
VERIFY_KEY = '_ZN7Updater21SignatureVerification9verifyKeyEPKc'
MODIFIED_SHAS = {SD: 'f6c68faca339cadff1c1bda5aca9971fb4fcf3af5ac5150ccb6e59f489b65c75',
                 CORE: 'cfe23b709f1a4feba16642729f39c9bb5f4516caa188fa67a6d31d3c1d833425'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def file_sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def write(path, data):
    with Path(path).open('xb') as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def save(path, value):
    write(path, (json.dumps(value, indent=2) + '\n').encode())


def run(args, **kwargs):
    return subprocess.run(args, check=True, stderr=subprocess.PIPE, timeout=120, **kwargs)


def squash_header(raw):
    require(len(raw) >= 96, 'Short SquashFS header')
    h = struct.unpack_from('<5I6H8Q', raw)
    require(h[0] == 0x73717368 and h[9:11] == (4, 0) and h[3] == 131072
            and h[5] == 1 and h[12] <= len(raw), 'Unreviewed SquashFS geometry')
    require(h[14] == 0xffffffffffffffff, 'Unreviewed xattrs cannot be discarded')
    return {'block_size': h[3], 'compression': 'gzip', 'major': h[9], 'minor': h[10],
            'bytes_used': h[12], 'xattrs_absent': True}


def canonical(name):
    name = name.removeprefix('./').rstrip('/')
    require(not PurePosixPath(name).is_absolute() and '..' not in PurePosixPath(name).parts,
            'Unsafe tar member name')
    return name


def entries(path):
    rows = {}
    with tarfile.open(path, 'r:') as stream:
        for member in stream:
            name = canonical(member.name)
            require(name not in rows, 'Duplicate tar path')
            require(member.isdir() or member.isreg() or member.issym() or member.islnk()
                    or member.ischr() or member.isblk() or member.isfifo(), 'Unreviewed tar inode')
            require(not any('xattr' in key.lower() for key in member.pax_headers), 'Unreviewed tar xattrs')
            if member.islnk():
                canonical(member.linkname)
            data = stream.extractfile(member).read() if member.isreg() else None
            require(data is None or len(data) == member.size, 'Short tar member')
            rows[name] = copy.deepcopy(member), data
    require(rows, 'Empty SquashFS inventory')
    return rows


def inventory(rows):
    return {name: {'mode': m.mode, 'uid': m.uid, 'gid': m.gid, 'mtime': m.mtime,
                   'type': m.type.decode('ascii'), 'linkname': m.linkname, 'size': m.size,
                   'devmajor': m.devmajor, 'devminor': m.devminor, 'uname': m.uname, 'gname': m.gname,
                   'pax_headers': m.pax_headers, 'sha256': sha(data) if data is not None else None}
            for name, (m, data) in rows.items()}


def mapped_symbol(data, symbol, va, entry=None, size=None):
    from elftools.elf.elffile import ELFFile
    elf = ELFFile(io.BytesIO(data))
    require(elf.elfclass == 64 and elf.little_endian and elf['e_machine'] == 'EM_AARCH64', 'Wrong library ABI')
    rows = [s for s in elf.get_section_by_name('.dynsym').iter_symbols()
            if s.name == symbol and s['st_shndx'] != 'SHN_UNDEF']
    require(len(rows) == 1 and rows[0]['st_value'] == va and (size is None or rows[0]['st_size'] == size),
            'Library symbol differs from profile')
    length = size or len(bytes.fromhex(entry))
    segments = [s for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD' and s['p_flags'] & 1
                and s['p_vaddr'] <= va and va + length <= s['p_vaddr'] + s['p_filesz']]
    require(len(segments) == 1, 'Symbol not in one executable segment')
    offset = segments[0]['p_offset'] + va - segments[0]['p_vaddr']
    require(offset == va, 'Reviewed VA/file-offset mapping changed')
    if entry is not None:
        require(data[offset:offset + len(bytes.fromhex(entry))].hex() == entry, 'Library entry differs')
    return offset


def verify_libraries(contents, profile, modified):
    evidence = {}
    for name, row in profile['libraries'].items():
        path = 'usr/lib/' + name
        data = contents[path]
        expected = MODIFIED_SHAS[path] if modified and path in MODIFIED_SHAS else row['original_sha256']
        require(sha(data) == expected, 'Unexpected whole updater library hash')
        offset = mapped_symbol(data, VERIFY_KEY, row['va'], row['original_hex'])
        require(offset == row['offset'], 'verifyKey offset changed')
        evidence[name] = {'sha256': sha(data), 'verifyKey_offset': offset, 'original_verifyKey_entry_matched': True}
    core = profile['chkfirm_version_gate']
    require(sha(contents[CORE]) == (MODIFIED_SHAS[CORE] if modified else core['original_sha256']),
            'Unexpected whole core library hash')
    mapped_symbol(contents[CORE], core['symbol'], core['va'], size=core['size'])
    for key, patch in [('sd_signature_gate', '00008052c0035fd6'), ('sd_version_gate', '20008052c0035fd6')]:
        row = profile[key]
        mapped_symbol(contents[SD], row['symbol'], row['va'], patch if modified else row['original_hex'], row['size'])
    for site in core['sites']:
        require(contents[CORE][site['offset']:site['offset'] + site['length']].hex()
                == (site['patched_hex'] if modified else site['original_hex']), 'Core gate differs')
    return evidence


def fat_inventory(fs):
    rows = {}
    def visit(first=None, prefix=''):
        for name, row in fs.entries(first).items():
            if name in ('.', '..'):
                continue
            entry, cluster, size, attr = row
            path = prefix + name
            rows[path] = {'entry_offset': entry, 'cluster': cluster, 'size': size, 'attr': attr,
                          'entry_hex': bytes(fs.data[entry:entry + 32]).hex(), 'chain': fs.chain(cluster)}
            if attr & 16:
                visit(cluster, path + '/')
            else:
                rows[path]['sha256'] = sha(fs.read(path))
    visit()
    return rows


def build():
    os.umask(0o077)
    require(not OUT.exists(), 'Choose a fresh fixed output directory')
    require(subprocess.check_output(['git', '-C', str(UPSTREAM), 'rev-parse', 'HEAD'], text=True).strip() == COMMIT,
            'Upstream revision changed')
    require(not subprocess.check_output(['git', '-C', str(UPSTREAM), 'status', '--porcelain']), 'Upstream checkout changed')
    require(file_sha(PROFILE) == PROFILE_SHA and file_sha(UPSTREAM / 'a7m4/fat.py') == FAT_SHA, 'Profile/FAT reader changed')
    st = SOURCE.lstat()
    require(stat.S_ISREG(st.st_mode) and not SOURCE.is_symlink() and st.st_size == 25100288, 'Expected saved full regular P1')
    raw = SOURCE.read_bytes()
    require(sha(raw) == SOURCE_SHA, 'Saved source differs')
    profile = json.loads(PROFILE.read_text())
    require(profile['sd_version_gate']['return_value'] == 1
            and profile['sd_version_gate']['stub_hex'] == '20008052c0035fd6', 'Boolean-true profile required')
    local_manifest = json.loads(TOOL_MANIFEST.read_text())
    tool_evidence = {}
    for name, digest in TOOL_SHAS.items():
        path = TOOLS / name
        require(file_sha(path) == digest == local_manifest['files']['squashfs/' + name]['sha256']
                and path.stat().st_size == local_manifest['files']['squashfs/' + name]['size'], 'Local tool provenance changed')
        kind = subprocess.check_output(['/usr/bin/file', '-b', str(path)], text=True).strip()
        require('Mach-O 64-bit executable arm64' in kind, 'Expected native Mac ARM64 tool')
        tool_evidence[name] = {'path': str(path.relative_to(ROOT)), 'sha256': digest, 'file_type': kind}
    require(file_sha(UNSQUASHFS) == UNSQUASHFS_SHA, 'Independent unsquashfs changed')
    sys.path.insert(0, str(UPSTREAM))
    from a7m4.fat import Fat
    fs = Fat(raw)
    require(fs.total == profile['fat_bytes'] == 19377152, 'Wrong FAT geometry')
    initrd, kernel, sums = fs.read('boot/initrd.img'), fs.read('boot/vmlinux.bin'), fs.read('p1chksum')
    expected_sums = (hashlib.md5(kernel).hexdigest() + '  ./boot/vmlinux.bin\n' +
                     hashlib.md5(initrd).hexdigest() + '  ./boot/initrd.img\n').encode()
    require(sums == expected_sums, 'Original P1CHKSUM differs')
    source_header = squash_header(initrd)
    OUT.mkdir(mode=0o700)
    write(OUT / 'source.img', initrd)

    def tar_image(image, output):
        with output.open('xb') as stream:
            os.fchmod(stream.fileno(), 0o600)
            run([str(TOOLS / 'sqfs2tar.exe'), '--no-skip', '--root-becomes', '.', str(image)], stdout=stream)

    tar_image(OUT / 'source.img', OUT / 'source.tar')
    rows = entries(OUT / 'source.tar')
    original_inventory = inventory(rows)
    contents = {name: data for name, (_, data) in rows.items() if data is not None}
    require(sha(contents[PUBLIC]) == profile['stock_public_key_sha256'], 'Official public key differs')
    original_library_checks = verify_libraries(contents, profile, False)
    signature, version, core = profile['sd_signature_gate'], profile['sd_version_gate'], profile['chkfirm_version_gate']
    # Preserve the reviewed callers and Boolean version vtable slot as well.
    caller = signature['caller']
    require(contents[SD][caller['va']:caller['va'] + 4].hex() == caller['call_hex']
            and contents[SD][caller['result_va']:caller['result_va'] + 4].hex() == caller['result_hex'], 'Signature caller differs')
    require(contents[SD][version['caller_va']:version['caller_va'] + len(bytes.fromhex(version['caller_hex']))].hex()
            == version['caller_hex'], 'Boolean version caller differs')
    patched_sd, patched_core = bytearray(contents[SD]), bytearray(contents[CORE])
    patched_sd[signature['offset']:signature['offset'] + 8] = bytes.fromhex('00008052c0035fd6')
    patched_sd[version['offset']:version['offset'] + 8] = bytes.fromhex('20008052c0035fd6')
    for site in core['sites']:
        patched_core[site['offset']:site['offset'] + site['length']] = bytes.fromhex('13008052')
    replacements = {SD: bytes(patched_sd), CORE: bytes(patched_core)}
    require({name: sha(value) for name, value in replacements.items()} == MODIFIED_SHAS, 'Patched whole-file hashes differ')
    modified = {name: (copy.deepcopy(member), replacements.get(name, data)) for name, (member, data) in rows.items()}
    with tarfile.open(OUT / 'modified.tar', 'x', format=tarfile.PAX_FORMAT) as stream:
        for name, (member, data) in modified.items():
            if name in replacements:
                require(member.isreg() and member.size == len(data), 'Patch target must retain regular-file geometry')
            stream.addfile(member, io.BytesIO(data) if data is not None else None)
    with (OUT / 'modified.tar').open('rb') as stream:
        run([str(TOOLS / 'tar2sqfs.exe'), '--no-skip', '--quiet', '-j', '1', '-c', 'gzip', '-b', '131072',
             '--exportable', str(OUT / 'candidate.img')], stdin=stream, stdout=subprocess.PIPE)
    (OUT / 'candidate.img').chmod(0o600)
    rebuilt = (OUT / 'candidate.img').read_bytes()
    target_header = squash_header(rebuilt)
    tar_image(OUT / 'candidate.img', OUT / 'roundtrip.tar')
    rebuilt_rows = entries(OUT / 'roundtrip.tar')
    require(inventory(rebuilt_rows) == inventory(modified), 'Complete roundtrip contents/metadata/links/devices differ')
    rebuilt_contents = {name: data for name, (_, data) in rebuilt_rows.items() if data is not None}
    require(rebuilt_contents == contents | replacements, 'Unexpected changed initrd content')
    require(rebuilt_contents[PUBLIC] == contents[PUBLIC], 'Official public key bytes changed')
    target_library_checks = verify_libraries(rebuilt_contents, profile, True)
    independent = {}
    for image, expected, is_modified in [('source.img', contents, False), ('candidate.img', rebuilt_contents, True)]:
        checked = {}
        for name in [PUBLIC, *('usr/lib/' + n for n in profile['libraries']), CORE]:
            data = run([str(UNSQUASHFS), '-cat', str(OUT / image), name], stdout=subprocess.PIPE).stdout
            require(data == expected[name], 'Independent unsquashfs content differs')
            checked[name] = data
        verify_libraries(checked, profile, is_modified)
        require(sha(checked[PUBLIC]) == profile['stock_public_key_sha256'], 'Independent public key hash differs')
        independent[image] = {name: sha(data) for name, data in checked.items()}
    before_fat = fat_inventory(fs)
    initrd_entry, first, _, _ = fs.locate('boot/initrd.img')
    allocated = len(fs.chain(first)) * fs.cluster_size
    require(len(rebuilt) <= allocated, 'Rebuilt initrd exceeds original allocation')
    old_md5 = hashlib.md5(initrd).hexdigest().encode()
    require(sums.count(old_md5) == 1, 'Ambiguous initrd checksum')
    new_sums = sums.replace(old_md5, hashlib.md5(rebuilt).hexdigest().encode())
    fs.replace('boot/initrd.img', rebuilt)
    fs.replace('p1chksum', new_sums)
    candidate = fs.bytes()
    require(len(candidate) == len(raw), 'Partition length changed')
    other = Fat(candidate)
    after_fat = fat_inventory(other)
    require(before_fat.keys() == after_fat.keys(), 'FAT directory paths changed')
    for name, before in before_fat.items():
        after = after_fat[name]
        if name == 'BOOT/INITRD.IMG':
            expected = copy.deepcopy(before)
            expected.update(size=len(rebuilt), sha256=sha(rebuilt))
            entry = bytearray.fromhex(expected['entry_hex'])
            struct.pack_into('<I', entry, 28, len(rebuilt))
            expected['entry_hex'] = entry.hex()
            require(after == expected, 'Initrd FAT entry/allocation changed unexpectedly')
        elif name == 'P1CHKSUM':
            require(after == before | {'sha256': sha(new_sums)}, 'Checksum FAT entry/allocation changed')
        else:
            require(after == before, 'Unrelated FAT entry/content changed')
    spans = []
    original_fs = Fat(raw)
    for name in ('boot/initrd.img', 'p1chksum'):
        entry, first, _, _ = original_fs.locate(name)
        if name == 'boot/initrd.img':
            spans.append((entry + 28, 4, 'initrd_size'))
        for cluster in original_fs.chain(first):
            spans.append((original_fs.offset(cluster), fs.cluster_size, name + '_existing_cluster'))
    spans.sort()
    cursor, inverse = 0, bytearray(candidate)
    span_report = []
    for offset, length, purpose in spans:
        require(offset >= cursor and candidate[cursor:offset] == raw[cursor:offset], 'Change outside allowed allocation')
        inverse[offset:offset + length] = raw[offset:offset + length]
        span_report.append({'offset': offset, 'length': length, 'purpose': purpose,
                            'before_sha256': sha(raw[offset:offset + length]),
                            'after_sha256': sha(candidate[offset:offset + length])})
        cursor = offset + length
    require(candidate[cursor:] == raw[cursor:] and candidate[fs.total:] == raw[fs.total:], 'Unlisted bytes/tail changed')
    require(candidate[:fs.root_start] == raw[:fs.root_start], 'FAT headers or allocation tables changed')
    require(bytes(inverse) == raw and sha(inverse) == SOURCE_SHA, 'Exact local inverse failed')
    write(OUT / 'p1_original.bin', raw)
    write(OUT / 'p1_candidate.bin', candidate)
    write(OUT / 'p1_inverse.bin', inverse)
    require(file_sha(OUT / 'p1_original.bin') == file_sha(OUT / 'p1_inverse.bin') == SOURCE_SHA
            and file_sha(OUT / 'p1_candidate.bin') == sha(candidate), 'Written candidate/rollback readback failed')
    require(file_sha(SOURCE) == SOURCE_SHA and file_sha(PROFILE) == PROFILE_SHA
            and all(file_sha(TOOLS / n) == d for n, d in TOOL_SHAS.items())
            and file_sha(UNSQUASHFS) == UNSQUASHFS_SHA, 'Source/dependency changed during construction')
    save(OUT / 'source-inventory.json', original_inventory)
    save(OUT / 'candidate-inventory.json', inventory(rebuilt_rows))
    manifest = {'schema': 'camera-stock-key-preserving-receiver-offline/1',
        'status': 'OFFLINE_CANDIDATE_NOT_WRITTEN', 'source': str(SOURCE.relative_to(ROOT)),
        'source_sha256': SOURCE_SHA, 'candidate_sha256': sha(candidate), 'bytes': len(candidate),
        'original': 'p1_original.bin', 'candidate': 'p1_candidate.bin', 'inverse': 'p1_inverse.bin',
        'profile': str(PROFILE.relative_to(ROOT)), 'profile_sha256': PROFILE_SHA,
        'builder_sha256': file_sha(Path(__file__)), 'fat_reader_sha256': FAT_SHA, 'upstream_revision': COMMIT,
        'tool_manifest_sha256': file_sha(TOOL_MANIFEST), 'local_tools': tool_evidence,
        'independent_unsquashfs_sha256': UNSQUASHFS_SHA,
        'source_initrd_sha256': sha(initrd), 'candidate_initrd_sha256': sha(rebuilt),
        'source_initrd_bytes': len(initrd), 'candidate_initrd_bytes': len(rebuilt), 'original_initrd_capacity': allocated,
        'source_squashfs': source_header, 'candidate_squashfs': target_header,
        'tar_sha256': {n: file_sha(OUT / n) for n in ('source.tar', 'modified.tar', 'roundtrip.tar')},
        'inventory_sha256': {n: file_sha(OUT / n) for n in ('source-inventory.json', 'candidate-inventory.json')},
        'only_changed_initrd_members': sorted(replacements), 'source_libraries': original_library_checks,
        'candidate_libraries': target_library_checks, 'modified_library_sha256': MODIFIED_SHAS,
        'stock_public_key_sha256': profile['stock_public_key_sha256'], 'stock_public_key_bytes_unchanged': True,
        'all_four_original_verifyKey_entries_unchanged': True, 'independent_extraction_sha256': independent,
        'complete_tar_metadata_links_devices_preserved': True, 'xattrs_absent': True,
        'fat_tables_and_chains_unchanged': True, 'all_other_fat_entries_and_contents_unchanged': True,
        'partition_tail_bytes': len(raw) - fs.total, 'partition_tail_sha256': sha(raw[fs.total:]),
        'partition_tail_unchanged': True, 'allowed_spans': span_report,
        'exact_local_inverse_sha256': sha(inverse), 'exact_local_inverse_matches_saved_source': True,
        'source_unchanged_before_after': True, 'camera_io': False, 'hardware_operations': 0,
        'installable': False, 'current_body_verified': False, 'physical_restore_tested': False,
        'full_packaged_product_validation': False, 'private_signing_keys_accessed': False,
        'firmware_container_built': False, 'device_writer_present': False}
    save(OUT / 'manifest.json', manifest)
    require(all(stat.S_IMODE(p.stat().st_mode) == (0o700 if p.is_dir() else 0o600) for p in [OUT, *OUT.rglob('*')]),
            'Output permissions differ')
    return manifest


def main():
    try:
        result = build()
        print(json.dumps({k: result[k] for k in ('status', 'source_sha256', 'candidate_sha256',
            'candidate_initrd_bytes', 'stock_public_key_bytes_unchanged', 'all_four_original_verifyKey_entries_unchanged',
            'exact_local_inverse_matches_saved_source', 'hardware_operations')}))
    except BaseException as error:
        if OUT.is_dir() and not (OUT / 'manifest.json').exists() and not (OUT / 'failure.json').exists():
            save(OUT / 'failure.json', {'status': 'OFFLINE_BUILD_FAILED', 'error_type': type(error).__name__,
                                      'camera_io': False, 'hardware_operations': 0})
        print(json.dumps({'status': 'OFFLINE_BUILD_FAILED', 'error_type': type(error).__name__, 'camera_io': False}))
        raise SystemExit(1)


if __name__ == '__main__':
    main()
