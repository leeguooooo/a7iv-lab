"""Offline-only refinement of this camera's existing research-key candidate.

No camera imports, handles, loaders, block devices or live writer are provided.
"""
import copy
import hashlib
import io
import json
from pathlib import Path
import struct
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'ref/sony-a7m4-custom-firmware'))
from a7m4.fat import Fat
from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X30


def sha(b):
    return hashlib.sha256(b).hexdigest()


def entries(path):
    result = {}
    with tarfile.open(path) as tf:
        for m in tf:
            name = m.name.removeprefix('./').rstrip('/')
            assert not name.startswith('/') and '..' not in name.split('/')
            assert name not in result
            data = tf.extractfile(m).read() if m.isfile() else None
            result[name] = (copy.copy(m), data)
    return result


def identity(rows):
    return {k: (m.mode, m.uid, m.gid, m.mtime, m.type, m.linkname,
                m.devmajor, m.devminor, m.pax_headers, sha(b) if b is not None else None)
            for k, (m, b) in rows.items()}


def mapped_symbol(raw, name, expected_va, expected_size):
    e = ELFFile(io.BytesIO(raw))
    matches = [s for s in e.get_section_by_name('.dynsym').iter_symbols()
               if s.name == name and s['st_shndx'] != 'SHN_UNDEF']
    assert len(matches) == 1
    s = matches[0]
    assert (s['st_value'], s['st_size']) == (expected_va, expected_size)
    segs = [p for p in e.iter_segments() if p['p_type'] == 'PT_LOAD'
            and p['p_flags'] & 1 and p['p_vaddr'] <= expected_va
            and expected_va + expected_size <= p['p_vaddr'] + p['p_filesz']]
    assert len(segs) == 1
    return segs[0]['p_offset'] + expected_va - segs[0]['p_vaddr']


def emulate_version(code, left, right):
    u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    u.mem_map(0x10000, 0x1000)
    u.mem_map(0x20000, 0x1000)
    u.mem_map(0x30000, 0x1000)
    u.mem_write(0x10000, code)
    b = bytearray(0x40)
    struct.pack_into('<II', b, 4, *left)
    struct.pack_into('<II', b, 0x1c, *right)
    u.mem_write(0x20000, bytes(b))
    u.reg_write(UC_ARM64_REG_X1, 0x20000)
    u.reg_write(UC_ARM64_REG_X30, 0x30000)
    reached = []
    def stop(uc, pc, size, data):
        if pc == 0x30000:
            reached.append(True)
            uc.emu_stop()
    u.hook_add(UC_HOOK_CODE, stop)
    u.emu_start(0x10000, 0, count=64)
    assert reached
    return u.reg_read(UC_ARM64_REG_X0)


def main():
    out = ROOT / 'output/fl23-updater-personal-version-02'
    out.mkdir(mode=0o700, exist_ok=False)
    source = ROOT / 'output/fl23-updater-personal-01/nflasha1.candidate.bin'
    raw = source.read_bytes()
    assert sha(raw) == '46710f524c2327d0a0851f442412c48163eb7d4127d2e31342a3a55c1172716d'
    fs = Fat(raw)
    initrd = fs.read('boot/initrd.img')
    (out / 'source.img').write_bytes(initrd)
    tools = ROOT / 'ref/squashfs-tools-ng-1.3.2'
    def unpack(name, dest):
        with dest.open('xb') as f:
            subprocess.run([str(tools / 'sqfs2tar'), str(out / name)],
                           stdout=f, stderr=subprocess.PIPE, check=True, timeout=90)
    unpack('source.img', out / 'source.tar')
    rows = entries(out / 'source.tar')
    sdname, ccname = 'usr/lib/libsdfileinputupdaterapi.so', 'usr/lib/libupdatercorecommon.so'
    sd, cc = rows[sdname][1], rows[ccname][1]
    assert sha(sd) == '0624862064e43495d6291637d2e193d4656145d069550c58a4ce184bb9f5e354'
    assert sha(cc) == 'b2b066b963a42d96556f811a773579eb16a0358de1b3a9206a1845c0df99bb74'
    voff = mapped_symbol(sd, '_ZN7Updater21SDUUDConditionChecker11isVersionOKERN10UpdaterAPI22firmware_information_tE', 0x9fd4, 48)
    coff = mapped_symbol(cc, '_ZN7Updater8RVchk4PI18chkFirmInfo_beforeEPN10UpdaterAPI22firmware_information_t11informationE', 0xd028, 604)
    assert voff == 0x9fd4 and coff == 0xd028
    assert sd[voff:voff+8].hex() == '220440b900008052'
    assert cc[0xd208:0xd20c].hex() == '13008012'
    assert cc[0xd27c:0xd280].hex() == 'f3c39f5a'
    cases = []
    for left, right, expected in [((6,2),(6,2),0), ((6,2),(6,3),1),
                                  ((6,2),(6,1),0), ((6,2),(7,0),1), ((6,2),(5,99),0)]:
        got = emulate_version(sd[voff:voff+48], left, right)
        assert got == expected
        cases.append(dict(fields_4_8=left, fields_1c_20=right, result=got))
    new_sd, new_cc = bytearray(sd), bytearray(cc)
    new_sd[voff:voff+8] = bytes.fromhex('20008052c0035fd6')
    new_cc[0xd208:0xd20c] = bytes.fromhex('13008052')
    new_cc[0xd27c:0xd280] = bytes.fromhex('13008052')
    assert sha(new_cc) == 'cfe23b709f1a4feba16642729f39c9bb5f4516caa188fa67a6d31d3c1d833425'
    for case in cases:
        assert emulate_version(bytes(new_sd[voff:voff+48]), case['fields_4_8'], case['fields_1c_20']) == 1
        assert emulate_version(bytes.fromhex('00008052c0035fd6'), case['fields_4_8'], case['fields_1c_20']) == 0
    changed = {sdname: bytes(new_sd), ccname: bytes(new_cc)}
    modified = {k: (m, changed.get(k, b)) for k, (m, b) in rows.items()}
    with tarfile.open(out / 'modified.tar', 'x', format=tarfile.PAX_FORMAT) as tf:
        for name, (m, b) in modified.items():
            item = copy.copy(m)
            if b is not None:
                item.size = len(b)
            tf.addfile(item, io.BytesIO(b) if b is not None else None)
    with (out / 'modified.tar').open('rb') as f:
        subprocess.run([str(tools / 'tar2sqfs'), '-c', 'gzip', '-b', '131072',
                        '--exportable', '-j', '1', str(out / 'candidate.img')],
                       stdin=f, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=90)
    unpack('candidate.img', out / 'roundtrip.tar')
    assert identity(entries(out / 'roundtrip.tar')) == identity(modified)
    rebuilt = (out / 'candidate.img').read_bytes()
    sums = fs.read('p1chksum')
    old_md5 = hashlib.md5(initrd).hexdigest().encode()
    assert sums.count(old_md5) == 1
    fs.replace('boot/initrd.img', rebuilt)
    fs.replace('p1chksum', sums.replace(old_md5, hashlib.md5(rebuilt).hexdigest().encode()))
    candidate = fs.bytes()
    assert len(candidate) == len(raw)
    reread = Fat(candidate)
    assert reread.read('boot/initrd.img') == rebuilt
    assert reread.read('boot/vmlinux.bin') == Fat(raw).read('boot/vmlinux.bin')
    # Constrain physical modifications to the old initrd allocation, its size,
    # and the checksum file's pre-existing chain; preserve FAT and all tail bytes.
    allowed = bytearray(len(raw))
    for path in ['boot/initrd.img', 'p1chksum']:
        ent, first, _, _ = Fat(raw).locate(path)
        allowed[ent+28:ent+32] = bytes([1])*4
        for c in Fat(raw).chain(first):
            pos = Fat(raw).offset(c)
            allowed[pos:pos+fs.cluster_size] = bytes([1])*fs.cluster_size
    assert all(a == b or allowed[i] for i, (a, b) in enumerate(zip(raw, candidate)))
    (out / 'nflasha1.candidate.bin').write_bytes(candidate)
    report = dict(camera_io=False, installable=False, live_writer=False,
        status='OFFLINE_ONLY_REQUIRES_INSTALL_AND_RECOVERY_REVIEW',
        source_sha256=sha(raw), output_sha256=sha(candidate), bytes=len(candidate),
        key_and_verifyKey_preserved=True, other_initrd_content_metadata_preserved=True,
        fat_and_kernel_and_partition_tail_preserved=True, original_version_cases=cases,
        version_return_one_cases=5, version_return_zero_rejection_cases=5,
        library_changes={k: dict(before_sha256=sha(rows[k][1]), after_sha256=sha(v)) for k,v in changed.items()},
        remaining=['Normal menu version preflight remains separate',
                   'Independent physical NOR backup missing', 'No live installation or cold boot acceptance'],
        native_evidence=['m4-version-gates-native.bundle.json','m4-core-version-native.bundle.json'])
    (out / 'manifest.json').write_text(json.dumps(report, indent=2)+'\n')
    assert sha(source.read_bytes()) == sha(raw)
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
