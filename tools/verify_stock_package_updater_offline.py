"""Independent raw-volume reconstruction from saved official bytes; no device I/O."""
import hashlib
import json
import os
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'output/stock-key-preserving-package-updater-01'
sys.path.insert(0, str(ROOT / 'ref/sony-a7m4-custom-firmware'))
from a7m4.fat import Fat


def sha(data):
    return hashlib.sha256(data).hexdigest()


def require(ok, message):
    if not ok:
        raise ValueError(message)


def main():
    old = (OUT / 'nflasha1.original.component.bin').read_bytes()
    new = (OUT / 'nflasha1.candidate.component.bin').read_bytes()
    require(len(old) == len(new) == 19377152, 'Wrong generic component geometry')
    require(sha(old) == '696992b67a8a962b9d5f1a5cf17108b1a5fb4e77d1389a359e7e73ac88c6a103',
            'Official component hash differs')
    require(sha(new) == '4e9f1ba88ad31abab3debc02a26593cdca1fb64e384f32780f96885ab23064aa',
            'Candidate component hash differs')
    # Bind the entire source component directly to the saved official package.
    with (ROOT / 'local/firmware/a7m4-6.02/plaintext.bin').open('rb') as f:
        f.seek(77116416)
        require(f.read(19377152) == old, 'Source is not the official generic volume')
    require((OUT / 'nflasha1.inverse.component.bin').read_bytes() == old, 'Inverse differs')
    source, target = Fat(old), Fat(new)
    initrd = (ROOT / 'output/stock-key-preserving-receiver-01/candidate.img').read_bytes()
    require(sha(initrd) == '89d798faa7b57b9d06e04b6430635ff1c048d878d6f96fd498147aa5a822e203',
            'Shared software differs')
    require(sha(source.read('boot/initrd.img')) ==
            '2aea454ee676c2019ea44026cb15421756ef0631ef45ce5311d168c0f8b318e5',
            'Original software differs')
    sums = (hashlib.md5(source.read('boot/vmlinux.bin')).hexdigest() + '  ./boot/vmlinux.bin\n' +
            hashlib.md5(initrd).hexdigest() + '  ./boot/initrd.img\n').encode()
    expected = bytearray(old)
    for name, payload in (('boot/initrd.img', initrd), ('p1chksum', sums)):
        entry, first, _, _ = source.locate(name)
        chain = source.chain(first)
        require(len(payload) <= len(chain) * source.cluster_size, 'Allocation overflow')
        cursor = 0
        for cluster in chain:
            piece = payload[cursor:cursor + source.cluster_size]
            if not piece:
                break
            at = source.offset(cluster)
            expected[at:at + len(piece)] = piece
            cursor += len(piece)
        require(cursor == len(payload), 'Incomplete replacement')
        struct.pack_into('<I', expected, entry + 28, len(payload))
        require(target.read(name) == payload, 'Independent FAT read differs')
    require(bytes(expected) == new, 'Unexpected byte outside exact reconstructed changes')
    require(new[:source.root_start] == old[:source.root_start], 'Allocation tables changed')
    report = dict(all_passed=True, source_sha256=sha(old), candidate_sha256=sha(new),
                  official_source_bytes_checked=True, independent_expected_full_image_matches=True,
                  exact_inverse_matches=True, hardware_operations=0, full_DAT_built=False,
                  signature_validity_verified=False, physical_restore_tested=False,
                  verifier_sha256=sha(Path(__file__).read_bytes()))
    with (OUT / 'independent-root-audit.json').open('x') as f:
        os.fchmod(f.fileno(), 0o600)
        json.dump(report, f, indent=2)
        f.write('\n')
        f.flush()
        os.fsync(f.fileno())
    print(json.dumps(report))


if __name__ == '__main__':
    main()
