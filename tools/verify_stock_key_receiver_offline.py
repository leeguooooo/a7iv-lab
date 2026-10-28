"""Independently audit the saved-file stock-key P1 candidate. No camera I/O."""
import hashlib
import io
import json
from pathlib import Path
import struct
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "output/stock-key-preserving-receiver-01"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def check(condition, message):
    if not condition:
        raise ValueError(message)


def tar_inventory(path):
    result = {}
    with tarfile.open(path, "r:") as archive:
        for entry in archive:
            name = entry.name.removeprefix("./").rstrip("/")
            check(name not in result, "Duplicate tar entry")
            attributes = (entry.type, entry.mode, entry.uid, entry.gid, entry.mtime,
                          entry.linkname, entry.size, entry.devmajor, entry.devminor,
                          entry.uname, entry.gname, entry.pax_headers)
            payload = archive.extractfile(entry).read() if entry.isfile() else None
            result[name] = (attributes, sha(payload) if payload is not None else None)
    return result


def main():
    manifest = json.loads((OUT / "manifest.json").read_text())
    old = (ROOT / manifest["source"]).read_bytes()
    new = (OUT / manifest["candidate"]).read_bytes()
    inverse = (OUT / manifest["inverse"]).read_bytes()
    check(sha(old) == manifest["source_sha256"] == sha(inverse), "Source/inverse hash differs")
    check(sha(new) == manifest["candidate_sha256"] and len(old) == len(new) == 25100288,
          "Candidate differs")
    check(sha((ROOT / "tools/build_stock_key_receiver_offline.py").read_bytes()) == manifest["builder_sha256"],
          "Builder source differs from build record")
    sys.path.insert(0, str(ROOT / "ref/sony-a7m4-custom-firmware"))
    from a7m4.fat import Fat
    before, after = Fat(old), Fat(new)
    source_initrd, candidate_initrd = before.read("boot/initrd.img"), after.read("boot/initrd.img")
    check((OUT / "source.img").read_bytes() == source_initrd and
          (OUT / "candidate.img").read_bytes() == candidate_initrd, "SquashFS artifacts not bound to full P1")
    expected = bytearray(old)
    def put_existing(path, value):
        entry, first, _, _ = before.locate(path)
        chain = before.chain(first)
        check(len(value) <= len(chain) * before.cluster_size, "Replacement exceeds original allocation")
        at = 0
        for cluster in chain:
            count = min(before.cluster_size, len(value) - at)
            if count <= 0:
                break
            physical = before.offset(cluster)
            expected[physical:physical + count] = value[at:at + count]
            at += count
        struct.pack_into("<I", expected, entry + 28, len(value))
    put_existing("boot/initrd.img", candidate_initrd)
    checksum = (hashlib.md5(before.read("boot/vmlinux.bin")).hexdigest() + "  ./boot/vmlinux.bin\n" +
                hashlib.md5(candidate_initrd).hexdigest() + "  ./boot/initrd.img\n").encode()
    put_existing("p1chksum", checksum)
    check(bytes(expected) == new, "Unexpected P1 byte outside independently reconstructed changes")
    check(new[before.total:] == old[before.total:] and new[:before.root_start] == old[:before.root_start],
          "FAT allocation/header or tail changed")
    check(after.read("p1chksum") == checksum, "Candidate updater checksum invalid")
    original_inventory, candidate_inventory = tar_inventory(OUT / "source.tar"), tar_inventory(OUT / "roundtrip.tar")
    check(original_inventory.keys() == candidate_inventory.keys(), "Filesystem paths changed")
    changed = []
    for name in original_inventory:
        a, b = original_inventory[name], candidate_inventory[name]
        check(a[0] == b[0], "Tar metadata/link/device attributes changed")
        if a[1] != b[1]:
            changed.append(name)
    allowed = {"usr/lib/libsdfileinputupdaterapi.so": [(44016, 8), (40916, 8)],
               "usr/lib/libupdatercorecommon.so": [(53768, 4), (53884, 4)]}
    check(set(changed) == set(allowed), "Unexpected file content changed")
    tool = "/opt/homebrew/bin/unsquashfs"
    def extract(image, member):
        return subprocess.run([tool, "-cat", str(OUT / image), member],
                              check=True, capture_output=True, timeout=30).stdout
    profile = json.loads((ROOT / manifest["profile"]).read_text())
    pub_before = extract("source.img", "etc/VerificationKey.pem")
    pub_after = extract("candidate.img", "etc/VerificationKey.pem")
    check(pub_before == pub_after and sha(pub_after) == profile["stock_public_key_sha256"], "Stock public key changed")
    lib_proofs = {}
    for name in [*("usr/lib/" + n for n in profile["libraries"]), "usr/lib/libupdatercorecommon.so"]:
        a, b = extract("source.img", name), extract("candidate.img", name)
        check(len(a) == len(b), "ELF length changed")
        differences = [i for i, (x, y) in enumerate(zip(a, b)) if x != y]
        permitted = {i for at, length in allowed.get(name, []) for i in range(at, at + length)}
        check(all(i in permitted for i in differences), "Library changed outside four reviewed sites")
        if name.removeprefix("usr/lib/") in profile["libraries"]:
            entry = profile["libraries"][name.removeprefix("usr/lib/")]
            check(a[entry["offset"]:entry["offset"] + 8] == b[entry["offset"]:entry["offset"] + 8]
                  == bytes.fromhex(entry["original_hex"]), "Original verifyKey entry changed")
        lib_proofs[name] = {"source_sha256": sha(a), "candidate_sha256": sha(b),
                            "actual_changed_bytes": len(differences), "all_changes_in_allowed_sites": True}
    report = {"all_passed": True, "candidate_sha256": sha(new), "source_sha256": sha(old),
              "independent_expected_full_image_matches": True, "exact_inverse_matches": inverse == old,
              "tar_entries_checked": len(original_inventory), "only_changed_members": changed,
              "all_member_metadata_preserved": True, "libraries": lib_proofs,
              "stock_public_key_bytes_unchanged": True, "fat_and_tail_unchanged": True,
              "source_squashfs_creation_time": struct.unpack_from("<I", source_initrd, 8)[0],
              "candidate_squashfs_creation_time": struct.unpack_from("<I", candidate_initrd, 8)[0],
              "creation_time_note": "Filesystem-level build time is recorded separately from per-file metadata",
              "verifier_sha256": sha(Path(__file__).read_bytes()), "hardware_operations": 0,
              "installable": False, "physical_restore_tested": False}
    with (OUT / "independent-root-audit.json").open("x") as f:
        (OUT / "independent-root-audit.json").chmod(0o600)
        json.dump(report, f, indent=2)
        f.write("\n")
    print(json.dumps({"all_passed": True, "candidate_sha256": sha(new), "tar_entries_checked": len(original_inventory),
                      "independent_full_image_reconstruction_matches": True, "hardware_operations": 0}))


if __name__ == "__main__":
    main()
