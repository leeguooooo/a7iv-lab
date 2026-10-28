"""Read-only audit of the already captured full p1; never opens a camera.

Uses the upstream pure-Python FAT reader and the locally installed unsquashfs.
The unpackaged GUI adapter lacks release.json/runtime dependencies, so this does
not impersonate its product integrity approval or disable any of its checks.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import stat
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
UPSTREAM = ROOT / "ref/sony-a7m4-custom-firmware"
COMMIT = "caa29145644e1d7d0a41cef1e42f0c53368bd025"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, text):
    if not condition:
        raise ValueError(text)


def symbol_check(data, symbol, va, entry, expected_size=None):
    from elftools.elf.elffile import ELFFile
    elf = ELFFile(io.BytesIO(data))
    require(elf.elfclass == 64 and elf.little_endian and elf["e_machine"] == "EM_AARCH64", "Wrong ELF ABI")
    symbols = [s for s in elf.get_section_by_name(".dynsym").iter_symbols()
               if s.name == symbol and s["st_shndx"] != "SHN_UNDEF"]
    require(len(symbols) == 1 and symbols[0]["st_value"] == va, "Symbol differs from profile")
    if expected_size is not None:
        require(symbols[0]["st_size"] == expected_size, "Symbol size differs")
    length = len(bytes.fromhex(entry))
    segments = [s for s in elf.iter_segments() if s["p_type"] == "PT_LOAD" and s["p_flags"] & 1
                and s["p_vaddr"] <= va and va + length <= s["p_vaddr"] + s["p_filesz"]]
    require(len(segments) == 1, "Function not mapped in one executable segment")
    offset = segments[0]["p_offset"] + va - segments[0]["p_vaddr"]
    require(data[offset:offset + length].hex() == entry, "Original entry differs")
    return {"symbol": symbol, "va": va, "offset": offset, "original_entry_matched": True}


def audit():
    require(subprocess.check_output(["git", "-C", str(UPSTREAM), "rev-parse", "HEAD"],
                                    text=True).strip() == COMMIT, "Upstream changed")
    require(not subprocess.check_output(["git", "-C", str(UPSTREAM), "status", "--porcelain"]),
            "Upstream checkout dirty")
    sys.path.insert(0, str(UPSTREAM))
    from a7m4.fat import Fat
    source = ROOT / "output/backup-01/execution/cnflasha1.bin"
    st = source.stat()
    require(stat.S_ISREG(st.st_mode) and st.st_size == 25100288, "Only captured full regular p1 file admitted")
    raw = source.read_bytes()
    profile_path = UPSTREAM / "no-fastboot-install/software/app/profiles/profile.json"
    profile = json.loads(profile_path.read_text())
    fs = Fat(raw)
    require(fs.total == profile["fat_bytes"] == 19377152, "FAT capacity differs")
    initrd, kernel = fs.read("boot/initrd.img"), fs.read("boot/vmlinux.bin")
    checksum = (hashlib.md5(kernel).hexdigest() + "  ./boot/vmlinux.bin\n" +
                hashlib.md5(initrd).hexdigest() + "  ./boot/initrd.img\n").encode("ascii")
    require(fs.read("p1chksum") == checksum, "Updater checksum invalid")
    tool = Path("/opt/homebrew/bin/unsquashfs")
    require(tool.is_file(), "Local unsquashfs required")
    with tempfile.TemporaryDirectory(prefix="camera_p1_profile_", dir=ROOT / "output") as temporary:
        image = Path(temporary) / "initrd.img"
        image.write_bytes(initrd)
        image.chmod(0o600)

        def member(name):
            return subprocess.run([str(tool), "-cat", str(image), name], check=True,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30).stdout

        public = member("etc/VerificationKey.pem")
        require(sha(public) == profile["stock_public_key_sha256"], "Public key differs from stock profile")
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        key = serialization.load_pem_public_key(public)
        require(isinstance(key, rsa.RSAPublicKey) and key.key_size == 2048
                and key.public_numbers().e == 65537, "Unexpected public key format")
        libraries, saved = {}, {}
        for name, entry in profile["libraries"].items():
            data = member("usr/lib/" + name)
            require(sha(data) == entry["original_sha256"], "Updater library not in stock profile")
            check = symbol_check(data, "_ZN7Updater21SignatureVerification9verifyKeyEPKc",
                                 entry["va"], entry["original_hex"])
            libraries[name] = {"sha256": sha(data), "stock_full_file_hash_matched": True, **check}
            saved[name] = data
        gates = {}
        for name in ("sd_signature_gate", "sd_version_gate"):
            entry = profile[name]
            gates[name] = symbol_check(saved[entry["library"]], entry["symbol"], entry["va"],
                                        entry["original_hex"], entry["size"])
        core = profile["chkfirm_version_gate"]
        cc = member("usr/lib/" + core["library"])
        require(sha(cc) == core["original_sha256"], "Core updater library not stock")
        gates["core_original_sha256"] = sha(cc)
    require(sha(source.read_bytes()) == sha(raw), "Source changed during local inspection")
    return {"input": str(source.relative_to(ROOT)), "input_sha256": sha(raw), "input_bytes": len(raw),
            "upstream_revision": COMMIT, "profile_sha256": sha(profile_path.read_bytes()),
            "audit_source_sha256": sha(Path(__file__).read_bytes()),
            "fat_reader_sha256": sha((UPSTREAM / "a7m4/fat.py").read_bytes()),
            "unsquashfs_sha256": sha(tool.read_bytes()), "all_checks_passed": True,
            "fat_bytes": fs.total, "partition_tail_bytes": len(raw) - fs.total,
            "partition_tail_sha256": sha(raw[fs.total:]), "initrd_bytes": len(initrd),
            "initrd_sha256": sha(initrd), "p1chksum_valid": True,
            "stock_public_key_matched": True, "libraries": libraries, "original_gates": gates,
            "state": "SAVED_FULL_P1_MATCHES_STOCK_6_02_PROFILE",
            "new_hardware_operations": 0, "source_unchanged": True,
            "restore_verified": False, "full_packaged_product_validation": False,
            "not_full_product_reason": "Unpackaged source lacks release.json and bundled dependencies; used a separate read-only audit without patching product integrity checks",
            "source_view": "/dev/cnflasha1 at capture; raw/clear view equivalence not asserted"}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    result = audit()
    with a.output.open("x") as stream:
        a.output.chmod(0o600)
        json.dump(result, stream, indent=2)
        stream.write("\n")
    print(json.dumps({k: result[k] for k in ("state", "input_bytes", "fat_bytes", "partition_tail_bytes",
                                             "all_checks_passed", "new_hardware_operations", "restore_verified")}))


if __name__ == "__main__":
    main()
