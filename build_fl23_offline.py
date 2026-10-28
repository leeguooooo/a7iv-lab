"""Reproduce pinned upstream FL23 programs and a local settings candidate. No USB I/O.

Run with .venv-offline/bin/python build_fl23_offline.py --output output/fl23-offline
Outputs are research components, never a flashable partition or installation package.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
UPSTREAM = ROOT / "ref/sony-a7m4-custom-firmware"
COMMIT = "caa29145644e1d7d0a41cef1e42f0c53368bd025"
sys.path.insert(0, str(UPSTREAM))
from a7m4.fl23 import RECIPES, SLOTS, bk4_rows, color_records, patch_backup, patch_program


def sha(data):
    return hashlib.sha256(data).hexdigest()


def records(data):
    result = {}
    for chip, row in enumerate(bk4_rows(data)):
        for key, rec in row["records"].items():
            result[(chip, key)] = (rec["attrs"], data[rec["offset"]:rec["offset"] + rec["size"]])
    return result


def unique_record(rows, key):
    matches = [value for (_, prop), value in rows.items() if prop == key]
    if len(matches) != 1:
        raise ValueError(f"Expected one property {key:08x}")
    return matches[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError("Choose a new output directory; existing evidence is retained")
    commit = subprocess.check_output(["git", "-C", str(UPSTREAM), "rev-parse", "HEAD"], text=True).strip()
    if commit != COMMIT or subprocess.check_output(["git", "-C", str(UPSTREAM), "status", "--porcelain"], text=True).strip():
        raise ValueError("Expected the exact clean reviewed upstream checkout")
    donor = ROOT / "local/firmware/fx2-1.01"
    sources = {
        "ap": ROOT / "dumps/20261026-032053-probe3/usr_lib_appFw.so",
        "cp": ROOT / "dumps/20261026-032053-probe3/cp_cpapp-b.bin",
        "backup": ROOT / "dumps/20261026-031555/backup_preset.bin",
        "live_cc1": ROOT / "dumps/20261026-031806-probe2/cp_02a40001.bin",
        "live_block13": ROOT / "dumps/20261026-031806-probe2/cp_02a4000d.bin",
        "fx2_cp": donor / "donor/CPAPP-B.BIN",
        "fx2_cc1": donor / "color/cc1.bin",
        "fx2_block13": donor / "color/block13.bin",
    }
    data = {key: path.read_bytes() for key, path in sources.items()}
    ar = json.loads((RECIPES / "ap-recipe.json").read_text())
    cr = json.loads((RECIPES / "cp-v7-recipe.json").read_text())
    donors = {key: data[key] for key in cr["donors"]}
    if any(sha(value) != cr["donors"][key] for key, value in donors.items()):
        raise ValueError("Donor identity mismatch")
    ap = patch_program(data["ap"], ar)
    cp = patch_program(data["cp"], cr, donors)
    before = records(data["backup"])
    if unique_record(before, 0x02a40001)[1] != data["live_cc1"] or unique_record(before, 0x02a4000d)[1] != data["live_block13"]:
        raise ValueError("Captured live colors differ from captured backup")
    backup = patch_backup(data["backup"], donors["fx2_cc1"], donors["fx2_block13"], "fixed-a1")
    after = records(backup)
    allowed = {0x02a40001, 0x02a4000d, *SLOTS}
    changed = {key for key in before if before[key] != after[key]}
    if before.keys() != after.keys() or any(key not in allowed for _, key in changed):
        raise ValueError("Unexpected settings record changes")
    for key, value in SLOTS.items():
        if unique_record(after, key) != (0x60, bytes([value])):
            raise ValueError("Look slot validation failed")
    cc1, block13 = color_records(data["live_cc1"], data["live_block13"], donors["fx2_cc1"], donors["fx2_block13"], "fixed-a1")
    if unique_record(after, 0x02a40001)[1] != cc1 or unique_record(after, 0x02a4000d)[1] != block13:
        raise ValueError("Live/backup candidate colors disagree")
    # Recheck all input files before persisting outputs.
    if any(sha(path.read_bytes()) != sha(data[key]) for key, path in sources.items()):
        raise ValueError("An input changed while building")
    report = {
        "camera_io": False, "installable_dat": False, "personal_partitions_built": False,
        "device_write_performed": False, "nor_updated": False, "physical_acceptance": False,
        "upstream_commit": COMMIT, "matrix_mode": "fixed-a1",
        "inputs": {key: {"path": str(path.relative_to(ROOT)), "size": len(data[key]), "sha256": sha(data[key])} for key, path in sources.items()},
        "settings": {"record_count": len(before), "unchanged_record_count": len(before) - len(changed),
                     "changed_records": [f"chip{chip}:{key:08x}" for chip, key in sorted(changed)], "bk4_checksums_valid": True},
        "limitations": ["Historical captures, not fresh installation preflight", "No complete nfa2/nfa6 or physical NOR backup", "No arbitrary CUBE/DCP/A7Look import", "AP/CP v7 only; separate lossless RAW repair not applied"],
        "outputs": {},
    }
    products = {"appFw.so": ap, "CPAPP-B.BIN": cp, "backup_preset.candidate.bin": backup,
                "cp_02a40001.candidate.bin": cc1, "cp_02a4000d.candidate.bin": block13}
    args.output.mkdir(parents=True)
    for name, payload in products.items():
        path = args.output / name
        with path.open("xb") as f:
            f.write(payload)
        if path.read_bytes() != payload:
            raise ValueError("Output readback mismatch")
        report["outputs"][name] = {"size": len(payload), "sha256": sha(payload)}
    (args.output / "manifest.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
