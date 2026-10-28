"""Offline, read-only adapter: auto-fill fl23_prewrite_guard.gate() inputs.

Locates the on-disk candidate artifacts, package config and backups, and assembles
the kwargs for gate(). It reads local files ONLY — no device/USB/vendor execution,
no sealed-source edits, no fabricated values. Device-side values (camera region,
power-IC type, NAND capacity) are left None so the guard reports RUNTIME_UNKNOWN,
to be confirmed on-camera. Items already proven by an independent audit JSON are
filled with that audit's provenance (file + sha256 + all_passed), never invented.

Usage (dry run):  python tools/fl23_prewrite_adapter.py [--header <file> --header-offset <n>]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import fl23_prewrite_guard as g  # same tools/ dir

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from camera_package_audit import audit_candidate, regular_path

# Known, verified on-disk locations for THIS candidate (all under the repo).
CAND = ROOT / "output/fl23-stock-receiver-plain-01"
RECV = ROOT / "output/stock-key-preserving-receiver-01"
OFFLINE = ROOT / "output/fl23-offline"
RECOVERY = ROOT / "local/recovery"

# Program artifacts common to both install paths (AP/CP). P1 is handled via three
# explicit roles below, NOT folded into this dict (see guard ACCEPTANCE note).
ARTIFACT_PATHS = {
    "AP": OFFLINE / "appFw.so",
    "CP_v7": OFFLINE / "CPAPP-B.BIN",
}
# P1 roles kept separate to avoid misjudgment:
P1_PERSONAL_RECEIVER = RECV / "p1_candidate.bin"   # (a) e3ac — written via direct P1 writer
# (b) full-SD generic updater member (~4e9f): no standalone file on disk here; provenance only
# (c) post-install whole-partition SHA: device readback only
MOUNT_CONF = CAND / "package-config/0100_config--mount.conf"
PARTINF = CAND / "package-config/0300_partconf--partinf.conf"
PACKAGE_CONFIG_DIR = CAND / "package-config"
P1_INVERSE = RECV / "p1_inverse.bin"

# Header field offsets (within the firmware header buffer), per FirmwareHeader::Check
# and captured-p1-model-region-binding.json (model@0x24, region@0x28).
OFF_MODEL = 0x24
OFF_REGION = 0x28


def _sha(path: Path) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with Path(path).open("rb") as f:
            for c in iter(lambda: f.read(1 << 20), b""):
                h.update(c)
        return h.hexdigest()
    except OSError:
        return None


def _load_json(path: Path) -> Optional[dict]:
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return None


@dataclass
class Assembled:
    kwargs: dict
    provenance: list = field(default_factory=list)
    missing: list = field(default_factory=list)

    def note(self, msg: str):
        self.provenance.append(msg)


def read_header(header_path: Path, offset: int = 0) -> tuple[Optional[bytes], Optional[str], Optional[str], str]:
    """Read a 512-byte firmware header at `offset`; return (bytes, model_hex, region, note).

    model and region are little-endian uint32 fields at 0x24 and 0x28.
    Returns (None, None, None, reason) if the header cannot be read/validated shape.
    """
    try:
        if type(offset) is not int or offset < 0:
            raise ValueError('Nonnegative integer header offset required')
        with regular_path(header_path).open('rb') as source:
            source.seek(offset)
            hdr = source.read(g.HEADER_LEN)
    except (OSError, ValueError) as e:
        return None, None, None, f"header unreadable: {e}"
    if len(hdr) < g.HEADER_LEN:
        return None, None, None, "header slice < 512 bytes"
    model = hdr[OFF_MODEL:OFF_MODEL + 4]
    region = hdr[OFF_REGION:OFF_REGION + 4]
    # The bytes 81 00 03 01 encode numeric model 0x01030081.
    model_be = f'{int.from_bytes(model, "little"):08x}'
    region_val = str(int.from_bytes(region, "little"))
    return hdr, model_be, region_val, f"header@0x{offset:x} model=0x{model_be} region={region_val}"


def _parse_mount_sizes(path: Path) -> dict:
    """Parse mount.conf lines '/dev/nflashaN mnt type SIZE CLUSTER' -> {dev: bytes}."""
    sizes = {}
    try:
        for line in Path(path).read_text(errors="replace").splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[0].startswith("/dev/nflasha"):
                dev = parts[0].rsplit("/", 1)[-1]
                try:
                    n = int(parts[3])
                except ValueError:
                    continue
                if n > 0:
                    sizes[dev] = n
    except OSError:
        pass
    return sizes


def assemble(header_path: Optional[Path] = None, header_offset: int = 0,
             signature_verify_ok: Optional[bool] = None,
             emmc_backup_ok: Optional[bool] = None,
             nor_backup_ok: Optional[bool] = None,
             write_scope: str = "full_sd",
             upper_layer_resolved: bool = False) -> Assembled:
    a = Assembled(kwargs={})
    k = a.kwargs
    k["write_scope"] = write_scope
    k["upper_layer_resolved"] = upper_layer_resolved is True

    # --- program artifacts AP/CP (on-disk, re-hashable) ---
    arts = {}
    for key, p in ARTIFACT_PATHS.items():
        if p.is_file():
            arts[key] = p
            a.note(f"artifact {key}: {p.relative_to(ROOT)} sha={_sha(p)[:12]}")
        else:
            a.missing.append(f"artifact {key} missing: {p.relative_to(ROOT)}")
    # P1 three roles kept distinct
    if write_scope == 'p1_only' and P1_PERSONAL_RECEIVER.is_file():
        arts["P1_personal_receiver_candidate"] = P1_PERSONAL_RECEIVER
        a.note(f"P1 role (a) personal receiver candidate: {P1_PERSONAL_RECEIVER.relative_to(ROOT)} sha={_sha(P1_PERSONAL_RECEIVER)[:12]} (e3ac; written via DIRECT P1 writer)")
    elif write_scope == 'p1_only':
        a.missing.append("P1 personal receiver candidate missing")
    a.note("P1 role (b) full-SD generic updater member (~4e9f): no standalone file here; not auto-hashed — distinct from (a)")
    a.note("P1 role (c) post-install whole-partition SHA: device readback only — not an offline artifact")
    k["artifacts"] = arts

    # --- package config (on-disk) ---
    k["package_config_dir"] = PACKAGE_CONFIG_DIR
    if not PACKAGE_CONFIG_DIR.is_dir():
        a.missing.append(f"package_config_dir missing: {PACKAGE_CONFIG_DIR.relative_to(ROOT)}")

    # --- required partition sizes from mount.conf (explicit byte sizes) ---
    sizes = _parse_mount_sizes(MOUNT_CONF) if MOUNT_CONF.is_file() else {}
    # restrict to the devices this candidate actually writes (generic set)
    written = {"nflasha1", "nflasha3", "nflasha5", "nflasha7", "nflasha8", "nflasha15"}
    k["required_partition_sizes"] = {d: s for d, s in sizes.items() if d in written} or None
    if k["required_partition_sizes"]:
        a.note(f"required_partition_sizes from mount.conf: {k['required_partition_sizes']}")
    else:
        a.missing.append(f"mount.conf partition sizes not parsed: {MOUNT_CONF.relative_to(ROOT)}")
    k["device_capacities"] = None  # RUNTIME

    # Recompute actual CRCs from the pinned plaintext; a report boolean is not
    # evidence about bytes currently present on disk.
    try:
        audit = audit_candidate(CAND / 'plain.DO_NOT_INSTALL.bin')
        k["component_sums"] = audit['component_sums']
        a.note(f"component CRCs recomputed from fixed plaintext sha={audit['plaintext_sha256']}: "
               f"{audit['table_count']} tables / {audit['regular_CRC_rows']} regular rows")
    except (OSError, ValueError) as error:
        k["component_sums"] = {}
        a.missing.append('actual candidate checksum audit failed: ' + type(error).__name__)

    # --- header + package_model + package_region (only if a header source is given) ---
    # camera_model/camera_region are DEVICE values -> always None here (RUNTIME).
    k["camera_model"] = None
    k["camera_region"] = None
    k["power_ic_type"] = None
    if header_path is not None:
        hdr, model_be, region_val, note = read_header(Path(header_path), header_offset)
        a.note("header: " + note)
        k["header"] = hdr if hdr is not None else b""
        k["package_model"] = model_be
        k["package_region"] = region_val
    else:
        k["header"] = b""  # no header supplied -> guard_header FAIL (clears offline_consistency)
        k["package_model"] = None
        k["package_region"] = None
        a.missing.append("no header source (--header): header/package_model/package_region left unfilled -> offline_consistency fails")
        b = _load_json(CAND / "captured-p1-model-region-binding.json")
        if b and b.get("DAT2_matches_candidate_header_model_bytes_0x24") and b.get("DAT3_matches_candidate_header_region_bytes_0x28"):
            a.note("binding evidence: captured-p1-model-region-binding.json confirms DAT2==header model@0x24, DAT3==header region@0x28 (supply --header to check numerically)")
    a.note("device-side values (camera_model/camera_region/power_ic_type/device_capacities) left None -> RUNTIME_UNKNOWN; confirm on camera")

    # --- signature self-verify: caller-supplied (host signs with research key) ---
    k["signature_verify_ok"] = signature_verify_ok
    if signature_verify_ok is None:
        a.missing.append("signature_verify_ok not provided (host must pass its own research-key signature self-verify result)")

    # --- recovery policy inputs: NOT faked. eMMC/NOR 'verified' must be asserted by caller. ---
    k["emmc_backup_ok"] = emmc_backup_ok is True
    k["nor_backup_ok"] = nor_backup_ok is True
    if emmc_backup_ok is None:
        a.missing.append("emmc_backup_ok not asserted by caller -> False (14-partition verification is the caller's job; adapter does not infer it from one file)")
    if nor_backup_ok is None:
        a.missing.append("nor_backup_ok not asserted by caller -> False")
    k["p1_inverse_path"] = P1_INVERSE if P1_INVERSE.is_file() else None
    if P1_INVERSE.is_file():
        a.note(f"P1 inverse: {P1_INVERSE.relative_to(ROOT)} sha={_sha(P1_INVERSE)[:12]} (single-partition only; NOT whole-device atomic)")
    k["user_informed_exception"] = False

    return a


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--header", type=Path, default=None, help="firmware header source file (offline)")
    ap.add_argument("--header-offset", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--signature-ok", dest="sig", action="store_true", help="host research-key signature self-verified")
    args = ap.parse_args()

    a = assemble(header_path=args.header, header_offset=args.header_offset,
                 signature_verify_ok=(True if args.sig else None))
    result = g.gate(**a.kwargs)

    print("=== provenance (auto-filled, offline read-only) ===")
    for n in a.provenance:
        print("  +", n)
    if a.missing:
        print("=== not auto-filled / caller must supply ===")
        for m in a.missing:
            print("  -", m)
    print("=== gate verdicts ===")
    for v in result.verdicts:
        print(f"  [{v.status:14s}] {v.name:18s} {v.detail}")
    print("=== result axes (none is an automatic device action) ===")
    print(f"  offline_consistency = {result.offline_consistency}")
    print(f"  runtime_pending     = {result.runtime_pending}")
    print(f"  recovery_policy_ok  = {result.recovery_policy_ok}")
    print(f"  write_admission     = {result.write_admission}  (default False; needs offline-clean + no runtime_pending + policy_ok + explicit upper_layer_resolved)")


if __name__ == "__main__":
    main()
