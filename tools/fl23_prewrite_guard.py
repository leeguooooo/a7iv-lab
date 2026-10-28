"""Offline, host-side fail-closed pre-write guards for the FL2/FL3 SD candidate.

Pure stdlib. This module performs NO device/USB I/O and runs NO vendor program.
It only reads local files/bytes and returns structured PASS/FAIL/RUNTIME verdicts.
It mirrors the firmware's own gates so the host rejects BEFORE the camera does;
its result is only an offline consistency report, never device write authority.
Runtime values, CRC pairs, signature/recovery assertions must come from the
trusted caller: this module cannot authenticate their provenance or freshness.

Spec: output/fl23-acceptance-spec-01.json ; evidence: reports/仓库更新与新参考20261027.md
"""
from __future__ import annotations

import binascii
import hashlib
import json
import os
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

# ---- Fixed, verified expectations for THIS candidate (offline evidence) -------
MODEL_CODE = "01030081"
HEADER_MAGIC = b"UDTRFIRM"
HEADER_FORMAT = b"0100"
HEADER_LEN = 0x200
CRC_POLY_REVERSED = 0xEDB88320  # FirmwareHeader::Check@0x96fc

ACCEPTANCE = {
    "AP": {"sha256": "d17e61fb4ba193d8e7d802196edff5f578d5691b3fcc4abcd1cbbb6e58bdd8ff"},
    "CP_v7": {"sha256": "4551c73386c27a0a9b247fd3e05c3bd5e3425bdb9fe9f8374c201c96533b3479", "bytes": 16236816},
    # P1 has THREE distinct roles — do NOT conflate:
    #  (a) personal receiver candidate actually written via the direct P1 writer (this hash)
    #  (b) the full-SD package's generic updater member (different hash, ~4e9f…) — NOT this
    #  (c) the post-install whole-partition SHA read back from the camera — device-only
    "P1_personal_receiver_candidate": {"sha256": "e3ac140c49bd81b74799da9051b47a12ed201931380df87f7c35bc122345275e", "bytes": 25100288},
}

PASS, FAIL, RUNTIME, SKIP = "PASS", "FAIL", "RUNTIME_UNKNOWN", "SKIP"
POLICY_OK, POLICY_BLOCK = "POLICY_OK", "POLICY_BLOCK"


@dataclass
class Verdict:
    name: str
    status: str            # PASS / FAIL / RUNTIME_UNKNOWN / SKIP
    detail: str = ""
    mirrors: str = ""      # the firmware gate this mirrors

    @property
    def blocking_fail(self) -> bool:
        return self.status == FAIL


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _safe_path(path):
    try:
        path = Path(path).absolute()
        if any(component.is_symlink() for component in (path, *path.parents)):
            return None, "symlink-not-allowed"
        return path, None
    except (TypeError, ValueError, OSError):
        return None, "invalid-path"


def _regular_file(path: Path) -> Optional[str]:
    path, error = _safe_path(path)
    if error:
        return error
    try:
        if not path.exists():
            return "missing"
        if not path.is_file():
            return "not-a-regular-file"
    except OSError:
        return "unreadable"
    return None


# ---- Individual guards --------------------------------------------------------

def guard_header(header: bytes) -> Verdict:
    """Mirror FirmwareHeader::Check@0x96fc: magic, format, header CRC32.

    `header` is the 512-byte firmware header buffer. CRC32 (reversed poly
    0xedb88320, init 0xffffffff, final XOR 0xffffffff) over bytes [0xc, 0x200)
    compared against the 4-byte little-endian value stored at offset 8.
    """
    g = "FirmwareHeader::Check@0x96fc"
    if not isinstance(header, (bytes, bytearray)) or len(header) < HEADER_LEN:
        return Verdict("header", FAIL, f"header < {HEADER_LEN} bytes", g)
    if header[0:8] != HEADER_MAGIC:
        return Verdict("header", FAIL, f"magic={header[0:8]!r} != {HEADER_MAGIC!r}", g)
    if header[0xC:0x10] != HEADER_FORMAT:
        return Verdict("header", FAIL, f"format={header[0xC:0x10]!r} != {HEADER_FORMAT!r}", g)
    computed = binascii.crc32(bytes(header[0xC:HEADER_LEN])) & 0xFFFFFFFF
    stored = int.from_bytes(header[8:0xC], "little")
    if computed != stored:
        return Verdict("header", FAIL, f"crc computed=0x{computed:08x} stored=0x{stored:08x}", g)
    return Verdict("header", PASS, "magic/format/crc ok", g)


def guard_model(package_model: str, camera_model=None) -> Verdict:
    """isModelOK is an EXACT compare of the package model vs the camera's model.

    Offline we can only confirm the package declares 01030081. The real gate
    compares against the camera's current/update model, which is a device value:
    when camera_model is None we cannot mirror the exact-eq here -> RUNTIME.
    """
    g = "SDUUDConditionChecker::isModelOK (+c/+24 exact-eq, package vs camera)"
    if not isinstance(package_model, str) or package_model.strip().lower() != MODEL_CODE:
        return Verdict("model", FAIL, f"package model={package_model!r} != {MODEL_CODE}", g)
    if camera_model is None:
        return Verdict("model", RUNTIME,
                       f"package model={MODEL_CODE} ok offline; camera model unknown -> exact-eq unverified", g)
    if not isinstance(camera_model, str) or camera_model.strip().lower() != MODEL_CODE:
        return Verdict("model", FAIL, f"camera model={camera_model!r} != package {MODEL_CODE}", g)
    return Verdict("model", PASS, f"package==camera=={MODEL_CODE}", g)


def guard_region(package_region, camera_region) -> Verdict:
    """isRegionOK does an EXACT compare; region 0 is NOT a wildcard."""
    g = "SDUUDConditionChecker::isRegionOK (+10/+28 exact-eq, region0 not wildcard)"
    def valid_region(value):
        return ((type(value) is int and value >= 0) or
                (isinstance(value, str) and bool(re.fullmatch(r"[0-9]+", value))))
    if not valid_region(package_region):
        return Verdict("region", FAIL, "package region is missing/invalid", g)
    if camera_region is None:
        return Verdict("region", RUNTIME, "camera region unknown offline; must equal package region on device", g)
    if not valid_region(camera_region):
        return Verdict("region", FAIL, "camera region is invalid", g)
    if package_region != camera_region:
        return Verdict("region", FAIL, f"package={package_region!r} != camera={camera_region!r}", g)
    return Verdict("region", PASS, f"region={package_region!r}", g)


def guard_component_crcs(sum_files: dict[str, tuple[str, int]]) -> Verdict:
    """Compare trusted caller-supplied CRC pairs; this does not read components.

    A matching pair, including ("0", 0), proves only pair equality. The caller
    must bind complete manifest coverage and computations to the current actual
    package bytes. An all_passed JSON or invented sentinel is not that evidence.
    """
    g = "config.xml *_sum procs (uc_crc32sum.elf -c)"
    if not isinstance(sum_files, dict) or not sum_files:
        return Verdict("component_crc", FAIL, "no valid component sums provided", g)
    bad = []
    for label, pair in sum_files.items():
        if (not isinstance(label, str) or not label or not isinstance(pair, (list, tuple)) or len(pair) != 2):
            bad.append(str(label))
            continue
        expected, got = pair
        if (not isinstance(expected, str) or not re.fullmatch(r"(?:0x)?[0-9a-fA-F]{1,8}", expected)
                or type(got) is not int or not 0 <= got <= 0xffffffff
                or int(expected, 16) != got):
            bad.append(label)
    if bad:
        return Verdict("component_crc", FAIL, "crc mismatch/malformed: " + ','.join(bad), g)
    return Verdict("component_crc", PASS, f"{len(sum_files)} caller-supplied CRC pairs equal; package binding required", g)


def guard_no_sub_conf(package_config_dir: Path) -> Verdict:
    """chkfirm.sh main-LSI branch requires the package has NO config/sub.conf."""
    g = "chkfirm.sh (main LSI => no sub.conf)"
    folder, error = _safe_path(package_config_dir)
    if error or not folder.is_dir():
        return Verdict("sub_conf", FAIL, "package config directory missing/unsafe", g)
    sub = folder / "sub.conf"
    # A broken symlink still establishes a forbidden sub.conf entry.
    if sub.exists() or sub.is_symlink():
        return Verdict("sub_conf", FAIL, "config/sub.conf present (sub-LSI package)", g)
    return Verdict("sub_conf", PASS, "no sub.conf in checked package config directory", g)


def guard_lsi_main(power_ic_type: Optional[int]) -> Verdict:
    """LSI main check depends on a RUNTIME value (ud_get_power_ic_type.elf)."""
    g = "chkfirm.sh ud_get_power_ic_type"
    main = {1, 6, 4, 5, 7}
    if power_ic_type is None:
        return Verdict("lsi_main", RUNTIME, "power IC type is a device-runtime value; confirm on camera", g)
    if type(power_ic_type) is not int or power_ic_type <= 0:
        return Verdict("lsi_main", FAIL, "power IC type must be a positive integer (not bool)", g)
    if power_ic_type not in main:
        return Verdict("lsi_main", FAIL, f"power_ic={power_ic_type} not a main-LSI value {sorted(main)}", g)
    return Verdict("lsi_main", PASS, f"power_ic={power_ic_type} (main)", g)


def guard_nand_capacity(required_partition_sizes: Optional[dict],
                        device_capacities: Optional[dict]) -> Verdict:
    """chknandcapa.elf: each required partition must fit the device NAND.

    `required_partition_sizes`: {dev: bytes} the package requires (e.g. parsed
    from mount.conf, which carries explicit byte sizes). `device_capacities`:
    {dev: bytes} the actual device reports (RUNTIME). This guard NEVER PASSes
    without real data: no device capacities, or any required device missing a
    capacity, or an empty/unknown requirement set -> RUNTIME_UNKNOWN (not PASS).
    """
    g = "chknandcapa.elf"
    if required_partition_sizes is not None and not isinstance(required_partition_sizes, dict):
        return Verdict("nand_capacity", FAIL, "invalid partition requirement map", g)
    if device_capacities is not None and not isinstance(device_capacities, dict):
        return Verdict("nand_capacity", FAIL, "invalid device capacity map", g)
    if not required_partition_sizes:
        return Verdict("nand_capacity", RUNTIME, "required partition sizes not supplied; cannot assess", g)
    if any(not isinstance(dev, str) or not dev or type(want) is not int or want <= 0
           for dev, want in required_partition_sizes.items()):
        return Verdict("nand_capacity", FAIL, "partition sizes must be positive integers (not bool)", g)
    if device_capacities and any(not isinstance(dev, str) or not dev or type(cap) is not int or cap <= 0
                                 for dev, cap in device_capacities.items()):
        return Verdict("nand_capacity", FAIL, "device capacities must be positive integers (not bool)", g)
    if not device_capacities:
        return Verdict("nand_capacity", RUNTIME,
                       f"device NAND capacities are a runtime value ({len(required_partition_sizes)} partitions to check)", g)
    missing, over = [], []
    for dev, want in required_partition_sizes.items():
        cap = device_capacities.get(dev)
        if cap is None:
            missing.append(dev)
        elif want > cap:
            over.append(f"{dev}:{want}>{cap}")
    if over:
        return Verdict("nand_capacity", FAIL, "partition exceeds device: " + ",".join(over), g)
    if missing:
        return Verdict("nand_capacity", RUNTIME, "device capacity missing for: " + ",".join(missing), g)
    return Verdict("nand_capacity", PASS, f"all {len(required_partition_sizes)} partitions fit", g)


def guard_signature(verify_ok: Optional[bool]) -> Verdict:
    """Host must have produced a VALID research-key RSA signature over the package.

    Even though the receiver's VerifySignature is patched to success, the host
    still signs correctly so the package is well-formed off-camera. Caller passes
    the result of its own signature self-verify.
    """
    g = "VerifySignature (sole RSA chokepoint)"
    if verify_ok is None:
        return Verdict("signature", FAIL, "no signature self-verify result provided", g)
    return Verdict("signature", PASS if verify_ok is True else FAIL,
                   "research-key signature valid" if verify_ok is True else "signature self-verify requires strict True", g)


def recovery_policy(*, emmc_backup_ok: bool, nor_backup_ok: bool,
                    p1_inverse_path: Optional[Path], write_scope: str,
                    user_informed_exception: bool = False) -> Verdict:
    """Recovery-capability POLICY (NOT a firmware technical gate).

    This reflects rollback/risk capability, not something the updater itself
    checks. It never fakes PASS. Strict default:
      - write_scope == 'full_sd': require eMMC(14-part) AND physical NOR backups.
      - write_scope == 'p1_only': P1 single-partition inverse is the relevant
        recovery artifact; NOR/eMMC are advisory, not a hard block.
    A shortfall is POLICY_BLOCK unless the caller passes an explicit
    user_informed_exception, which is recorded, never silently satisfied.
    """
    g = "recovery policy (risk/rollback capability; not a firmware gate)"
    gaps = []
    if write_scope == "full_sd":
        if emmc_backup_ok is not True:
            gaps.append("eMMC(14-part) backup not verified")
        if nor_backup_ok is not True:
            gaps.append("physical NOR backup not verified")
    elif write_scope == "p1_only":
        if p1_inverse_path is None or _regular_file(p1_inverse_path):
            gaps.append("P1 single-partition inverse missing")
    else:
        return Verdict("recovery_policy", POLICY_BLOCK, f"unknown write_scope {write_scope!r}", g)
    note = ("P1 inverse is single-partition only, NOT whole-device atomic; "
            "a mid-sequence full-SD failure is not rollback-covered")
    if not gaps:
        return Verdict("recovery_policy", POLICY_OK, f"{write_scope}: recovery capability present. {note}", g)
    if user_informed_exception is True:
        return Verdict("recovery_policy", POLICY_OK,
                       f"{write_scope}: GAPS ACCEPTED via explicit user-informed exception [{'; '.join(gaps)}]. {note}", g)
    return Verdict("recovery_policy", POLICY_BLOCK, f"{write_scope}: {'; '.join(gaps)}. {note}", g)


def guard_artifact_hashes(artifacts: dict[str, Path], write_scope="full_sd") -> list[Verdict]:
    """Check the complete scope-specific artifact set, rejecting unknown labels.

    AP/CP are mandatory in both scopes. The personal P1 receiver is mandatory
    only for p1_only; it must never be confused with the full-SD updater member.
    These separate files still do not prove the actual package embeds them.
    """
    g = "acceptance SHA (report §9/§10/§14)"
    if not isinstance(artifacts, dict):
        return [Verdict("artifacts", FAIL, "artifact map required", g)]
    required = {"AP", "CP_v7"}
    if write_scope == "p1_only":
        required.add("P1_personal_receiver_candidate")
    out = [Verdict(f"hash:{key}", FAIL, "required artifact missing", g)
           for key in sorted(required - artifacts.keys())]
    for key, path in artifacts.items():
        exp = ACCEPTANCE.get(key)
        if exp is None:
            out.append(Verdict(f"hash:{key}", FAIL, "unknown artifact label", g))
            continue
        err = _regular_file(path)
        if err:
            out.append(Verdict(f"hash:{key}", FAIL, f"{path}: {err}", g))
            continue
        try:
            path = Path(path)
            got = _sha256(path)
            size = path.stat().st_size
        except OSError:
            out.append(Verdict(f"hash:{key}", FAIL, "artifact unreadable", g))
            continue
        nb = exp.get("bytes")
        if got == exp["sha256"] and (nb is None or size == nb):
            out.append(Verdict(f"hash:{key}", PASS, exp["sha256"][:12], g))
        else:
            out.append(Verdict(f"hash:{key}", FAIL,
                               f"sha={got[:12]} expected={exp['sha256'][:12]} size={size}", g))
    return out


# ---- Aggregator: fail-closed --------------------------------------------------

@dataclass
class GateResult:
    """Separates three independent axes; NONE of them is a device write permission.

    - offline_consistency: every offline-checkable firmware-mirror gate PASSed
      (no FAIL). Necessary, not sufficient.
    - runtime_pending: device-side values the host cannot know offline
      (RUNTIME_UNKNOWN); each MUST be confirmed on-camera before any write.
    - recovery_policy_ok: the recovery/risk policy is satisfied (or an explicit
      user-informed exception was recorded).
    - write_admission: default False. Only True when offline_consistency AND no
      runtime_pending remain AND recovery_policy_ok AND the caller explicitly
      passes upper_layer_resolved=True. This flag still authorizes NO automatic
      device action — a human/orchestrator decides the actual write.
    """
    offline_consistency: bool
    runtime_pending: list
    recovery_policy_ok: bool
    write_admission: bool
    verdicts: list = field(default_factory=list)

    def to_json(self) -> str:
        return json.dumps(
            {"offline_consistency": self.offline_consistency,
             "runtime_pending": self.runtime_pending,
             "recovery_policy_ok": self.recovery_policy_ok,
             "write_admission": self.write_admission,
             "write_admission_is_not_an_automatic_action": True,
             "source_and_runtime_authenticity_proven": False,
             "prohibited_on_unknown_outcome": [
                 "auto-retry failed write", "host rollback", "STOP/service-exit", "camera reboot/reset"],
             "verdicts": [asdict(v) for v in self.verdicts]},
            indent=2, ensure_ascii=False)


def gate(*, header: bytes, package_model: str, camera_model=None,
         package_region=None, camera_region=None,
         component_sums: dict, package_config_dir, power_ic_type,
         required_partition_sizes=None, device_capacities=None, signature_verify_ok=None,
         emmc_backup_ok: bool = False, nor_backup_ok: bool = False, p1_inverse_path=None,
         write_scope: str = "full_sd", user_informed_exception: bool = False,
         upper_layer_resolved: bool = False, artifacts: dict = None) -> GateResult:
    """Assemble all axes. write_admission defaults False and is never a device action.

    A FAIL in any firmware-mirror gate clears offline_consistency. RUNTIME_UNKNOWN
    items are collected into runtime_pending and do NOT by themselves grant
    admission. Recovery policy is assessed separately (not a firmware gate).
    """
    artifacts = {} if artifacts is None else artifacts
    firmware = [
        guard_header(header),
        guard_model(package_model, camera_model),
        guard_region(package_region, camera_region),
        guard_component_crcs(component_sums),
        guard_no_sub_conf(package_config_dir),
        guard_lsi_main(power_ic_type),
        guard_nand_capacity(required_partition_sizes, device_capacities),
        guard_signature(signature_verify_ok),
        *guard_artifact_hashes(artifacts, write_scope),
    ]
    policy = recovery_policy(emmc_backup_ok=emmc_backup_ok, nor_backup_ok=nor_backup_ok,
                             p1_inverse_path=p1_inverse_path, write_scope=write_scope,
                             user_informed_exception=user_informed_exception)
    verdicts = firmware + [policy]

    offline_consistency = not any(v.blocking_fail for v in firmware)
    runtime_pending = [v.name for v in firmware if v.status == RUNTIME]
    recovery_policy_ok = policy.status == POLICY_OK
    write_admission = bool(offline_consistency and not runtime_pending
                           and recovery_policy_ok and upper_layer_resolved is True)
    return GateResult(offline_consistency=offline_consistency,
                      runtime_pending=runtime_pending,
                      recovery_policy_ok=recovery_policy_ok,
                      write_admission=write_admission,
                      verdicts=verdicts)


if __name__ == "__main__":  # offline self-test with synthetic inputs (no device)
    import struct

    hdr = bytearray(HEADER_LEN)
    hdr[0:8] = HEADER_MAGIC
    hdr[0xC:0x10] = HEADER_FORMAT
    crc = binascii.crc32(bytes(hdr[0xC:HEADER_LEN])) & 0xFFFFFFFF
    hdr[8:0xC] = struct.pack("<I", crc)

    # Individual positive/negative checks
    assert guard_header(bytes(hdr)).status == PASS
    bad = bytearray(hdr); bad[0] = ord("X")
    assert guard_header(bytes(bad)).status == FAIL
    assert guard_model("01030081", None).status == RUNTIME          # camera model unknown
    assert guard_model("01030081", "01030081").status == PASS       # exact-eq
    assert guard_model("01030081", "01030099").status == FAIL       # camera differs
    assert guard_model("01030099", None).status == FAIL             # package wrong
    assert guard_region("0", "0").status == PASS
    assert guard_region("0", "1").status == FAIL
    assert guard_region("0", None).status == RUNTIME
    assert guard_component_crcs({"config": ("0000ffff", 0x0000FFFF)}).status == PASS
    assert guard_component_crcs({"config": ("0000ffff", 0x12345678)}).status == FAIL
    assert guard_lsi_main(None).status == RUNTIME
    assert guard_lsi_main(1).status == PASS and guard_lsi_main(2).status == FAIL
    assert guard_signature(True).status == PASS and guard_signature(False).status == FAIL
    # nand: no sizes / no caps -> RUNTIME (never a silent PASS); fits / exceeds explicit
    assert guard_nand_capacity(None, None).status == RUNTIME
    assert guard_nand_capacity({"nflasha8": 100}, None).status == RUNTIME
    assert guard_nand_capacity({"nflasha8": 100}, {"nflasha15": 200}).status == RUNTIME  # required cap missing
    assert guard_nand_capacity({"nflasha8": 100}, {"nflasha8": 200}).status == PASS
    assert guard_nand_capacity({"nflasha8": 300}, {"nflasha8": 200}).status == FAIL
    # recovery policy is separate (POLICY_*), never a fake firmware PASS
    assert recovery_policy(emmc_backup_ok=True, nor_backup_ok=True, p1_inverse_path=None,
                           write_scope="full_sd").status == POLICY_OK
    assert recovery_policy(emmc_backup_ok=True, nor_backup_ok=False, p1_inverse_path=None,
                           write_scope="full_sd").status == POLICY_BLOCK
    assert recovery_policy(emmc_backup_ok=False, nor_backup_ok=False, p1_inverse_path=None,
                           write_scope="full_sd", user_informed_exception=True).status == POLICY_OK

    # write_admission defaults False; RUNTIME-pending must NOT admit even if offline-clean.
    clean = gate(header=bytes(hdr), package_model="01030081", camera_model=None,
                 package_region="0", camera_region=None,
                 component_sums={"c": ("0", 0)}, package_config_dir=".", power_ic_type=None,
                 required_partition_sizes=None, device_capacities=None, signature_verify_ok=True,
                 emmc_backup_ok=True, nor_backup_ok=True, p1_inverse_path=None,
                 write_scope="full_sd", upper_layer_resolved=True,
                 artifacts={})
    assert clean.offline_consistency is False      # mandatory artifacts missing
    assert clean.runtime_pending                   # model/region/lsi/nand pending
    assert clean.write_admission is False          # pending => NOT admitted
    print("fl23_prewrite_guard self-test OK; write_admission(runtime-pending)=", clean.write_admission,
          "runtime_pending=", clean.runtime_pending)
