"""Local-only validation/sealing of four fixed remaining backup candidates."""
import hashlib
import json
import io
import struct
from pathlib import Path
import subprocess

from camera_stream_profiles import PROFILES, profile
from camera_inventory import ROOT, NATIVE, UPSTREAM, COMMIT, inspect
from tools.build_remaining_backup_worker import derived_source, target_header, TEMPLATE_SHA

BATCH = ROOT / "output/remaining-backup-batch-02"


def sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for data in iter(lambda: f.read(65536), b""):
            h.update(data)
    return h.hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read(path):
    return json.loads(Path(path).read_text())


def checked_worker(job, *, allow_test=False):
    job = Path(job).resolve()
    require(job.is_relative_to(ROOT), "Job outside workspace")
    meta, report = read(job / "job.json"), read(job / "emulation.json")
    require(meta["schema"] == "camera-remaining-offline-worker/1" and type(meta["test_image"]) is bool,
            "Wrong remaining worker schema")
    p = profile(meta["profile"])
    require(allow_test or not meta["test_image"], "Test images cannot access a device")
    require(meta["target"] == [p.name, p.minor, p.tiny_size if meta["test_image"] else p.size]
            and meta["chunk_bytes"] == (4096 if meta["test_image"] else 8388608), "Wrong fixed geometry")
    nonce = bytes.fromhex(meta["nonce"])
    require(len(nonce) == 16 and meta["nonce"] == nonce.hex()
            and meta["job_dir"] == "/tmp_wbshd/m4stream_" + nonce.hex(), "Wrong job identity")
    expected_header = '#define JOB_DIR "' + meta["job_dir"] + '"\n'
    expected_header += 'static const unsigned char job_nonce[]={' + ','.join(map(str, nonce)) + '};\n'
    require((job / "job.h").read_text() == expected_header and
            (job / "target.h").read_text() == target_header(p) and
            (job / "stream_backup_remaining.c").read_text() == derived_source(), "Generated source changed")
    shared = [ROOT / "native/stream_backup.c", ROOT / "tools/build_remaining_backup_worker.py",
              ROOT / "camera_stream_profiles.py", ROOT / "camera_inventory.py",
              NATIVE / "lifecycle_worker.c", NATIVE / "linux_a64.h", NATIVE.parent / "writer/sha256.h"]
    shared_names = {str(x.relative_to(ROOT)) for x in shared}
    generated = {str((job / x).relative_to(ROOT)) for x in ("job.h", "target.h", "stream_backup_remaining.c")}
    require(set(meta["shared_sources"]) == shared_names and set(meta["sources"]) == shared_names | generated,
            "Source closure changed")
    require(all(sha(ROOT / n) == d for n, d in meta["sources"].items()), "Worker sources stale")
    require(sha(ROOT / "native/stream_backup.c") == TEMPLATE_SHA == meta["reference_pilot_template_sha256"],
            "Validated pilot body changed")
    require(sha(job / "worker.debug.elf") == meta["worker_sha256"] == report["worker_sha256"], "Worker changed")
    require(report["all_passed"] is True and report["hardware_acceptance"] is False
            and report["full_size_success_emulated"] is False
            and report["job_manifest_sha256"] == sha(job / "job.json")
            and report["sources"] == meta["sources"] and report["target"] == meta["target"]
            and report["chunk_bytes"] == meta["chunk_bytes"] and report["test_image"] is meta["test_image"]
            and report["emulator_sha256"] == sha(ROOT / "tools/emulate_remaining_backup_worker.py"),
            "Worker evidence binding changed")
    tests = report["tests"]
    require(len(tests) == (26 if meta["test_image"] else 10)
            and len({t["scenario"] for t in tests}) == len(tests)
            and all(t["passed"] is True for t in tests), "Incomplete worker evidence")
    if not meta["test_image"]:
        require(all(t["source_bytes_read"] == 0 for t in tests), "Production evidence scope changed")
    return meta


def checked_bootstrap(name, batch=BATCH):
    p = profile(name)
    folder = Path(batch).resolve() / p.name
    require(folder.is_relative_to(ROOT), "Batch outside workspace")
    prod, tiny = checked_worker(folder / "production"), checked_worker(folder / "tiny", allow_test=True)
    require(tiny["test_image"] is True and prod["shared_sources"] == tiny["shared_sources"]
            and prod["derived_source_sha256"] == tiny["derived_source_sha256"]
            and prod["target_header_sha256"] == tiny["target_header_sha256"], "Production/tiny mismatch")
    out = folder / "bootstrap"
    meta, report = read(out / "bootstrap.json"), read(out / "emulation.json")
    require(meta["schema"] == "camera-remaining-bootstrap-offline/1" and meta["profile"] == p.name
            and meta["target"] == list(p.target) and meta["nonce"] == prod["nonce"]
            and meta["job_dir"] == prod["job_dir"], "Bootstrap target changed")
    require(meta["production_worker_job"] == str((folder / "production").relative_to(ROOT))
            and meta["tiny_worker_job"] == str((folder / "tiny").relative_to(ROOT)), "Worker paths changed")
    for field, path in (("production_job_manifest_sha256", folder / "production/job.json"),
                        ("tiny_job_manifest_sha256", folder / "tiny/job.json"),
                        ("production_emulation_sha256", folder / "production/emulation.json"),
                        ("tiny_emulation_sha256", folder / "tiny/emulation.json")):
        require(meta[field] == sha(path), "Exact worker evidence changed")
    require(meta["production_debug_worker_sha256"] == prod["worker_sha256"]
            and meta["shared_sources"] == prod["shared_sources"]
            and sha(out / "job.h") == meta["job_header_sha256"] == prod["header_sha256"]
            and (out / "job.h").read_bytes() == (folder / "production/job.h").read_bytes(),
            "Bootstrap/source identity mismatch")
    module, compact = (out / "libJit.so").read_bytes(), (out / "worker.elf").read_bytes()
    require(0 < len(module) <= 65520 and sha(out / "libJit.so") == meta["module"]["sha256"]
            and len(module) == meta["module"]["size"] and sha(out / "worker.elf") == meta["compact_worker_sha256"]
            and module.count(compact) == 1, "Bootstrap bytes or embedding changed")
    from elftools.elf.elffile import ELFFile
    raw = (folder / "production/worker.debug.elf").read_bytes()
    elf = ELFFile(io.BytesIO(raw))
    limit = max(s["p_offset"] + s["p_filesz"] for s in elf.iter_segments() if s["p_type"] == "PT_LOAD")
    expected = bytearray(raw[:limit])
    struct.pack_into("<Q", expected, 40, 0)
    struct.pack_into("<3H", expected, 58, 0, 0, 0)
    require(compact == bytes(expected), "Embedded worker differs from exact validated production ELF")
    require(inspect(out / "libJit.so", False) == meta["module"], "Bootstrap ELF layout changed")
    require(meta["bootstrap_source_sha256"] == sha(NATIVE / "bootstrap.c")
            and meta["linux_helpers_sha256"] == sha(NATIVE / "linux_a64.h")
            and meta["builder_sha256"] == sha(ROOT / "tools/prepare_remaining_bootstrap.py"),
            "Bootstrap source/builder changed")
    require(report["all_passed"] is True and report["hardware_acceptance"] is False
            and report["module_sha256"] == meta["module"]["sha256"]
            and report["compact_worker_sha256"] == meta["compact_worker_sha256"]
            and report["emulator_sha256"] == sha(ROOT / "tools/emulate_stream_bootstrap.py")
            and len(report["tests"]) == 16 and all(t["passed"] is True for t in report["tests"]),
            "Bootstrap emulation changed")
    return meta, module


def all_candidates(batch=BATCH):
    require(subprocess.check_output(["git", "-C", str(UPSTREAM), "rev-parse", "HEAD"],
                                    text=True).strip() == COMMIT, "Helper revision changed")
    require(not subprocess.check_output(["git", "-C", str(UPSTREAM), "status", "--porcelain"]),
            "Helper checkout dirty")
    candidates = [checked_bootstrap(p.name, batch) for p in PROFILES]
    require(len({m["nonce"] for m, _ in candidates}) == len(PROFILES), "Repeated task nonce")
    return candidates
