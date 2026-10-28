"""Prepare an offline bootstrap containing an already emulated worker; no USB."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from camera_inventory import COMMIT, NATIVE, UPSTREAM, inspect, require, sha
from elftools.elf.elffile import ELFFile


def checked_job(directory):
    meta = json.loads((directory / "job.json").read_text())
    report = json.loads((directory / "emulation.json").read_text())
    require(meta["schema"] == "camera-stream-offline-worker/1", "Wrong worker schema")
    require(sha(directory / "worker.debug.elf") == meta["worker_sha256"] == report["worker_sha256"],
            "Worker or emulation binding changed")
    require(report["all_passed"] and all(t["passed"] for t in report["tests"]), "Worker tests failed")
    require(sha(directory / "job.h") == meta["header_sha256"], "Job header changed")
    require(all(sha(ROOT / p) == h for p, h in meta["sources"].items()), "Worker sources changed")
    require(sha(ROOT / "tools/emulate_stream_backup_worker.py") == report["emulator_sha256"],
            "Emulator changed since validation")
    return meta, report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--worker-job", type=Path, required=True)
    p.add_argument("--test-job", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    worker, test, out = a.worker_job.resolve(), a.test_job.resolve(), a.output.resolve()
    prod, pr = checked_job(worker)
    tiny, tr = checked_job(test)
    require(not prod["test_image"] and tiny["test_image"] and prod["sources"] == tiny["sources"],
            "Production/tiny source mismatch")
    require(prod["target"] == ["cnflasha7", 135, 16777216]
            and prod["chunk_bytes"] == 8388608, "Only fixed pilot admitted")
    require(subprocess.check_output(["git", "-C", str(UPSTREAM), "rev-parse", "HEAD"],
                                    text=True).strip() == COMMIT, "Helper revision changed")
    require(not subprocess.check_output(["git", "-C", str(UPSTREAM), "status", "--porcelain"]),
            "Helper checkout dirty")
    raw = (worker / "worker.debug.elf").read_bytes()
    elf = ELFFile(io.BytesIO(raw))
    limit = max(s["p_offset"] + s["p_filesz"] for s in elf.iter_segments() if s["p_type"] == "PT_LOAD")
    compact = bytearray(raw[:limit])
    struct.pack_into("<Q", compact, 40, 0)
    struct.pack_into("<3H", compact, 58, 0, 0, 0)
    ce = ELFFile(io.BytesIO(compact))
    original_loads = [(dict(s.header), s.data()) for s in elf.iter_segments() if s["p_type"] == "PT_LOAD"]
    compact_loads = [(dict(s.header), s.data()) for s in ce.iter_segments() if s["p_type"] == "PT_LOAD"]
    # The ELF header is in PT_LOAD: only section-table header fields change.
    for (oh, od), (ch, cd) in zip(original_loads, compact_loads):
        require(oh == ch, "Program headers changed")
        expect = bytearray(od)
        if oh["p_offset"] == 0:
            struct.pack_into("<Q", expect, 40, 0)
            struct.pack_into("<3H", expect, 58, 0, 0, 0)
        require(bytes(expect) == cd, "Loaded worker bytes changed")
    require(len(original_loads) == len(compact_loads) and ce["e_entry"] == elf["e_entry"],
            "Compact loader mapping differs")
    out.mkdir(mode=0o700)
    (out / "job.h").write_bytes((worker / "job.h").read_bytes())
    (out / "worker.elf").write_bytes(compact)
    (out / "worker_blob.h").write_text("static const unsigned char worker_blob[]={" +
                                      ",".join(map(str, compact)) + "};\n")
    compiler = ROOT / "local/zig-aarch64-macos-0.15.2/zig"
    require(sha(compiler) == prod["compiler_sha256"], "Compiler changed")
    args = [str(compiler), "cc", "-target", "aarch64-linux-gnu", "-mcpu=generic", "-Os",
            "-ffreestanding", "-fno-builtin", "-fno-stack-protector", "-fno-unwind-tables",
            "-fno-asynchronous-unwind-tables", "-nostdlib", "-ffunction-sections",
            "-fdata-sections", "-Wl,--gc-sections", "-Wl,--no-undefined", "-Wl,--build-id=none",
            "-Wl,-z,noexecstack", "-Wl,-z,max-page-size=4096", "-Wl,-z,common-page-size=4096",
            "-shared", "-fPIC", "-Wl,-Bsymbolic", "-s", "-I", str(out), "-I", str(NATIVE),
            str(NATIVE / "bootstrap.c"), "-o", str(out / "libJit.so")]
    result = subprocess.run(args, capture_output=True, text=True, timeout=120)
    (out / "compile.log").write_text(result.stdout + result.stderr)
    require(result.returncode == 0, result.stderr[-3000:])
    module = inspect(out / "libJit.so", False)
    require(module["size"] <= 65520, "One-upload bootstrap limit")
    module_bytes = (out / "libJit.so").read_bytes()
    require(module_bytes.count(bytes(compact)) == 1, "Embedded worker must match exactly once")
    manifest = {"schema": "camera-stream-bootstrap-offline/1", "nonce": prod["nonce"],
                "job_dir": prod["job_dir"], "target": prod["target"],
                "production_worker_job": str(worker.relative_to(ROOT)),
                "tiny_worker_job": str(test.relative_to(ROOT)),
                "production_debug_worker_sha256": prod["worker_sha256"],
                "compact_worker_sha256": hashlib.sha256(compact).hexdigest(),
                "loaded_worker_bytes_preserved_except_section_header": True,
                "job_header_sha256": sha(out / "job.h"), "module": module,
                "bootstrap_source_sha256": sha(NATIVE / "bootstrap.c"),
                "linux_helpers_sha256": sha(NATIVE / "linux_a64.h"),
                "builder_sha256": sha(Path(__file__)), "compiler_sha256": sha(compiler),
                "tiny_cases": len(tr["tests"]), "production_rejection_cases": len(pr["tests"]),
                "hardware_acceptance": False, "bootstrap_CPU_emulated": False,
                "admission": "OFFLINE_CANDIDATE_NO_DEVICE_EXECUTION",
                "uploads": 0, "block_writes": False, "NOR_access": False}
    (out / "bootstrap.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"output": str(out), "module_bytes": module["size"],
                      "module_sha256": module["sha256"], "hardware_acceptance": False}))


if __name__ == "__main__":
    main()
