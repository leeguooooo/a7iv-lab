"""Build only the offline ARM64 worker. No bootstrap, USB, or run command."""
import argparse
import hashlib
import json
from pathlib import Path
import secrets
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from camera_inventory import COMMIT, NATIVE, UPSTREAM, inspect


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--test-image", action="store_true")
    a = p.parse_args()
    if subprocess.check_output(["git", "-C", str(UPSTREAM), "rev-parse", "HEAD"],
                               text=True).strip() != COMMIT:
        raise RuntimeError("Pinned helper revision changed")
    if subprocess.check_output(["git", "-C", str(UPSTREAM), "status", "--porcelain"]):
        raise RuntimeError("Helper checkout is dirty")
    out = a.output.resolve()
    out.mkdir(mode=0o700)
    nonce = secrets.token_bytes(16)
    directory = "/tmp_wbshd/m4stream_" + nonce.hex()
    header = '#define JOB_DIR "' + directory + '"\n'
    header += "static const unsigned char job_nonce[]={" + ",".join(map(str, nonce)) + "};\n"
    (out / "job.h").write_text(header)
    compiler = ROOT / "local/zig-aarch64-macos-0.15.2/zig"
    args = [str(compiler), "cc", "-target", "aarch64-linux-gnu", "-mcpu=generic",
            "-Os", "-g", "-ffreestanding", "-fno-builtin", "-fno-stack-protector",
            "-fno-unwind-tables", "-fno-asynchronous-unwind-tables", "-nostdlib",
            "-ffunction-sections", "-fdata-sections", "-Wl,--gc-sections",
            "-Wl,--no-undefined", "-Wl,--build-id=none", "-Wl,-z,noexecstack",
            "-Wl,-z,max-page-size=4096", "-Wl,-z,common-page-size=4096",
            "-static", "-fno-pic", "-Wl,-e,_start", "-I", str(out),
            "-I", str(NATIVE), "-I", str(NATIVE.parent / "writer")]
    if a.test_image:
        args += ["-DSTREAM_TEST_IMAGE=1"]
    args += [str(ROOT / "native/stream_backup.c"), "-o", str(out / "worker.debug.elf")]
    result = subprocess.run(args, capture_output=True, text=True, timeout=120)
    (out / "compile.log").write_text(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError(result.stderr[-3000:])
    sources = [ROOT / "native/stream_backup.c", Path(__file__), ROOT / "camera_inventory.py",
               NATIVE / "lifecycle_worker.c", NATIVE / "linux_a64.h",
               NATIVE.parent / "writer/sha256.h"]
    manifest = {"schema": "camera-stream-offline-worker/1", "nonce": nonce.hex(),
                "job_dir": directory, "test_image": a.test_image,
                "target": ["cnflasha7", 135, 8192 if a.test_image else 16777216],
                "chunk_bytes": 4096 if a.test_image else 8388608,
                "sources": {str(x.relative_to(ROOT)): sha(x) for x in sources},
                "compiler_sha256": sha(compiler), "header_sha256": sha(out / "job.h"),
                "worker": inspect(out / "worker.debug.elf", True),
                "worker_sha256": sha(out / "worker.debug.elf"),
                "admission": "OFFLINE_ONLY_NO_BOOTSTRAP_OR_EXECUTOR",
                "hardware_acceptance": False, "restore_verified": False}
    (out / "job.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"output": str(out), "test_image": a.test_image,
                      "worker_sha256": manifest["worker_sha256"]}))


if __name__ == "__main__":
    main()
