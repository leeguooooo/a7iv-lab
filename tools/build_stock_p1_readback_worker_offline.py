# Derived OFFLINE for fixed cn1 only; donor build_remaining_backup_worker.py SHA256 fc326f129f0abb0c3a114912ad92f0d25d7b457b151eed7464fdafe662fbc812
"""Build one fixed remaining-partition worker OFFLINE. No camera execution."""
import argparse
import hashlib
import json
from pathlib import Path
import secrets
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from camera_stream_profiles import RemainingProfile
PROFILES = (RemainingProfile("cnflasha1", 129, 25100288, 9728),)

def profile(name):
    if name != "cnflasha1":
        raise ValueError("Only fixed P1 readback admitted")
    return PROFILES[0]

from camera_inventory import COMMIT, NATIVE, UPSTREAM, inspect

TEMPLATE_SHA = "7e081a19bd7de8e49f6a6910b0e5caa56c98e0788b06ec270f2fd474cd8357f6"


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def derived_source():
    path = ROOT / "native/stream_backup.c"
    if sha(path) != TEMPLATE_SHA:
        raise ValueError("Physically validated pilot template changed")
    text = path.read_text()
    prefix = text[text.index("#define _start"):text.index("/* --- fixed pilot identity")]
    tail = text[text.index("#define READ_STEP"):]
    return ('/* Fixed remaining target; runtime body preserved from validated pilot. */\n' +
            prefix + '#include "target.h"\n' + tail)


def target_header(p):
    return (f'#ifdef STREAM_TEST_IMAGE\n#define PART_SIZE {p.tiny_size}UL\n'
            f'#define SECTORS_STR "{p.tiny_size // 512}\\n"\n#define CHUNK 4096UL\n'
            f'#else\n#define PART_SIZE {p.size}UL\n'
            f'#define SECTORS_STR "{p.size // 512}\\n"\n#define CHUNK 8388608UL\n#endif\n'
            f'#define PART_PATH "/dev/{p.name}"\n#define PART_RDEV {(252 << 8) | p.minor}UL\n'
            f'#define SYS_DEV "/sys/class/block/{p.name}/dev"\n'
            f'#define DEV_STR "252:{p.minor}\\n"\n'
            f'#define SYS_SIZE "/sys/class/block/{p.name}/size"\n')


def build(name, out, test_image=False):
    p = profile(name)
    if subprocess.check_output(["git", "-C", str(UPSTREAM), "rev-parse", "HEAD"],
                               text=True).strip() != COMMIT:
        raise ValueError("Helper revision changed")
    if subprocess.check_output(["git", "-C", str(UPSTREAM), "status", "--porcelain"]):
        raise ValueError("Helper checkout dirty")
    text = derived_source()
    out = Path(out).resolve()
    out.mkdir(mode=0o700, parents=True, exist_ok=False)
    nonce = secrets.token_bytes(16)
    directory = "/tmp_wbshd/m4stream_" + nonce.hex()
    header = '#define JOB_DIR "' + directory + '"\n'
    header += 'static const unsigned char job_nonce[]={' + ','.join(map(str, nonce)) + '};\n'
    (out / "job.h").write_text(header)
    (out / "target.h").write_text(target_header(p))
    (out / "stream_backup_remaining.c").write_text(text)
    compiler = ROOT / "local/zig-aarch64-macos-0.15.2/zig"
    args = [str(compiler), "cc", "-target", "aarch64-linux-gnu", "-mcpu=generic", "-Os", "-g",
            "-ffreestanding", "-fno-builtin", "-fno-stack-protector", "-fno-unwind-tables",
            "-fno-asynchronous-unwind-tables", "-nostdlib", "-ffunction-sections", "-fdata-sections",
            "-Wl,--gc-sections", "-Wl,--no-undefined", "-Wl,--build-id=none", "-Wl,-z,noexecstack",
            "-Wl,-z,max-page-size=4096", "-Wl,-z,common-page-size=4096", "-static", "-fno-pic",
            "-Wl,-e,_start", "-I", str(out), "-I", str(NATIVE), "-I", str(NATIVE.parent / "writer")]
    if test_image:
        args.append("-DSTREAM_TEST_IMAGE=1")
    args += [str(out / "stream_backup_remaining.c"), "-o", str(out / "worker.debug.elf")]
    result = subprocess.run(args, capture_output=True, text=True, timeout=120)
    (out / "compile.log").write_text(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError(result.stderr[-3000:])
    shared = [ROOT / "native/stream_backup.c", Path(__file__), ROOT / "camera_stream_profiles.py",
              ROOT / "camera_inventory.py", NATIVE / "lifecycle_worker.c", NATIVE / "linux_a64.h",
              NATIVE.parent / "writer/sha256.h"]
    shared_sources = {str(path.relative_to(ROOT)): sha(path) for path in shared}
    generated = {str((out / name).relative_to(ROOT)): sha(out / name)
                 for name in ("job.h", "target.h", "stream_backup_remaining.c")}
    meta = {"schema": "camera-stock-p1-readback-offline-worker/1", "nonce": nonce.hex(), "job_dir": directory,
            "test_image": bool(test_image), "profile": p.name,
            "target": [p.name, p.minor, p.tiny_size if test_image else p.size],
            "chunk_bytes": 4096 if test_image else 8388608,
            "sources": shared_sources | generated, "shared_sources": shared_sources,
            "header_sha256": sha(out / "job.h"), "target_header_sha256": sha(out / "target.h"),
            "derived_source_sha256": sha(out / "stream_backup_remaining.c"),
            "reference_pilot_template_sha256": TEMPLATE_SHA,
            "compiler_sha256": sha(compiler), "worker": inspect(out / "worker.debug.elf", True),
            "worker_sha256": sha(out / "worker.debug.elf"), "hardware_acceptance": False,
            "admission": "OFFLINE_FIXED_TARGET_NO_EXECUTOR", "direct_block_node_writes": False,
            "DMA": False, "NOR": False, "restoration_verified": False}
    (out / "job.json").write_text(json.dumps(meta, indent=2) + "\n")
    print(json.dumps({"output": str(out.relative_to(ROOT)), "target": meta["target"],
                      "test_image": bool(test_image), "worker_sha256": meta["worker_sha256"]}), flush=True)
    return meta


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--target", choices=[p.name for p in PROFILES], required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--test-image", action="store_true")
    a = p.parse_args()
    build(a.target, a.output, a.test_image)


if __name__ == "__main__":
    main()
