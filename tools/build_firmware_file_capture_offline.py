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
from camera_firmware_capture import JOBS, profile
from camera_inventory import COMMIT, NATIVE, UPSTREAM, inspect

TEMPLATE_SHA = "7e081a19bd7de8e49f6a6910b0e5caa56c98e0788b06ec270f2fd474cd8357f6"


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def derived_source(name="pre_app"):
    path = ROOT / "native/stream_backup.c"
    if sha(path) != TEMPLATE_SHA:
        raise ValueError("Physically validated pilot template changed")
    text = path.read_text()
    prefix = text[text.index("#define _start"):text.index("/* --- fixed pilot identity")]
    tail = text[text.index("#define READ_STEP"):]
    if profile(name).source_kind == "BLOCK":
        return ('/* Fixed P1 block readback; validated pilot runtime preserved. */\n' +
                prefix + '#include "target.h"\n' + tail)
    begin = tail.index("static i64 open_and_validate(void)")
    end = tail.index("/* poll JOB_DIR/ack", begin)
    gate = r"""/* Linux aarch64 struct stat: dev/ino/mode/nlink/uid/gid/rdev/size/times.
 * Identity equality is an observation, not a filesystem lock or atomic snapshot.
 * O_NOFOLLOW prevents the fixed final component from being a symlink.
 */
static u8 original_stat[128];
static int stat_valid(const u8 *s) {
    return ((*(const u32*)(s+16)&0170000)==0100000 && *(const u64*)(s+48)==PART_SIZE);
}
static int stat_equal(const u8 *a,const u8 *b) {
    return same(a,b,32) && same(a+48,b+48,8) && same(a+88,b+88,32);
}
static i64 verify_identity(void) {
    i64 r=sc(80,source,(i64)st,0,0,0,0); if(r)return r;
    if(!stat_valid(st)||!stat_equal(original_stat,st))return -22;
    i64 fd=op(PART_PATH,A64_READ|0x20000,0); if(fd<0)return fd;
    u8 reopened[128]; r=sc(80,fd,(i64)reopened,0,0,0,0);
    i64 c=cl(fd); if(r)return r;if(c)return c;
    return stat_valid(reopened)&&stat_equal(original_stat,reopened)?0:-22;
}
static i64 open_and_validate(void) {
    source=op(PART_PATH,A64_READ|0x20000,0);if(source<0)return source;
    i64 r=sc(80,source,(i64)original_stat,0,0,0,0);if(r)return r;
    if(!stat_valid(original_stat))return -22;
    r=verify_identity();if(r)return r;
    sr.flags|=8;return 0;
}

"""
    tail = tail[:begin] + gate + tail[end:]
    tail = tail.replace("sha_final(&h1,sr.first); sr.flags|=16;", "sha_final(&h1,sr.first); sr.flags|=16;\n    sr.error=verify_identity();if(sr.error)goto done;")
    tail = tail.replace("sha_final(&h2,sr.second);", "sha_final(&h2,sr.second);\n    sr.error=verify_identity();if(sr.error)goto done;")
    return "/* Fixed regular file capture, derived from hash-pinned pilot. */\n" + prefix + '#include "target.h"\n' + tail


def target_header(p):
    if p.source_kind == "BLOCK":
        if p.name != "post_p1" or p.path != "/dev/cnflasha1" or p.minor != 129 or p.size != 25100288:
            raise ValueError("Only fixed post-install P1 block admitted")
        return (f'#ifdef STREAM_TEST_IMAGE\n#define PART_SIZE {p.tiny_size}UL\n'
                f'#define SECTORS_STR "{p.tiny_size // 512}\\n"\n#define CHUNK 4096UL\n'
                f'#else\n#define PART_SIZE {p.size}UL\n'
                f'#define SECTORS_STR "{p.size // 512}\\n"\n#define CHUNK 8388608UL\n#endif\n'
                f'#define PART_PATH "{p.path}"\n#define PART_RDEV {(252 << 8) | p.minor}UL\n'
                '#define SYS_DEV "/sys/class/block/cnflasha1/dev"\n'
                '#define DEV_STR "252:129\\n"\n'
                '#define SYS_SIZE "/sys/class/block/cnflasha1/size"\n')
    return (f'#ifdef STREAM_TEST_IMAGE\n#define PART_SIZE {p.tiny_size}UL\n#define CHUNK 4096UL\n'
            f'#else\n#define PART_SIZE {p.size}UL\n#define CHUNK 8388608UL\n#endif\n'
            f'#define PART_PATH "{p.path}"\n')


def build(name, out, test_image=False):
    p = profile(name)
    if subprocess.check_output(["git", "-C", str(UPSTREAM), "rev-parse", "HEAD"],
                               text=True).strip() != COMMIT:
        raise ValueError("Helper revision changed")
    if subprocess.check_output(["git", "-C", str(UPSTREAM), "status", "--porcelain"]):
        raise ValueError("Helper checkout dirty")
    text = derived_source(name)
    out = Path(out).resolve()
    out.mkdir(mode=0o700, parents=True)
    nonce = secrets.token_bytes(16)
    directory = "/tmp_wbshd/m4stream_" + nonce.hex()
    header = '#define JOB_DIR "' + directory + '"\n'
    header += 'static const unsigned char job_nonce[]={' + ','.join(map(str, nonce)) + '};\n'
    (out / "job.h").write_text(header)
    (out / "target.h").write_text(target_header(p))
    (out / "firmware_file_capture.c").write_text(text)
    compiler = ROOT / "local/zig-aarch64-macos-0.15.2/zig"
    args = [str(compiler), "cc", "-target", "aarch64-linux-gnu", "-mcpu=generic", "-Os", "-g",
            "-ffreestanding", "-fno-builtin", "-fno-stack-protector", "-fno-unwind-tables",
            "-fno-asynchronous-unwind-tables", "-nostdlib", "-ffunction-sections", "-fdata-sections",
            "-Wl,--gc-sections", "-Wl,--no-undefined", "-Wl,--build-id=none", "-Wl,-z,noexecstack",
            "-Wl,-z,max-page-size=4096", "-Wl,-z,common-page-size=4096", "-static", "-fno-pic",
            "-Wl,-e,_start", "-I", str(out), "-I", str(NATIVE), "-I", str(NATIVE.parent / "writer")]
    if test_image:
        args.append("-DSTREAM_TEST_IMAGE=1")
    args += [str(out / "firmware_file_capture.c"), "-o", str(out / "worker.debug.elf")]
    result = subprocess.run(args, capture_output=True, text=True, timeout=120)
    (out / "compile.log").write_text(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError(result.stderr[-3000:])
    shared = [ROOT / "native/stream_backup.c", Path(__file__), ROOT / "camera_firmware_capture.py",
              ROOT / "camera_inventory.py", ROOT / "tools/firmware_file_capture_assets.py", NATIVE / "lifecycle_worker.c", NATIVE / "linux_a64.h",
              NATIVE.parent / "writer/sha256.h"]
    shared_sources = {str(path.relative_to(ROOT)): sha(path) for path in shared}
    generated = {str((out / name).relative_to(ROOT)): sha(out / name)
                 for name in ("job.h", "target.h", "firmware_file_capture.c")}
    meta = {"schema": "camera-firmware-file-offline-worker/1", "nonce": nonce.hex(), "job_dir": directory,
            "test_image": bool(test_image), "profile": p.name,
            "source_kind": p.source_kind, "targetpath": p.path, "expected_sha256": p.sha256,
            "target": [p.name, p.minor, p.tiny_size if test_image else p.size],
            "chunk_bytes": 4096 if test_image else 8388608,
            "sources": shared_sources | generated, "shared_sources": shared_sources,
            "header_sha256": sha(out / "job.h"), "target_header_sha256": sha(out / "target.h"),
            "derived_source_sha256": sha(out / "firmware_file_capture.c"),
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
    p.add_argument("--target", choices=list(JOBS), required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--test-image", action="store_true")
    p.add_argument("--bundle", action="store_true", help="Build tiny/prod, emulate each, and prepare bootstrap")
    a = p.parse_args()
    if a.bundle:
        if a.test_image:
            p.error("--bundle already builds both geometries")
        for suffix, tiny in (("tiny", True), ("prod", False)):
            directory = a.output / suffix
            build(a.target, directory, tiny)
            subprocess.run([sys.executable, str(ROOT / "tools/emulate_firmware_file_capture_offline.py"),
                            "--job", str(directory)], check=True)
        subprocess.run([sys.executable, str(ROOT / "tools/firmware_file_capture_bootstrap.py"),
                        "--worker-job", str(a.output / "prod"), "--test-job", str(a.output / "tiny"),
                        "--output", str(a.output / "bootstrap")], check=True)
    else:
        build(a.target, a.output, a.test_image)


if __name__ == "__main__":
    main()
