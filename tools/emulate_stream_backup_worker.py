"""Execute the exact offline ARM64 worker against a synthetic syscall model.

This verifies worker control flow, not USB transport, real filesystem behavior,
physical-device geometry, kernel scheduling, or restoration.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from camera_stream_receiver import ACK, RECORD
from camera_inventory import sha, require
from emulate_inventory import entry
from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_INTR
from unicorn.arm64_const import UC_ARM64_REG_SP, UC_ARM64_REG_X0, UC_ARM64_REG_X8


def emulate(job, scenario):
    meta = json.loads((job / "job.json").read_text())
    directory = meta["job_dir"]
    size, chunk = meta["target"][2], meta["chunk_bytes"]
    nonce = bytes.fromhex(meta["nonce"])
    u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    with (job / "worker.debug.elf").open("rb") as f:
        elf = ELFFile(f)
        pages = set()
        for s in elf.iter_segments():
            if s["p_type"] == "PT_LOAD":
                pages.update(range(s["p_vaddr"] & ~4095,
                                   (s["p_vaddr"] + s["p_memsz"] + 4095) & ~4095, 4096))
        ranges = []
        for page in sorted(pages):
            if ranges and ranges[-1][1] == page:
                ranges[-1][1] += 4096
            else:
                ranges.append([page, page + 4096])
        for first, last in ranges:
            u.mem_map(first, last - first)
        for s in elf.iter_segments():
            if s["p_type"] == "PT_LOAD":
                u.mem_write(s["p_vaddr"], s.data())
        start = elf["e_entry"]
    stack = 0x80000000
    u.mem_map(stack, 0x100000)
    sp = stack + 0x80000
    u.reg_write(UC_ARM64_REG_SP, sp)
    u.mem_write(sp, struct.pack("<4Q", 2, sp + 256, sp + 300, 0))
    u.mem_write(sp + 256, b"worker\0")
    u.mem_write(sp + 300, b"123\0")
    files = {directory + "/worker": b"x",
             directory + "/start": b"M4START1" + nonce + struct.pack("<Q", 1),
             "/proc/123/maps": b"1000 r-x /usr/lib/libJiritsu.so\n",
             "/sys/class/block/cnflasha7/dev": b"252:135\n",
             "/sys/class/block/cnflasha7/size": f"{size // 512}\n".encode()}
    if scenario == "bad_sysfs":
        files["/sys/class/block/cnflasha7/dev"] = b"252:136\n"
    preserved = {}
    if scenario.startswith("existing_"):
        suffix = {"existing_data": "chunk.bin", "existing_temp": "chunk.tmp",
                  "existing_record": "chunk.ready", "existing_done": "done"}[scenario]
        preserved[directory + "/" + suffix] = b"KEEP_EXISTING"
        files.update(preserved)
    fds, dirs, opened, calls, published = {}, {}, [], [], []
    state = {"next": 3, "clock": 1, "exit": None, "read_bytes": 0,
             "ack": None, "done": None}

    def text(ptr):
        raw = bytes(u.mem_read(ptr, 1024))
        require(b"\0" in raw, "String bound")
        return raw.split(b"\0", 1)[0].decode()

    def ret(value):
        u.reg_write(UC_ARM64_REG_X0, value & ((1 << 64) - 1))

    def observe(path):
        raw = files[path]
        if raw.startswith(b"M4CHNK01"):
            magic, n, index, offset, length, digest = RECORD.unpack(raw)
            payload = files.get(directory + "/chunk.bin")
            require(payload is not None, "Chunk record visible before data")
            require(n == nonce and index == len(published) and offset == index * chunk,
                    "Published identity/order mismatch")
            require(length == min(chunk, size - offset) and len(payload) == length,
                    "Published geometry mismatch")
            require(hashlib.sha256(payload).digest() == digest, "Published chunk hash mismatch")
            published.append((offset, bytes(payload)))
            state["ack"] = ACK.pack(b"M4SACK01", nonce, index, digest)
            if scenario == "bad_ack":
                state["ack"] = ACK.pack(b"M4SACK01", nonce, index + 1, digest)
            elif scenario == "wrong_ack_nonce":
                state["ack"] = ACK.pack(b"M4SACK01", b"X" * 16, index, digest)
            elif scenario == "wrong_ack_hash":
                state["ack"] = ACK.pack(b"M4SACK01", nonce, index, b"X" * 32)
            elif scenario == "short_ack":
                state["ack"] = state["ack"][:-1]
        elif raw.startswith(b"M4DONE01"):
            state["done"] = RECORD.unpack(raw)

    def syscall(_u, _n, _data):
        no = u.reg_read(UC_ARM64_REG_X8)
        a, b, c, d, e, f = [u.reg_read(UC_ARM64_REG_X0 + i) for i in range(6)]
        calls.append(no)
        if no == 56:
            path = text(b)
            opened.append((path, c))
            writing = c & 3
            if writing:
                require(path.startswith(directory + "/") and c == 0x880c1,
                        "Writable source or unexpected create flags")
                if path in files:
                    ret(-17); return
                files[path] = b""
            else:
                require(c in (0x88000, 0x8c000), "Unexpected read flags")
                if path == "/proc/self/fd":
                    dirs[path] = entry(".", 4) + entry(str(state["next"]))
                if path == "/proc/123/fd":
                    dirs[path] = entry(".", 4) + entry("0")
                if path.endswith("/ack") and state["ack"] is not None and scenario != "no_ack":
                    files[path] = state["ack"]
                if path not in files and path not in dirs and path != "/dev/cnflasha7":
                    ret(-2); return
            fd = state["next"]
            state["next"] += 1
            fds[fd] = [path, 0, writing]
            ret(fd)
        elif no == 57:
            closed = fds.pop(a, None)
            ret(-5 if closed and closed[0] == "/dev/cnflasha7" and scenario == "close_error" else 0)
        elif no in (61, 63):
            path, pos, _ = fds[a]
            raw = (dirs if no == 61 else files)[path]
            n = min(c, len(raw) - pos)
            if scenario == "short_reads" and no == 63:
                n = min(n, 31)
            if n:
                u.mem_write(b, raw[pos:pos + n])
            fds[a][1] += n
            ret(n)
        elif no == 64:
            path, _, writing = fds[a]
            require(writing and path.startswith(directory + "/"), "Write outside job")
            files[path] += bytes(u.mem_read(b, c)); ret(c)
        elif no == 276:
            old, new = text(b), text(d)
            require(old.startswith(directory + "/") and new.startswith(directory + "/")
                    and e == 1, "Only fixed-job RENAME_NOREPLACE allowed")
            if scenario == "rename_unsupported":
                ret(-38); return
            if new in files:
                ret(-17); return
            files[new] = files.pop(old)
            observe(new)
            ret(0)
        elif no == 35:
            path = text(b)
            require(path.startswith(directory + "/"), "Unlink outside job")
            if path in files:
                del files[path]
                if path.endswith("/ack"):
                    state["ack"] = None
                ret(0)
            else:
                ret(-2)
        elif no == 43:
            require(text(a) == "/tmp_wbshd", "Wrong statfs")
            free = 1 if scenario == "low_tmpfs" else 100000
            u.mem_write(b, struct.pack("<15q", 0x1021994, 4096, 100000, free, free,
                                      0, 0, 0, 255, 4096, 0, 0, 0, 0, 0)); ret(0)
        elif no == 80:
            require(fds[a][0] == "/dev/cnflasha7", "Non-source fstat")
            raw = bytearray(128)
            struct.pack_into("<I", raw, 16, 0o020600 if scenario == "not_block" else 0o060600)
            struct.pack_into("<Q", raw, 32, (252 << 8) | (136 if scenario == "wrong_device" else 135))
            u.mem_write(b, bytes(raw)); ret(0)
        elif no == 29:
            require(fds[a][0] == "/dev/cnflasha7" and b == 0x80081272,
                    "Only source BLKGETSIZE64 allowed")
            u.mem_write(c, struct.pack("<Q", size + (512 if scenario == "wrong_size" else 0))); ret(0)
        elif no == 67:
            require(fds[a][0] == "/dev/cnflasha7" and not fds[a][2], "Writable source read")
            require(c <= 65536 and d + c <= size, "Source bounds exceeded")
            if scenario == "read_error":
                ret(-5); return
            n = min(c, 31) if scenario == "short_reads" else c
            raw = bytes(((d + i) * 7 + 3) & 255 for i in range(n))
            if scenario == "changed_second_read" and state["read_bytes"] >= size:
                raw = bytes([raw[0] ^ 1]) + raw[1:]
            state["read_bytes"] += n
            u.mem_write(b, raw); ret(n)
        elif no == 78:
            require(fds[a][0] == "/proc/123/fd", "Wrong readlink")
            u.mem_write(c, b"/dev/null"); ret(9)
        elif no == 175:
            ret(1000 if scenario == "not_root" else 0)
        elif no == 172:
            ret(234)
        elif no == 173:
            ret(1)
        elif no == 113:
            u.mem_write(b, struct.pack("<2q", state["clock"], 0))
            state["clock"] += 1
            ret(0)
        elif no == 101:
            ret(0)
        elif no == 94:
            state["exit"] = a; u.emu_stop()
        else:
            raise RuntimeError(f"Unapproved syscall {no}")

    u.hook_add(UC_HOOK_INTR, syscall)
    u.emu_start(start, 0, count=20000000)
    require(state["exit"] is not None, "Instruction budget exceeded")
    success = scenario in ("success", "short_reads")
    require((state["exit"] == 0) == success, f"Unexpected native result for {scenario}")
    if success:
        expected = bytes((i * 7 + 3) & 255 for i in range(size))
        require(b"".join(data for _, data in published) == expected, "Incomplete stream")
        require(state["read_bytes"] == 2 * size, "Not two independent full source reads")
        done = state["done"]
        require(done is not None and done[1] == nonce and done[2:5] == (len(published), size, 0)
                and done[5] == hashlib.sha256(expected).digest(), "Final record mismatch")
    else:
        require(state["done"] is None or state["done"][4] != 0, "Failure published success")
    require(all(flags & 3 == 0 for path, flags in opened if path.startswith("/dev/")),
            "Block opened writable")
    require(all(files.get(path) == raw for path, raw in preserved.items()),
            "Preexisting/unowned file changed")
    require(not any(path in files and path not in preserved for path in
                    (directory + "/chunk.bin", directory + "/chunk.ready", directory + "/chunk.tmp")),
            "Owned staging files leaked")
    if scenario in ("not_root", "bad_sysfs", "not_block", "wrong_device", "wrong_size",
                    "low_tmpfs", "read_error"):
        require(state["read_bytes"] == 0, "Admission failure consumed source bytes")
    return {"scenario": scenario, "passed": True, "syscalls": sorted(set(calls)),
            "source_bytes_read": state["read_bytes"], "published_chunks": len(published)}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--job", type=Path, required=True)
    a = p.parse_args()
    meta = json.loads((a.job / "job.json").read_text())
    require(sha(a.job / "worker.debug.elf") == meta["worker_sha256"], "Worker changed")
    require(all(sha(ROOT / name) == digest for name, digest in meta["sources"].items()),
            "Sources changed; rebuild")
    tests = []
    cases = (("success", "short_reads", "changed_second_read", "bad_ack", "no_ack",
              "wrong_ack_nonce", "wrong_ack_hash", "short_ack", "close_error",
              "existing_data", "existing_temp", "existing_record", "existing_done",
              "bad_sysfs", "not_block", "wrong_device", "wrong_size", "read_error",
              "not_root", "low_tmpfs", "rename_unsupported") if meta["test_image"] else
             ("not_root", "bad_sysfs", "not_block", "wrong_device", "wrong_size",
              "read_error", "low_tmpfs"))
    for case in cases:
        tests.append(emulate(a.job, case))
        print(case + " passed", flush=True)
    report = {"all_passed": True, "worker_sha256": meta["worker_sha256"], "tests": tests,
              "emulator_sha256": sha(Path(__file__)), "hardware_acceptance": False,
              "full_size_success_emulated": False, "test_image": meta["test_image"]}
    (a.job / "emulation.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
