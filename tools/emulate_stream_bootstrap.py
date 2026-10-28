"""Run the exact bootstrap initializer under a synthetic AArch64 syscall OS.

Fork branches are modeled separately; this is not a live loader/scheduler test.
execve is observed and stopped, not delegated to a real OS or camera.
"""
import argparse
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from camera_inventory import LAUNCH, NATIVE, require, sha
from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_INTR
from unicorn.arm64_const import UC_ARM64_REG_SP, UC_ARM64_REG_LR, UC_ARM64_REG_X0, UC_ARM64_REG_X8


def emulate(job, scenario):
    meta = json.loads((job / "bootstrap.json").read_text())
    directory = meta["job_dir"]
    compact = (job / "worker.elf").read_bytes()
    base, sentinel, stack = 0x40000000, 0x90000000, 0x80000000
    u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    with (job / "libJit.so").open("rb") as f:
        elf = ELFFile(f)
        pages = set()
        for segment in elf.iter_segments():
            if segment["p_type"] == "PT_LOAD":
                pages.update(range((base + segment["p_vaddr"]) & ~4095,
                                   (base + segment["p_vaddr"] + segment["p_memsz"] + 4095) & ~4095, 4096))
        for page in sorted(pages):
            u.mem_map(page, 4096)
        for segment in elf.iter_segments():
            if segment["p_type"] == "PT_LOAD":
                u.mem_write(base + segment["p_vaddr"], segment.data())
        for section in elf.iter_sections():
            if section["sh_type"] == "SHT_RELA":
                for relocation in section.iter_relocations():
                    require(relocation["r_info_type"] == 1027, "Only relative relocations admitted")
                    u.mem_write(base + relocation["r_offset"],
                                struct.pack("<Q", base + relocation["r_addend"]))
    u.mem_map(stack, 0x100000)
    u.mem_map(sentinel, 4096)
    u.reg_write(UC_ARM64_REG_SP, stack + 0x80000)
    u.reg_write(UC_ARM64_REG_LR, sentinel)
    files = {"/tmp/jiritsu/libJit.so": b"uploaded_module"}
    preserved = {}
    if scenario == "existing_worker":
        preserved[directory + "/worker"] = b"KEEP_EXISTING"
        files.update(preserved)
    fds, calls = {}, []
    state = {"next": 3, "clone": 0, "wait": 0, "exec": False, "exit": None}

    def text(ptr):
        raw = bytes(u.mem_read(ptr, 1024))
        require(b"\0" in raw, "String bound")
        return raw.split(b"\0", 1)[0].decode()

    def ret(value):
        u.reg_write(UC_ARM64_REG_X0, value & ((1 << 64) - 1))

    def syscall(_u, _n, _d):
        no = u.reg_read(UC_ARM64_REG_X8)
        a, b, c, d, e, f = [u.reg_read(UC_ARM64_REG_X0 + i) for i in range(6)]
        calls.append(no)
        if no == 175:
            ret(1000 if scenario == "not_root" else 0)
        elif no == 172:
            ret(123)
        elif no == 35:
            path = text(b)
            require(path == "/tmp/jiritsu/libJit.so", "Unexpected bootstrap unlink")
            if scenario == "unlink_error":
                ret(-13); return
            del files[path]; ret(0)
        elif no == 43:
            require(text(a) == "/tmp_wbshd", "Wrong statfs")
            fs_type = 0 if scenario == "wrong_fs" else 0x1021994
            free = 1 if scenario == "low_tmpfs" else 100000
            u.mem_write(b, struct.pack("<15q", fs_type, 4096, 100000, free, free,
                                      0, 0, 0, 255, 4096, 0, 0, 0, 0, 0)); ret(0)
        elif no == 34:
            require(text(b) == directory and c == 0o700, "Unexpected mkdir")
            ret(-17 if scenario == "existing_job" else 0)
        elif no == 56:
            path = text(b)
            require(path in (directory + "/worker", directory + "/launch", directory + "/exec_failure")
                    and c == 0x880c1, "Unexpected writable path/flags")
            require(d == (0o700 if path.endswith("/worker") else 0o600), "Unexpected file mode")
            if path in files:
                ret(-17); return
            files[path] = b""
            fd = state["next"]
            state["next"] += 1
            fds[fd] = path
            ret(fd)
        elif no == 64:
            path = fds[a]
            if scenario == "write_error" and path.endswith("/worker"):
                ret(-28); return
            n = min(c, 31) if scenario == "short_write" else c
            files[path] += bytes(u.mem_read(b, n)); ret(n)
        elif no == 57:
            fds.pop(a, None); ret(0)
        elif no == 220:
            require(a == 17 and not any((b, c, d, e, f)), "Unexpected clone flags/arguments")
            state["clone"] += 1
            if scenario == "fork_error":
                ret(-11)
            elif scenario in ("intermediate", "grandchild_exec", "exec_error", "setsid_error"):
                ret(0 if state["clone"] == 1 or scenario != "intermediate" else 345)
            else:
                ret(234)
        elif no == 157:
            ret(-1 if scenario == "setsid_error" else 234)
        elif no == 260:
            require(a == 234 and not any((c, d, e, f)), "Wait only for intermediate")
            state["wait"] += 1
            if scenario == "wait_eintr" and state["wait"] == 1:
                ret(-4); return
            u.mem_write(b, struct.pack("<I", 256 if scenario == "wait_status_error" else 0))
            ret(234)
        elif no == 221:
            require(text(a) == directory + "/worker" and c == 0, "Unexpected exec target/environment")
            argv = struct.unpack("<3Q", bytes(u.mem_read(b, 24)))
            require(text(argv[0]) == directory + "/worker" and text(argv[1]) == "123" and argv[2] == 0,
                    "Exec argv binding mismatch")
            require(files[directory + "/worker"] == compact, "Exec worker differs from validated blob")
            if scenario == "exec_error":
                ret(-8)
            else:
                state["exec"] = True; u.emu_stop()
        elif no == 94:
            state["exit"] = a; u.emu_stop()
        else:
            raise RuntimeError(f"Unapproved bootstrap syscall {no}")

    u.hook_add(UC_HOOK_INTR, syscall)
    u.emu_start(base + meta["module"]["init"], sentinel, count=5000000)
    launch = files.get(directory + "/launch")
    if scenario in ("success", "wait_eintr"):
        require(launch is not None, "Missing parent launch result")
        values = LAUNCH.unpack(launch)
        require(values[:3] == (b"M4BOOT01", bytes.fromhex(meta["nonce"]), 1)
                and values[3:6] == (3, 0, 0) and values[8:11] == (234, 234, 0), "Launch result mismatch")
        require(files[directory + "/worker"] == compact, "Written worker blob mismatch")
    elif scenario == "grandchild_exec":
        require(state["exec"], "Exec path not reached")
    elif scenario == "intermediate":
        require(state["exit"] == 0 and not state["exec"], "Intermediate did not exit cleanly")
    elif scenario in ("exec_error", "setsid_error"):
        require(state["exit"] == 1 and not state["exec"], "Child failure was not terminal")
        if scenario == "exec_error":
            require(files[directory + "/exec_failure"] == struct.pack("<q", -8), "Exec failure record mismatch")
    elif launch is not None:
        values = LAUNCH.unpack(launch)
        require(values[4] != 0 or values[3] != 3, "Error published parent success")
    else:
        require(state["clone"] == 0 and not state["exec"], "Admission failure continued to fork")
    require(all(files.get(path) == raw for path, raw in preserved.items()), "Overwrote existing worker")
    require(not fds, "Bootstrap leaked file descriptors")
    return {"scenario": scenario, "passed": True, "syscalls": sorted(set(calls)),
            "exec_observed_not_executed": state["exec"]}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--job", type=Path, required=True)
    a = p.parse_args()
    meta = json.loads((a.job / "bootstrap.json").read_text())
    require(sha(a.job / "libJit.so") == meta["module"]["sha256"], "Module changed")
    require(sha(a.job / "worker.elf") == meta["compact_worker_sha256"], "Embedded worker changed")
    require(sha(NATIVE / "bootstrap.c") == meta["bootstrap_source_sha256"], "Bootstrap source changed")
    tests = []
    for case in ("success", "wait_eintr", "not_root", "unlink_error", "wrong_fs", "low_tmpfs",
                 "existing_job", "existing_worker", "write_error", "short_write", "fork_error",
                 "wait_status_error", "intermediate", "grandchild_exec", "exec_error", "setsid_error"):
        tests.append(emulate(a.job, case))
        print(case + " passed", flush=True)
    report = {"all_passed": True, "module_sha256": meta["module"]["sha256"],
              "compact_worker_sha256": meta["compact_worker_sha256"], "tests": tests,
              "emulator_sha256": sha(Path(__file__)), "hardware_acceptance": False,
              "fork_scheduler_modeled_not_executed": True}
    (a.job / "emulation.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
