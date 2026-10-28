"""Execute the compiled ARM64 inventory in Unicorn with an allowlisted fake OS."""
import argparse
import json
import struct
from pathlib import Path

from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_INTR
from unicorn.arm64_const import UC_ARM64_REG_PC, UC_ARM64_REG_SP, UC_ARM64_REG_X0, UC_ARM64_REG_X8
from camera_inventory import RESULT, decode, require, save, sha


def entry(name, kind=8):
    name = name.encode() + b"\0"
    size = (19 + len(name) + 7) & ~7
    return struct.pack("<QqHB", 1, 0, size, kind) + name + bytes(size - 19 - len(name))


def emulate(job, scenario="success"):
    meta = json.loads((job / "job.json").read_text())
    directory = meta["job_dir"]
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    with (job / "worker.debug.elf").open("rb") as f:
        elf = ELFFile(f)
        pages = set()
        for seg in elf.iter_segments():
            if seg["p_type"] == "PT_LOAD":
                pages.update(range(seg["p_vaddr"] & ~4095, (seg["p_vaddr"] + seg["p_memsz"] + 4095) & ~4095, 4096))
        for p in sorted(pages):
            uc.mem_map(p, 4096)
        for seg in elf.iter_segments():
            if seg["p_type"] == "PT_LOAD":
                uc.mem_write(seg["p_vaddr"], seg.data())
        start = elf["e_entry"]
    stack = 0x80000000
    uc.mem_map(stack, 0x100000)
    sp = stack + 0x80000
    uc.mem_write(sp, struct.pack("<4Q", 2, sp + 256, sp + 300, 0))
    uc.mem_write(sp + 256, b"worker\0")
    uc.mem_write(sp + 300, b"123\0")
    uc.reg_write(UC_ARM64_REG_SP, sp)
    files = {
        directory + "/worker": b"placeholder",
        directory + "/start": b"M4START1" + bytes.fromhex(meta["nonce"]) + struct.pack("<Q", 1),
        directory + "/ack": b"M4ACK001" + bytes.fromhex(meta["nonce"]) + struct.pack("<Q", 1),
        "/proc/123/maps": (b"1000 r-x /tmp/jiritsu/libJit.so\n" if scenario == "loader_busy" else b"1000 r-x /usr/lib/libJiritsu.so\n"),
        "/proc/version": b"Linux mock\n", "/proc/partitions": b"major minor blocks name\n",
        "/proc/self/mountinfo": b"1 0 0:1 / / rw - rootfs rootfs rw\n", "/etc/fstab": b"/dev/nflasha15 / ext4 ro 0 0\n",
        "/proc/devices": b"Block devices:\n252 nflasha\n", "/proc/cmdline": b"mock\n", "/proc/cpuinfo": b"mock\n",
        "/proc/last_kmsg": b"previous kernel trace\n", "/proc/uptime": b"123.45 22.0\n",
        "/proc/meminfo": b"MemFree: 12345 kB\n", "/proc/sys/kernel/tainted": b"0\n",
        "/log/cp.log": b"synthetic CP diagnostic record\n" * 10000,
        "/proc/klog": b"synthetic kernel log\n", "/proc/osal/uipc": b"synthetic IPC status\n",
        "/proc/udm/dmm_log": b"synthetic DMM status\n",
        "/proc/udm/dmm_rule": b"Current rule: 0\n",
        "/proc/udm/dmm_extents": b"synthetic extent owner counters\n",
        "/proc/udm/dmm_units": b"synthetic unit table\n",
        "/proc/udm/dmm_units2": b"synthetic alternate unit table\n",
        "/proc/udm/dmm_reserve": b"synthetic reservation table\n",
        "/proc/udm/dmm_info": b"synthetic DMM configuration\n",
        "/proc/iomem": b"400000000-47fffffff : System RAM\n",
        "/proc/interrupts": b"93: 1 remote\n",
        "/sys/module/backup/parameters/Backup_pri_file": b"/setting/Backup.bin\n",
        "/sys/module/backup/parameters/Backup_sec_file": b"/setting/Backup.bin\n",
        "/sys/module/backup/parameters/Backup_save": b"1\n",
        "/sys/module/backup/parameters/Backup_load": b"1\n",
        "/proc/self/status": b"Name:\tworker\nCapEff:\t0000003fffffffff\n",
        "/sys/module/mmap/parameters/debug": b"0\n",
        "/sys/module/adrs_conv/parameters/debug": b"1\n",
        "/sys/module/adrs_conv/parameters/null": b"Y\n",
        "/proc/udm/gpio": b"17DIR   : 0x00000000\n17RDATA : 0x00000000\n17IEN   : 0x00000004\n17PORT  : 0x00000004\n17WDATA : 0x00000000\n",
        "/proc/sys/kernel/modules_disabled": b"0\n",
        "/sys/module/module/parameters/sig_enforce": b"N\n",
        "/proc/sys/kernel/kptr_restrict": b"1\n",
        "/proc/modules": b"backup 40960 0 - Live 0x0000000000000000\ndmm 98304 0 - Live 0x0000000000000000\n",
    }
    if meta.get("scope") == "kernel-lease-status":
        root="/sys/module/m4btl_lease_01"
        files.update({root+"/initstate":b"live\n",
                      root+"/parameters/status":b"schema=1 profile=lease-only nonce=4d27c5e90e00ba356d6fdca7ac027bce state=ready page_bytes=4096 page_phys=0x400000000 resident=boot dma=0\n\n",
                      root+"/parameters/nonce":b"4d27c5e90e00ba356d6fdca7ac027bce\n\n",
                      root+"/parameters/state":b"2\n\n",
                      root+"/parameters/bytes":b"4096\n\n",
                      root+"/parameters/phys":b"0x400000000\n\n",
                      "/proc/sys/kernel/random/boot_id":b"12345678-1234-1234-1234-123456789abc\n"})
    if scenario == "missing_required":
        del files["/proc/partitions"]
    if scenario == "missing_optional":
        selected = "/sys/module/m4btl_lease_01/parameters/status" if meta.get("scope") == "kernel-lease-status" else "/sys/module/module/parameters/sig_enforce" if meta.get("scope") == "module-policy" else "/proc/udm/dmm_extents" if meta.get("scope") == "dmm-metadata" else "/sys/module/mmap/parameters/debug" if meta.get("scope") == "memory-access-metadata" else "/sys/module/backup/parameters/Backup_pri_file" if meta.get("scope") == "backup-config" else "/proc/iomem" if meta.get("scope") == "memory-maps" else "/proc/klog" if meta.get("scope") == "live-logs" else "/proc/last_kmsg" if meta.get("scope") == "diagnostics" else "/etc/fstab"
        del files[selected]
    if scenario == "live_limit":
        files["/proc/klog"] = b"x" * 700000
    if scenario == "bad_start":
        files[directory + "/start"] = b"WRONG___" + files[directory + "/start"][8:]
    directories = {"/dev": entry(".", 4) + entry("nflasha", 6),
                   "/sys/devices/platform": entry(".", 4) + entry("soc", 4),
                   "/sys/bus/spi/devices": entry(".", 4) + entry("spi0.0", 10),
                   "/sys/module/backup/parameters": entry(".", 4) + entry("Backup_pri_file"),
                   "/sys/module/backup": entry(".", 4) + entry("parameters", 4),
                   "/sys/module/pcieatu/parameters": entry(".", 4) + entry("pcie_ctrl"),
                   "/sys/module/mmap/parameters": entry(".", 4) + entry("debug"),
                   "/sys/module/adrs_conv/parameters": entry(".", 4) + entry("debug") + entry("null"),
                   "/sys/module/upm/parameters": entry(".", 4),
                   "/sys/module/module/parameters": entry(".", 4) + entry("sig_enforce", 8),
                   "/sys/module": entry(".", 4) + entry("module", 4) + entry("backup", 4) + entry("dmm", 4),
                   "/proc/sys/kernel": entry(".", 4) + entry("modules_disabled", 8) + entry("kptr_restrict", 8),
                   "/cp": entry(".", 4) + entry("cpapp-b.bin") + entry("nor_ldr.img"),
                   "/sys/class/block": entry(".", 4) + entry("nflasha", 10),
                   "/proc/123/fd": entry(".", 4) + entry("0"),
                   "/proc": entry(".", 4) + entry("klog"),
                   "/proc/udm": entry(".", 4) + entry("dmm_log"),
                   "/log": entry(".", 4) + entry("cp.log", 8) + entry("ignored-device", 2) + entry(".secret", 8)}
    descriptors, opened, syscalls = {}, [], []
    state = {"nextfd": 3, "exit": None, "clock": 1, "published": {}}
    def cstring(ptr):
        raw = bytes(uc.mem_read(ptr, 1024));require(b"\0" in raw, "Unterminated syscall string")
        return raw.split(b"\0", 1)[0].decode()
    def ret(value):
        uc.reg_write(UC_ARM64_REG_X0, value & ((1 << 64) - 1))
    def interrupt(_uc, _intno, _data):
        number = uc.reg_read(UC_ARM64_REG_X8)
        args = [uc.reg_read(UC_ARM64_REG_X0 + i) for i in range(6)]
        syscalls.append(number)
        a,b,c,d,e,f = args
        if number == 56:
            path = cstring(b);flags = c;opened.append((path, flags))
            creating = flags & 3
            if creating:
                require(path.startswith(directory + "/") and flags == 0x880c1, "Write outside fixed tmpfs scope")
                if path in files:
                    ret(-17);return
                files[path] = b""
                if path in [directory + f"/f{i:02d}" for i in range(3,11)]:
                    state["published"][path] = b""
            else:
                require(flags in (0x88000, 0x8c000, 0x88800), "Unapproved source open flags")
                if flags == 0x88800:
                    require(path in ("/proc/klog", "/proc/osal/uipc", "/proc/udm/dmm_log"), "Unexpected nonblocking source")
                require(not path.startswith("/dev/") or flags == 0x8c000, "Attempt to open a device")
                if path == "/proc/self/fd":
                    directories[path] = entry(".", 4) + entry(str(state["nextfd"]))
                    if scenario == "inherited_fd":
                        directories[path] += entry("900")
                if path not in files and path not in directories:
                    ret(-2);return
            fd = state["nextfd"];state["nextfd"] += 1
            descriptors[fd] = [path, 0, creating];ret(fd)
        elif number == 57:
            descriptors.pop(a, None);ret(0)
        elif number in (63,61):
            path,pos,_ = descriptors[a]
            if number == 63 and path == "/proc/klog" and scenario in ("live_eagain", "live_error"):
                ret(-11 if scenario == "live_eagain" else -5);return
            raw = (directories if number == 61 else files)[path]
            n = min(len(raw) - pos, c)
            if scenario == "short_reads" and number == 63:
                n = min(n, 3)
            if n:
                uc.mem_write(b, raw[pos:pos+n])
            descriptors[a][1] += n;ret(n)
        elif number == 64:
            path,_,creating = descriptors[a];require(creating and path.startswith(directory + "/"), "Write descriptor escaped tmpfs")
            files[path] += bytes(uc.mem_read(b,c))
            if path.startswith(directory + "/log") or path in [directory + f"/f{i:02d}" for i in range(3,11)] + [directory + "/statuses"]:
                state["published"][path] = files[path]
            ret(c)
        elif number == 80:
            path = descriptors[a][0];require(path == "/log/cp.log", "Unexpected diagnostic fstat")
            value = bytearray(128)
            struct.pack_into("<I", value, 16, 0o060600 if scenario == "source_not_regular" else 0o100600)
            struct.pack_into("<q", value, 48, len(files[path]))
            uc.mem_write(b, bytes(value));ret(0)
        elif number == 67:
            path, _, creating = descriptors[a]
            require(path == "/log/cp.log" and not creating, "Unexpected diagnostic pread source")
            raw = files[path];n = min(c, max(0, len(raw) - d))
            if scenario == "short_reads":n = min(n, 64)
            if n:uc.mem_write(b, raw[d:d+n])
            ret(n)
        elif number == 35:
            path = cstring(b);require(path.startswith(directory + "/"), "Out-of-scope unlink")
            if path in files:
                del files[path];ret(0)
            else:
                ret(-2)
        elif number == 43:
            require(cstring(a) == "/tmp_wbshd", "Unexpected statfs path")
            fs_type = 0xEF53 if scenario == "not_tmpfs" else 0x1021994
            uc.mem_write(b, struct.pack("<15q", fs_type,4096,100000,100000,100000,0,0,0,255,4096,0,0,0,0,0));ret(0)
        elif number == 175:
            ret(1000 if scenario == "not_root" else 0)
        elif number == 172:
            ret(234)
        elif number == 173:
            ret(1)
        elif number == 113:
            uc.mem_write(b,struct.pack("<2q",state["clock"],0));state["clock"] += 1;ret(0)
        elif number == 101:
            ret(0)
        elif number == 78:
            require(descriptors[a][0] == "/proc/123/fd", "Unexpected readlink")
            uc.mem_write(c,b"/dev/null");ret(9)
        elif number == 94:
            state["exit"] = a;uc.emu_stop()
        else:
            raise RuntimeError(f"Unapproved syscall: {number}")
    uc.hook_add(UC_HOOK_INTR, interrupt)
    uc.emu_start(start, 0, count=4000000)
    require(state["exit"] is not None, "Worker exceeded instruction budget")
    result = decode(files[directory + "/result"], meta)
    success = scenario in ("success", "short_reads", "missing_optional", "source_not_regular", "live_eagain", "live_error", "live_limit")
    require((result["phase"] == 4 and result["error"] == 0) == success, f"Unexpected result for {scenario}: {result}")
    if success:
        cleaned = decode(files[directory + "/cleaned"], meta)
        require(cleaned["phase"] == 5 and not cleaned["error"], "Cleanup did not finish")
        require(not any(directory + f"/f{i:02d}" in files for i in range(11)), "Inventory chunks retained after ACK")
        if meta.get("scope") == "kernel-lease-status":
            root="/sys/module/m4btl_lease_01"
            source_files=("/proc/version","/proc/partitions","/proc/self/mountinfo",root+"/initstate",root+"/parameters/status",root+"/parameters/nonce",root+"/parameters/state",root+"/parameters/bytes",root+"/parameters/phys","/proc/sys/kernel/random/boot_id","/proc/uptime")
            source_dirs=()
            lifecycle=("/proc/123/maps","/proc/123/fd","/proc/self/fd")
            require(all(n not in syscalls for n in (29,105,106,222,226,273)),"Resident metadata performed ioctl, kernel load/unload, mapping or protection change")
            require(all(p in source_files+source_dirs+lifecycle for p,_ in opened if p.startswith(("/proc/","/sys/"))),"Resident metadata escaped fixed nodes")
            require(not any(p.startswith(("/dev/","/cp/","/setting/")) or p.endswith(".ko") for p,_ in opened),"Resident metadata opened device/data/module blob")
            require(all(flags==0x88000 for p,flags in opened if p in source_files),"Resident source not readonly")
            require(all(flags==0x8c000 for p,flags in opened if p in source_dirs),"Resident directory flags changed")
            statuses=struct.unpack('<11q',state['published'][directory+'/statuses'])
            for idx,node in enumerate(source_files[3:],3):
                if scenario=='missing_optional' and idx==4:
                    require(statuses[idx]==-2 and directory+'/f04' not in state['published'],"Missing resident status not preserved")
                else:
                    raw=state['published'][directory+f'/f{idx:02d}']
                    require(raw==files[node],"Resident raw metadata changed")
                    if 4<=idx<=8:require(raw.endswith(b"\n\n"),"Sysfs doubleLF lost")
            for idx,node in enumerate(source_dirs,8):require(state['published'][directory+f'/f{idx:02d}']==directories[node],"Resident dirents changed")
        if meta.get("scope") == "module-policy":
            source_files = ("/proc/version", "/proc/partitions", "/proc/self/mountinfo",
                            "/proc/sys/kernel/modules_disabled", "/sys/module/module/parameters/sig_enforce",
                            "/proc/sys/kernel/kptr_restrict", "/proc/modules", "/proc/self/status")
            source_dirs = ("/sys/module/module/parameters", "/sys/module", "/proc/sys/kernel")
            lifecycle = ("/proc/123/maps", "/proc/123/fd", "/proc/self/fd")
            require(not any(p.startswith(('/dev/', '/setting/', '/cp/')) for p, _ in opened), "Module policy opened a device or camera data")
            require(all(n not in syscalls for n in (29, 105, 106, 222, 226, 273)), "Module policy performed ioctl, driver load/unload or mapping")
            require(all(p in source_files + source_dirs + lifecycle for p, _ in opened if p.startswith(('/proc/', '/sys/'))), "Module policy read outside its fixed metadata scope")
            require(all(flags == 0x88000 for p, flags in opened if p in source_files), "Module policy source file was not read-only")
            require(all(flags == 0x8c000 for p, flags in opened if p in source_dirs), "Module policy source directory flags changed")
            statuses = struct.unpack('<11q', state['published'][directory + '/statuses'])
            for idx, node in enumerate(source_files[3:], 3):
                if scenario == 'missing_optional' and idx == 4:
                    require(statuses[idx] == -2 and directory + '/f04' not in state['published'], "Missing signature-policy status lost or exported")
                else:
                    require(state['published'][directory + f'/f{idx:02d}'] == files[node], "Module policy metadata content changed")
            for idx, node in enumerate(source_dirs, 8):
                require(state['published'][directory + f'/f{idx:02d}'] == directories[node], "Module policy directory inventory changed")
        if meta.get("scope") == "dmm-metadata":
            require(not any(p.startswith(('/dev/', '/setting/', '/cp/')) for p, _ in opened), "DMM metadata opened device or data")
            require(not any(p in ('/proc/udm/dmm_log', '/proc/klog', '/proc/osal/uipc') for p, _ in opened), "DMM metadata opened log or IPC nodes")
            require(all(n not in syscalls for n in (29, 222, 226)), "DMM metadata performed ioctl, mapping or protection change")
            require(all(flags == 0x88000 for p, flags in opened if p.startswith('/proc/udm/')), "DMM metadata source was not read-only")
            statuses = struct.unpack('<11q', state['published'][directory + '/statuses'])
            for idx, node in enumerate(('dmm_rule', 'dmm_extents', 'dmm_units', 'dmm_units2', 'dmm_reserve', 'dmm_info'), 3):
                if scenario == 'missing_optional' and idx == 4:
                    require(statuses[idx] == -2, "DMM optional status lost")
                else:
                    require(state['published'][directory + f'/f{idx:02d}'] == files['/proc/udm/' + node], "DMM metadata content changed")
        if meta.get("scope") == "memory-access-metadata":
            statuses = struct.unpack("<11q", state["published"][directory + "/statuses"])
            require(not any(p.startswith('/dev/') or p.startswith('/setting/') for p, _ in opened), "Memory metadata opened device/data")
            require(29 not in syscalls and 222 not in syscalls and 226 not in syscalls, "Memory metadata performed ioctl/mapping/protection change")
            require(state['published'][directory+'/f06'] == state['published'][directory+'/f07'] == files['/proc/udm/gpio'], "GPIO metadata snapshots changed")
            if scenario == "missing_optional":
                require(statuses[4] == -2, "Missing mmap guard metadata status lost")
            else:
                require(state['published'][directory+'/f04'] == files['/sys/module/mmap/parameters/debug'], "Mmap guard metadata changed")
        if meta.get("scope") == "backup-config":
            statuses = struct.unpack("<11q", state["published"][directory + "/statuses"])
            require(not any(p.startswith('/dev/') or p.startswith('/setting/') for p, _ in opened), "Backup metadata followed a path or opened device data")
            if scenario == "missing_optional":
                require(statuses[3] == -2, "Missing primary metadata status lost")
            else:
                require(state['published'][directory+'/f03'] == files['/sys/module/backup/parameters/Backup_pri_file'], "Primary metadata changed")
        if meta.get("scope") == "memory-maps":
            statuses = struct.unpack("<11q", state["published"][directory + "/statuses"])
            require(not any(p.startswith('/dev/') for p, _ in opened), "Memory metadata opened a device")
            require(not any(p in ('/proc/klog','/log/cp.log','/proc/udm/dmm_log') for p, _ in opened), "Memory metadata read logs")
            if scenario == "missing_optional":
                require(statuses[3] == -2, "Missing iomem status lost")
            else:
                require(state['published'][directory+'/f03'] == files['/proc/iomem'], "Iomem metadata changed")
        if meta.get("scope") == "diagnostics":
            index = state["published"][directory + "/logindex"]
            name, error, size, offset, count = struct.unpack_from("<96sqQQQ", index)
            require(name.rstrip(b"\0") == b"cp.log", "Unexpected log source")
            require(not any(p in ("/log/ignored-device", "/log/.secret") for p, _ in opened), "Out-of-scope log open")
            if scenario == "source_not_regular":
                require(error == -22 and directory + "/log00" not in state["published"], "Non-regular source was read")
            else:
                require(error == 0 and count == 131072 and offset == size - count, "Log tail bounds differ")
                require(state["published"][directory + "/log00"] == files["/log/cp.log"][-131072:], "Log tail bytes differ")
            require(directory + "/log00" not in files and directory + "/logindex" not in files, "Log tails not cleaned")
        if meta.get("scope") == "live-logs":
            statuses = struct.unpack("<11q", state["published"][directory + "/statuses"])
            require(not any(p == "/log/cp.log" for p, _ in opened), "Live-log scope opened access logs")
            if scenario in ("live_error", "missing_optional"):
                require(statuses[3] == (-5 if scenario == "live_error" else -2), "Proc error not retained")
                require(directory + "/f03" not in state["published"], "Error source was exported")
            elif scenario == "live_eagain":
                require(statuses[3] == 0 and state["published"][directory + "/f03"] == b"", "Empty nonblocking snapshot failed")
            else:
                require(state["published"][directory + "/f03"] == files["/proc/klog"][:524288], "Proc snapshot content/bound failed")
            require(all(flags == 0x88800 for p, flags in opened if p in ("/proc/klog", "/proc/osal/uipc", "/proc/udm/dmm_log")), "Live proc read was blocking")
    else:
        require(result["phase"] == 90 and result["error"] < 0, "Fail-closed error missing")
    return {"scenario": scenario, "passed": True, "phase": result["phase"], "error": result["error"],
            "syscalls": sorted(set(syscalls)), "block_open_or_write": False}


def main():
    p = argparse.ArgumentParser();p.add_argument("--job", type=Path, required=True);a=p.parse_args()
    scenarios = ["success", "short_reads", "missing_optional", "not_root", "not_tmpfs", "inherited_fd", "loader_busy", "missing_required", "bad_start"]
    if json.loads((a.job / "job.json").read_text()).get("scope") == "diagnostics":
        scenarios.append("source_not_regular")
    if json.loads((a.job / "job.json").read_text()).get("scope") == "live-logs":
        scenarios += ["live_eagain", "live_error", "live_limit"]
    results = [emulate(a.job.resolve(), s) for s in scenarios]
    report = {"all_passed": all(r["passed"] for r in results), "worker_sha256": sha(a.job / "worker.elf"),
              "bootstrap_sha256": sha(a.job / "libJit.so"), "tests": results, "physical_acceptance": False}
    save(a.job / "emulation.json", report);print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
