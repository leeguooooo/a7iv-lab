"""Prepare a fixed-path ARM64 inventory worker, then explicitly run it over USB.

No partition, settings, NOR, updater, mount, or memory-patch operation exists.
The run step uploads one self-deleting libJit module and exchanges tmpfs files.
"""
import argparse
import hashlib
import io
import json
import os
import secrets
import struct
import subprocess
import sys
import time
from pathlib import Path

from elftools.elf.elffile import ELFFile

ROOT = Path(__file__).resolve().parent
UPSTREAM = ROOT / "ref/sony-a7m4-custom-firmware"
NATIVE = UPSTREAM / "no-fastboot-install/software/app/native"
COMMIT = "caa29145644e1d7d0a41cef1e42f0c53368bd025"
RESULT = struct.Struct("<8s16s13q")
LAUNCH = struct.Struct("<8s16s10q")
FIELDS = ("version", "phase", "error", "euid", "pid", "ppid", "loader_pid", "cleanup",
          "maps_bytes", "fd_count", "fd_audit_bytes", "flags", "fs_available")
FILES = ["proc_version", "proc_partitions", "mountinfo", "fstab", "proc_mtd", "proc_devices",
         "proc_cmdline", "proc_cpuinfo", "dev.dirents", "block.dirents", "mtd.dirents"]
DIAGNOSTIC_FILES = ["proc_version", "proc_partitions", "mountinfo", "last_kmsg", "uptime", "meminfo",
                    "proc_cmdline", "kernel_tainted", "log.dirents", "pstore.dirents", "var-log.dirents"]
LIVE_LOG_FILES = ["proc_version", "proc_partitions", "mountinfo", "kernel_log", "uipc_log", "dmm_log",
                  "proc_cmdline", "uptime", "proc.dirents", "pstore.dirents", "udm.dirents"]
MEMORY_MAP_FILES = ["proc_version", "proc_partitions", "mountinfo", "iomem", "interrupts", "meminfo",
                    "proc_cmdline", "proc_cpuinfo", "platform.dirents", "udm.dirents", "spi.dirents"]
BACKUP_CONFIG_FILES = ["proc_version", "proc_partitions", "mountinfo", "backup_primary", "backup_secondary",
                       "backup_save", "backup_load", "uptime", "backup-parameters.dirents",
                       "backup-module.dirents", "pciatu-parameters.dirents"]
MEMORY_ACCESS_METADATA_FILES = ["proc_version", "proc_partitions", "mountinfo", "worker_status",
                                "mmap_debug", "adrs_debug", "gpio_before", "gpio_after",
                                "mmap-parameters.dirents", "adrs-parameters.dirents", "cp.dirents"]
DMM_METADATA_FILES = ["proc_version", "proc_partitions", "mountinfo", "dmm_rule", "dmm_extents",
                      "dmm_units", "dmm_units2", "dmm_reserve", "dmm_info", "worker_status", "uptime"]
MODULE_POLICY_FILES = ["proc_version", "proc_partitions", "mountinfo", "modules_disabled", "sig_enforce",
                       "kptr_restrict", "proc_modules", "worker_status", "module-parameters.dirents",
                       "modules.dirents", "kernel-sysctl.dirents"]
KERNEL_LEASE_STATUS_FILES = ["proc_version", "proc_partitions", "mountinfo", "lease_initstate",
                             "lease_status", "lease_nonce", "lease_state", "lease_bytes",
                             "lease_phys", "boot_id", "uptime"]
LIBRARIES = {"/usr/lib/libJiritsu.so": "3b19665f84bcd1b837a3b9377b40a91893010ff9732be71a430f3d0265c72c69",
             "/lib/ld-2.25.so": "90b4fe734ba7faa08d4591b1363bff478e7bde399a821fc0b2d021c062a58a9a"}


def require(value, message):
    if not value:
        raise RuntimeError(message)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, data):
    Path(path).write_text(json.dumps(data, indent=2) + "\n")


def inspect(path, executable):
    with Path(path).open("rb") as f:
        elf = ELFFile(f)
        require(elf["e_machine"] == "EM_AARCH64", "Expected AArch64")
        require(elf["e_type"] == ("ET_EXEC" if executable else "ET_DYN"), "ELF type mismatch")
        require(not any(s["p_type"] == "PT_INTERP" for s in elf.iter_segments()), "Unexpected interpreter")
        require(all(s["p_flags"] & 3 != 3 for s in elf.iter_segments() if s["p_type"] == "PT_LOAD"), "Writable executable segment")
        init, relocations = None, []
        for sec in elf.iter_sections():
            if sec["sh_type"] == "SHT_DYNAMIC":
                for tag in sec.iter_tags():
                    require(tag.entry.d_tag not in ("DT_NEEDED", "DT_TEXTREL"), "Unexpected dynamic dependency/text relocation")
                    if tag.entry.d_tag == "DT_INIT":
                        init = tag.entry.d_val
            if sec["sh_type"] == "SHT_DYNSYM":
                require(not any(s.name and s["st_shndx"] == "SHN_UNDEF" for s in sec.iter_symbols()), "Undefined import")
            if sec["sh_type"] in ("SHT_RELA", "SHT_REL"):
                relocations += [r.entry.r_info_type for r in sec.iter_relocations()]
        require(all(x == 1027 for x in relocations), "Non-relative relocation")
        require(executable or init is not None, "Missing module initializer")
        return {"sha256": sha(path), "size": Path(path).stat().st_size, "entry": elf["e_entry"], "init": init,
                "segments": [dict(s.header) for s in elf.iter_segments()], "relocations": relocations}


def prepare(out, diagnostics=False, live_logs=False, memory_maps=False, backup_config=False, memory_access_metadata=False, dmm_metadata=False, module_policy=False, kernel_lease_status=False):
    require(not kernel_lease_status or not any((diagnostics, live_logs, memory_maps, backup_config, memory_access_metadata, dmm_metadata, module_policy)), "Resident lease metadata must use its own fixed scope")
    require(not module_policy or not any((diagnostics, live_logs, memory_maps, backup_config, memory_access_metadata, dmm_metadata)), "Module policy metadata must use its own fixed scope")
    require(not dmm_metadata or not any((diagnostics, live_logs, memory_maps, backup_config, memory_access_metadata)), "DMM metadata must use its own fixed scope")
    require(not memory_access_metadata or not (diagnostics or live_logs or memory_maps or backup_config), "Memory-access metadata must use its own fixed scope")
    require(not backup_config or not (diagnostics or live_logs or memory_maps), "Backup metadata must use its own fixed scope")
    require(not memory_maps or not (diagnostics or live_logs), "Memory metadata must use its own fixed scope")
    diagnostics = diagnostics or live_logs
    require(not out.exists(), "Choose a new job directory")
    require(subprocess.check_output(["git", "-C", str(UPSTREAM), "rev-parse", "HEAD"], text=True).strip() == COMMIT, "Upstream commit changed")
    require(not subprocess.check_output(["git", "-C", str(UPSTREAM), "status", "--porcelain"], text=True).strip(), "Upstream checkout changed")
    compiler = ROOT / "local/zig-aarch64-macos-0.15.2/zig"
    require(compiler.exists(), "Missing verified Zig 0.15.2")
    nonce = secrets.token_bytes(16)
    directory = "/tmp_wbshd/m4inv_" + nonce.hex()
    out.mkdir(parents=True)
    def array(name, payload):
        return "static const unsigned char " + name + "[]={" + ",".join(map(str, payload)) + "};\n"
    (out / "job.h").write_text('#define JOB_DIR "' + directory + '"\n' + array("job_nonce", nonce))
    flags = ["cc", "-target", "aarch64-linux-gnu", "-mcpu=generic", "-Os", "-g", "-ffreestanding", "-fno-builtin",
             "-fno-stack-protector", "-fno-unwind-tables", "-fno-asynchronous-unwind-tables", "-nostdlib",
             "-ffunction-sections", "-fdata-sections", "-Wl,--gc-sections", "-Wl,--no-undefined", "-Wl,--build-id=none",
             "-Wl,-z,noexecstack", "-Wl,-z,max-page-size=4096", "-Wl,-z,common-page-size=4096", "-I", str(out), "-I", str(NATIVE)]
    if diagnostics:
        flags.append("-DINVENTORY_DIAGNOSTICS=1")
    if live_logs:
        flags.append("-DINVENTORY_LIVE_LOGS=1")
    if memory_maps:
        flags.append("-DINVENTORY_MEMORY_MAPS=1")
    if backup_config:
        flags.append("-DINVENTORY_BACKUP_CONFIG=1")
    if memory_access_metadata:
        flags.append("-DINVENTORY_MEMORY_ACCESS_METADATA=1")
    if dmm_metadata:
        flags.append("-DINVENTORY_DMM_METADATA=1")
    if kernel_lease_status:
        flags.append("-DINVENTORY_KERNEL_LEASE_STATUS=1")
    if module_policy:
        flags.append("-DINVENTORY_MODULE_POLICY=1")
    def compile(source, name, extra):
        result = subprocess.run([str(compiler), *flags, *extra, str(source), "-o", str(out / name)], capture_output=True, text=True, timeout=120)
        (out / (name + ".compile.log")).write_text(result.stdout + result.stderr)
        require(result.returncode == 0, result.stderr[-3000:])
    compile(ROOT / "native/inventory.c", "worker.debug.elf", ["-static", "-fno-pic", "-Wl,-e,_start"])
    worker = inspect(out / "worker.debug.elf", True)
    raw = (out / "worker.debug.elf").read_bytes()
    limit = max(s["p_offset"] + s["p_filesz"] for s in worker["segments"] if s["p_type"] == "PT_LOAD")
    compact = bytearray(raw[:limit]);struct.pack_into("<Q", compact, 40, 0);struct.pack_into("<3H", compact, 58, 0, 0, 0)
    (out / "worker.elf").write_bytes(compact)
    (out / "worker_blob.h").write_text(array("worker_blob", compact))
    compile(NATIVE / "bootstrap.c", "libJit.so", ["-shared", "-fPIC", "-Wl,-Bsymbolic", "-s"])
    bootstrap = inspect(out / "libJit.so", False)
    require(bootstrap["size"] <= 65520, "Module exceeds one-shot upload size")
    sources = [ROOT / "native/inventory.c", NATIVE / "linux_a64.h", NATIVE / "bootstrap.c", NATIVE / "lifecycle_worker.c", Path(__file__)]
    meta = {"schema": "camera-use-inventory/1", "nonce": nonce.hex(), "job_dir": directory,
            "scope": "kernel-lease-status" if kernel_lease_status else "module-policy" if module_policy else "dmm-metadata" if dmm_metadata else "memory-access-metadata" if memory_access_metadata else "backup-config" if backup_config else "memory-maps" if memory_maps else "live-logs" if live_logs else "diagnostics" if diagnostics else "layout",
            "worker": worker, "compact_worker_sha256": sha(out / "worker.elf"), "bootstrap": bootstrap,
            "compiler_sha256": sha(compiler), "upstream_commit": COMMIT,
            "sources": {str(p.relative_to(ROOT)): sha(p) for p in sources},
            "block_reads": False, "block_writes": False, "module_uploads_allowed": 1, "automatic_retry": False}
    save(out / "job.json", meta)
    for p in sources:
        dest = out / "sources" / p.relative_to(ROOT)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(p.read_bytes())
    print(json.dumps({"job": str(out), "module_bytes": bootstrap["size"], "block_writes": False}))


def decode(raw, meta):
    require(len(raw) == RESULT.size, "Partial native result")
    magic, nonce, *values = RESULT.unpack(raw)
    require(magic == b"M4INV001" and nonce.hex() == meta["nonce"], "Native result identity changed")
    return dict(zip(FIELDS, values))


def dirents(raw):
    result, at = [], 0
    while at < len(raw):
        require(at + 20 <= len(raw), "Truncated directory entry")
        length = struct.unpack_from("<H", raw, at + 16)[0]
        require(length >= 20 and at + length <= len(raw), "Directory entry length")
        name = raw[at + 19:at + length].split(b"\0", 1)[0]
        require(len(name) < length - 19, "Unterminated directory name")
        result.append({"name": name.decode("utf-8", "replace"), "type": raw[at + 18]})
        at += length
    return result


class CameraStatusError(RuntimeError):
    def __init__(self, status):
        self.status = status
        super().__init__(f"Camera status {status:#x}")


def run(out):
    require(sys.platform != "darwin" or os.geteuid() == 0,
            "macOS MSC access requires sudo: sudo -n env DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib .venv-offline/bin/python camera_inventory.py run --job JOB")
    meta = json.loads((out / "job.json").read_text())
    require(meta["schema"] == "camera-use-inventory/1", "Wrong job type")
    scope = meta.get("scope", "layout")
    require(scope in ("layout", "diagnostics", "live-logs", "memory-maps", "backup-config", "memory-access-metadata", "dmm-metadata", "module-policy", "kernel-lease-status"), "Unknown fixed inventory scope")
    require(all(sha(ROOT / p) == value for p, value in meta["sources"].items()), "Reviewed source changed; rebuild/retest")
    require(sha(out / "libJit.so") == meta["bootstrap"]["sha256"] and sha(out / "worker.elf") == meta["compact_worker_sha256"], "Job binary changed")
    require((out / "emulation.json").exists(), "Offline emulation is required")
    emulation = json.loads((out / "emulation.json").read_text())
    require(emulation.get("all_passed") is True and len(emulation.get("tests", [])) == (12 if scope == "live-logs" else 10 if scope == "diagnostics" else 9)
            and emulation.get("worker_sha256") == meta["compact_worker_sha256"]
            and emulation.get("bootstrap_sha256") == meta["bootstrap"]["sha256"], "Emulation evidence differs from this job")
    require(not (out / "attempt.json").exists(), "Job already attempted; never automatically reupload")
    sys.path.insert(0, str(ROOT / "Sony-PMCA-RE"))
    import usb.core
    import usb.util
    import usb.backend.libusb1
    backend = usb.backend.libusb1.get_backend(find_library=lambda _: "/opt/homebrew/lib/libusb-1.0.dylib")
    devices = list(usb.core.find(find_all=True, idVendor=0x054c, idProduct=0x0da5, backend=backend))
    require(len(devices) == 1, "Start with exactly one Sony camera in normal MSC mode")
    dev = devices[0];require(dev.product == "ILCE-7M4" and dev.serial_number, "Wrong or unidentified camera")
    body = {"model": dev.product, "usb_serial_sha256": hashlib.sha256(dev.serial_number.encode()).hexdigest(),
            "bus": dev.bus, "ports": list(dev.port_numbers or [])}
    usb.util.dispose_resources(dev)
    from pmca.commands.usb import senserShellCommand
    from pmca.platform.backend.senser import SenserPlatformBackend
    evidence = out / "execution";evidence.mkdir()
    report = {"body": body, "block_reads": False, "block_writes": False, "module_uploads": 0,
              "start_attempts": 0, "verdict": "NOT_STARTED", "automatic_retry": False,
              "scope": scope, "nor_requests": 0}
    with (out / "attempt.json").open("x") as f:
        json.dump({"time": time.time(), "body": body, "automatic_retry": False}, f)
    def complete(camera):
        SenserPlatformBackend(camera).start()
        from a7m4.fl23 import bk4_rows
        original = (ROOT / "dumps/20261026-031555/backup_preset.bin").read_bytes()
        serial_records = [row["records"][0x00e70003] for row in bk4_rows(original) if 0x00e70003 in row["records"]]
        require(len(serial_records) == 1, "Original serial binding is ambiguous")
        serial_record = serial_records[0]
        require(bytes(camera.readBackup(0x00e70003)) == original[serial_record["offset"]:serial_record["offset"] + serial_record["size"]], "Service body differs from original backup")
        healthy = True
        def jiritsu(cmd, payload):
            nonlocal healthy
            require(healthy, "Transport outcome unknown; stop")
            try:
                res, raw = camera.dev.sendSenserPacket(0x40, struct.pack("<HH", 0x1001, cmd) + payload)
                raw = bytes(raw or b"")
                require(res == 0 and len(raw) >= 4, "Bad Jiritsu response")
                status = struct.unpack_from("<I", raw)[0]
                if status:
                    raise CameraStatusError(status)
                return raw[4:]
            except CameraStatusError:
                raise
            except BaseException:
                healthy = False
                raise
        def select(path):
            require(jiritsu(15, b"\0" + path.encode("ascii") + b"\0") == b"", "Unexpected select reply")
        def read_path(path, size, missing=False):
            select("/tmp/jiritsu/../.." + path)
            try:
                data = jiritsu(17, b"\0\xff\0")
            except CameraStatusError as e:
                if missing and e.status == 0x10000006:
                    return None
                raise
            require(len(data) <= size, "Read exceeds expected bound")
            return data
        for path, expected in LIBRARIES.items():
            data = read_path(path, 300000)
            require(hashlib.sha256(data).hexdigest() == expected, "Firmware loader library differs: " + path)
            (evidence / Path(path).name).write_bytes(data)
        require(read_path("/tmp/jiritsu/libJit.so", 65520, True) is None, "Existing module must not be replaced")
        def read(name, size, missing=False):
            return read_path(meta["job_dir"] + "/" + name, size, missing)
        def write(name, payload):
            require(name in ("module", "start", "ack"), "Invalid upload")
            path = "/tmp/jiritsu/libJit.so" if name == "module" else "/tmp/jiritsu/../.." + meta["job_dir"] + "/" + name
            select(path)
            require(jiritsu(16, b"\0\xff\0" + payload) == b"", "Unexpected upload response")
        def poll(name, size):
            end = time.monotonic() + 45
            while time.monotonic() < end:
                raw = read(name, size, True)
                if raw is not None:
                    require(len(raw) == size, "Partial publication; stop")
                    (evidence / (name + ".bin")).write_bytes(raw)
                    return raw
                if name in ("launch", "ready"):
                    failure = read("exec_failure", 8, True)
                    require(failure is None, "Native worker exec failed")
                    result = read("result", RESULT.size, True)
                    if result is not None:
                        report["native"] = decode(result, meta)
                        raise RuntimeError("Worker stopped: " + str(report["native"]))
                time.sleep(0.2)
            raise TimeoutError("Publication deadline; do not reupload")
        report["module_uploads"] = 1;report["jiritsu_workarea_filesystem_touched"] = True
        report["verdict"] = "UPLOAD_ATTEMPTED";save(evidence / "run.json", report)
        write("module", (out / "libJit.so").read_bytes())
        launch = LAUNCH.unpack(poll("launch", LAUNCH.size))
        require(launch[:3] == (b"M4BOOT01", bytes.fromhex(meta["nonce"]), 1) and launch[3:6] == (3, 0, 0)
                and launch[7] == 0 and launch[8] > 0 and launch[8] == launch[9] and launch[10] == 0, "Bootstrap result invalid")
        ready = decode(poll("ready", RESULT.size), meta)
        require(ready["phase"] == 1 and ready["error"] == 0 and ready["euid"] == 0 and ready["ppid"] == 1
                and ready["cleanup"] == 0 and ready["loader_pid"] == launch[6], "Worker readiness invalid")
        report["start_attempts"] = 1;save(evidence / "run.json", report)
        write("start", b"M4START1" + bytes.fromhex(meta["nonce"]) + struct.pack("<Q", 1))
        result = decode(poll("result", RESULT.size), meta);report["native"] = result
        require(result["phase"] in (4, 90) and result["flags"] == 3, "Inventory lifecycle rejected")
        raw = read("statuses", 88, True)
        require(raw is not None and len(raw) == 88, "Partial/missing inventory status")
        statuses = struct.unpack("<11q", raw);report["files"] = {}
        selected_files = KERNEL_LEASE_STATUS_FILES if scope == "kernel-lease-status" else MODULE_POLICY_FILES if scope == "module-policy" else DMM_METADATA_FILES if scope == "dmm-metadata" else MEMORY_ACCESS_METADATA_FILES if scope == "memory-access-metadata" else BACKUP_CONFIG_FILES if scope == "backup-config" else MEMORY_MAP_FILES if scope == "memory-maps" else LIVE_LOG_FILES if scope == "live-logs" else DIAGNOSTIC_FILES if scope == "diagnostics" else FILES
        for i, (name, size) in enumerate(zip(selected_files, statuses)):
            item = {"bytes_or_error": size}
            if scope == "live-logs" and 3 <= i <= 5:
                item.update(nonblocking_snapshot=True, capacity=524288, complete_history_verified=False)
            if size >= 0:
                data = read(f"f{i:02d}", size);require(len(data) == size, "Partial inventory data")
                (evidence / name).write_bytes(data);item["sha256"] = hashlib.sha256(data).hexdigest()
                if i >= 8 and scope not in ("dmm-metadata", "kernel-lease-status"):
                    save(evidence / (name + ".json"), dirents(data))
            report["files"][name] = item
        for name, cap in (("loader_maps", 524288), ("loader_fds", 131072)):
            data = read(name, cap);(evidence / name).write_bytes(data)
        require(result["phase"] == 4 and result["error"] == 0, "Inventory rejected; exact path statuses retained")
        if scope == "diagnostics":
            raw = read("logindex", 2048, True)
            report["logs"] = []
            if raw is not None:
                require(len(raw) == 2048, "Partial log index")
                (evidence / "logindex.bin").write_bytes(raw)
                import re
                for i in range(16):
                    rawname, error, size, offset, count = struct.unpack_from("<96sqQQQ", raw, i * 128)
                    if not rawname[0]:
                        continue
                    name = rawname.split(b"\0", 1)[0].decode("ascii")
                    require(re.fullmatch(r"[A-Za-z0-9_-][A-Za-z0-9._-]{0,94}", name), "Invalid fixed log filename")
                    record = {"name": name, "error": error, "source_size": size, "offset": offset, "bytes": count}
                    require(count <= 131072 and offset + count <= size, "Log bounds changed")
                    if not error:
                        value = read(f"log{i:02d}", count)
                        require(len(value) == count, "Partial log tail")
                        dest = evidence / f"log{i:02d}.tail.bin"
                        dest.write_bytes(value)
                        record.update(local_file=dest.name, sha256=hashlib.sha256(value).hexdigest())
                    report["logs"].append(record)
        write("ack", b"M4ACK001" + bytes.fromhex(meta["nonce"]) + struct.pack("<Q", 1))
        cleaned = decode(poll("cleaned", RESULT.size), meta)
        require(cleaned["phase"] == 5 and cleaned["error"] == 0, "Cleanup failed")
        require(read_path("/tmp/jiritsu/libJit.so", 65520, True) is None, "Module cleanup not confirmed")
        report["verdict"] = "INVENTORY_READ_VERIFIED"
    try:
        senserShellCommand(complete=complete)
        require(report["verdict"] == "INVENTORY_READ_VERIFIED", "No successful inventory callback")
    except BaseException as error:
        report["error"] = {"type": type(error).__name__, "message": str(error)}
        raise
    finally:
        save(evidence / "run.json", report)
    print(json.dumps({"verdict": report["verdict"], "evidence": str(evidence), "block_writes": False}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "run"))
    parser.add_argument("--job", type=Path, required=True)
    parser.add_argument("--diagnostics", action="store_true", help="Prepare fixed /log tails and pstore/last_kmsg inventory; never send NOR commands")
    parser.add_argument("--live-logs", action="store_true", help="Prepare bounded nonblocking snapshots of fixed kernel/IPC/DMM proc nodes; never use official export or NOR commands")
    parser.add_argument("--memory-maps", action="store_true", help="Read fixed iomem/interrupt metadata and platform/SPI directory names; no physical memory or SPI access")
    parser.add_argument("--backup-config", action="store_true", help="Read fixed backup module parameter metadata; never follow returned paths or send SAVE/WRITE")
    parser.add_argument("--memory-access-metadata", action="store_true", help="Read fixed kernel parameters, worker capabilities, GPIO proc status and CP directory names; no /dev/mem, mmap, ioctl or permission/pin changes")
    parser.add_argument("--dmm-metadata", action="store_true", help="Read six fixed DMM proc metadata nodes, status and uptime; no log, allocation, IPC, mapping, DMA or device access")
    parser.add_argument("--module-policy", action="store_true", help="Read fixed module policy sysctl/sysfs values, module list and status; no kernel module load, ioctl, mapping or parameter writes")
    parser.add_argument("--kernel-lease-status", action="store_true", help="Read fixed resident module initstate/status/nonce/state/bytes/phys plus boot_id/uptime only; preserve raw sysfs bytes; no kernel load/unload, ioctl or mapping")
    args = parser.parse_args()
    if args.action == "prepare":
        prepare(args.job.resolve(), args.diagnostics, args.live_logs, args.memory_maps, args.backup_config, args.memory_access_metadata, args.dmm_metadata, args.module_policy, args.kernel_lease_status)
    else:
        # The scoped service session already closes before run() returns/raises.
        # Avoid a known macOS libusb global-finalizer hang after re-enumeration.
        code = 0
        try:
            run(args.job.resolve())
        except BaseException:
            import traceback
            traceback.print_exc()
            code = 1
        finally:
            sys.stdout.flush();sys.stderr.flush()
        os._exit(code)
