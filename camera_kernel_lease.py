"""Offline prepare by default. Kernel lease load requires a separate explicit scope.
Success leaves a private kernel page resident until reboot; AP cleanup is separate.
"""
import argparse
import hashlib
import json
import os
import re
import secrets
import struct
import subprocess
import sys
import time
from pathlib import Path
from elftools.elf.elffile import ELFFile
from camera_inventory import ROOT, UPSTREAM, NATIVE, COMMIT, RESULT, LAUNCH, FIELDS, LIBRARIES, require, sha, save, inspect, CameraStatusError
SCOPE = "kernel-lease-only"
LEASE = struct.Struct("<8s16s13q")
LEASE_FIELDS = ("version", "stage", "error", "attempts", "load_return", "version_bytes", "status_bytes", "disabled_bytes", "sig_bytes", "initial_state", "post_state_bytes", "post_status_bytes", "page_phys")
IMPORTS = {"__get_free_pages", "arch_va_to_phys", "scnprintf"}
KERNEL_MANIFEST = ROOT / "output/pcidma-OFFLINE_LEASE_ONLY-02/manifest.json"
POLICY = ROOT / "output/module-policy-01"

def decode(raw, meta):
    require(len(raw) == RESULT.size, "Partial native result")
    magic, nonce, *values = RESULT.unpack(raw)
    require(magic == b"M4KLS001" and nonce.hex() == meta["nonce"], "Native identity changed")
    return dict(zip(FIELDS, values))

def decode_lease(raw, meta):
    require(len(raw) == LEASE.size, "Partial lease report")
    magic, nonce, *values = LEASE.unpack(raw)
    require(magic == b"M4KLEAS1" and nonce.hex() == meta["nonce"], "Lease report identity changed")
    return dict(zip(LEASE_FIELDS, values))

def start_packet(meta):
    return b"M4KSTART" + bytes.fromhex(meta["nonce"]) + struct.pack("<Q", 1) + SCOPE.encode().ljust(32, b"\0")

def validate_status(raw, meta):
    nonce = meta["kernel"]["module_nonce"]
    pattern = rb"schema=1 profile=lease-only nonce=" + nonce.encode() + rb" state=ready page_bytes=4096 page_phys=0x([0-9a-f]+) resident=boot dma=0\n\n"
    m = re.fullmatch(pattern, raw)
    require(m is not None, "Module status schema/identity mismatch")
    phys = int(m.group(1), 16)
    require(0x400000000 <= phys <= 0x4fffff000 and phys % 4096 == 0, "Module page outside lease range")
    return phys

def run_guard(meta):
    require(meta.get("model_only") is not True, "MODEL_ONLY regression artifact cannot run on a device")

def scope_guard(meta, scope):
    require(meta.get("schema") == "camera-kernel-lease/1" and meta.get("scope") == SCOPE, "Wrong fixed scope")
    require(scope == meta["nonce"] + ":" + SCOPE, "Separate explicit nonce:kernel-lease-only scope required")

def check_kernel(manifest):
    m = json.loads(manifest.read_text()); require(m["schema"] == "m4btl-offline-lease-only/1", "Wrong kernel manifest")
    require(m["revision"] == 2 and m["module_name"] == "m4btl_lease_01"
            and m["module_nonce"] == "4d27c5e90e00ba356d6fdca7ac027bce"
            and m["module_bytes"] == 9160
            and m["module_sha256"] == "09a1930e7344a0021a21e8c3ec71d160930a477466c7f3cd80b0562222b12607", "Kernel revision02 sealed identity mismatch")
    require(m["free_pages_import"] is False and m["allocator_flags"] == "GFP_NOWAIT|__GFP_ZERO|__GFP_NOMEMALLOC=0x2018000"
            and m["model_cases"] == 15, "Kernel revision02 allocator contract changed")
    require(m["module_loads_performed"] == 0 and m["camera_io"] is False and m["model_assertions_passed"] is True, "Not sealed offline evidence")
    require(m["status_path"] == "/sys/module/m4btl_lease_01/parameters/status" and m["status_permissions"] == "0400", "Status getter changed")
    require(m["page"] == {"bytes":4096,"order":0,"physical_min":"0x400000000","physical_max":"0x4fffff000","alignment":4096,"content_exposed":False}, "Page contract changed")
    for p,h in m["source_hashes"].items(): require(sha(manifest.parent/p)==h, "Kernel source changed: "+p)
    ko=manifest.parent/m["module_file"]; require(sha(ko)==m["module_sha256"] and ko.stat().st_size==m["module_bytes"], "Kernel blob changed")
    with ko.open("rb") as f:
        elf=ELFFile(f); require(elf["e_type"]=="ET_REL" and elf["e_machine"]=="EM_AARCH64", "Kernel ELF type")
        sym=elf.get_section_by_name(".symtab"); require(sym is not None, "Kernel symbols missing")
        symbols=list(sym.iter_symbols()); imports={s.name for s in symbols if s.name and s["st_shndx"]=="SHN_UNDEF"}
        require(imports==IMPORTS and imports==set(m["allowed_undefined_imports"]), "Kernel import allowlist")
        require(any(s.name=="init_module" for s in symbols) and not any(s.name=="cleanup_module" for s in symbols), "Kernel lifecycle mismatch")
        this_module=elf.get_section_by_name(".gnu.linkonce.this_module")
        require(this_module is not None and this_module["sh_size"]==768 and this_module.data()[0x2b8:0x2c0]==bytes(8), "Missing/mismatched this_module or exit pointer")
        init_reloc=elf.get_section_by_name(".rela.gnu.linkonce.this_module")
        require(init_reloc is not None and any(r["r_offset"]==0x158 and sym.get_symbol(r["r_info_sym"]).name=="init_module" for r in init_reloc.iter_relocations()), "Module init binding changed")
        modinfo=elf.get_section_by_name(".modinfo").data().split(b"\0")
        require(elf.get_section_by_name(".gnu.linkonce.this_module").data()[0x18:0x50].split(b"\0",1)[0] == b"m4btl_lease_01" and b"vermagic=4.9.337-scel SMP preempt mod_unload aarch64" in modinfo, "Kernel name/vermagic mismatch")
    return m,ko

def prepare(out, model_only=False):
    require(not out.exists(), "Choose a fresh job directory")
    require(subprocess.check_output(["git","-C",str(UPSTREAM),"rev-parse","HEAD"],text=True).strip()==COMMIT, "Upstream commit changed")
    require(not subprocess.check_output(["git","-C",str(UPSTREAM),"status","--porcelain"],text=True).strip(), "Upstream checkout changed")
    km,ko=check_kernel(KERNEL_MANIFEST)
    require(sha(POLICY/"completion.json")==km["host_policy_evidence"]["sha256"], "Kernel/host policy evidence differs")
    policy=json.loads((POLICY/"completion.json").read_text())
    require(policy["metadata_verified"] is True and policy["policy_unchanged"] is True and policy["kernel_module_loads"]==0, "Policy evidence changed")
    version=(POLICY/"execution/proc_version").read_bytes(); require(version.startswith(b"Linux version 4.9.337-scel ") and version.endswith(b"\n"), "Wrong captured kernel")
    nonce=secrets.token_bytes(16); directory="/tmp_wbshd/m4kls_"+nonce.hex();out.mkdir(parents=True)
    def array(name,payload): return "static const unsigned char "+name+"[]={"+",".join(map(str,payload))+"};\n"
    (out/"job.h").write_text('#define JOB_DIR "'+directory+'"\n'+array("job_nonce",nonce))
    prefix="schema=1 profile=lease-only nonce="+km["module_nonce"]+" state=ready page_bytes=4096 page_phys=0x"
    (out/"kernel_module_blob.h").write_text(array("kernel_lease_module",ko.read_bytes())+array("expected_version",version)+'static const char lease_scope[32]="kernel-lease-only";\nstatic const char lease_status_prefix[]='+json.dumps(prefix)+';\n')
    compiler=ROOT/"local/zig-aarch64-macos-0.15.2/zig"
    flags=["cc","-target","aarch64-linux-gnu","-mcpu=generic","-Os","-g","-ffreestanding","-fno-builtin","-fno-stack-protector","-fno-unwind-tables","-fno-asynchronous-unwind-tables","-nostdlib","-ffunction-sections","-fdata-sections","-Wl,--gc-sections","-Wl,--no-undefined","-Wl,--build-id=none","-Wl,-z,noexecstack","-Wl,-z,max-page-size=4096","-Wl,-z,common-page-size=4096","-I",str(out),"-I",str(NATIVE)]
    def compile(source,name,extra):
        r=subprocess.run([str(compiler),*flags,*extra,str(source),"-o",str(out/name)],capture_output=True,text=True,timeout=120)
        (out/(name+".compile.log")).write_text(r.stdout+r.stderr); require(r.returncode==0,r.stderr[-3000:])
    compile(ROOT/"native/kernel_lease_loader.c","worker.debug.elf",["-static","-fno-pic","-Wl,-e,_start"])
    worker=inspect(out/"worker.debug.elf",True);raw=(out/"worker.debug.elf").read_bytes()
    blob=ko.read_bytes();positions=[]
    for segment in worker["segments"]:
        if segment["p_type"]=="PT_LOAD":
            payload=raw[segment["p_offset"]:segment["p_offset"]+segment["p_filesz"]]
            index=payload.find(blob)
            if index>=0:
                require(not segment["p_flags"]&2, "Embedded kernel blob is writable")
                positions.append(segment["p_vaddr"]+index)
    require(len(positions)==1, "Kernel blob must occur once in readonly LOAD data")
    limit=max(s["p_offset"]+s["p_filesz"] for s in worker["segments"] if s["p_type"]=="PT_LOAD")
    compact=bytearray(raw[:limit]);struct.pack_into("<Q",compact,40,0);struct.pack_into("<3H",compact,58,0,0,0)
    (out/"worker.elf").write_bytes(compact);(out/"worker_blob.h").write_text(array("worker_blob",compact))
    compile(NATIVE/"bootstrap.c","libJit.so",["-shared","-fPIC","-Wl,-Bsymbolic","-s"])
    bootstrap=inspect(out/"libJit.so",False);require(bootstrap["size"]<=65520,"Bootstrap upload bound")
    sources=[ROOT/"native/kernel_lease_loader.c",Path(__file__),ROOT/"emulate_kernel_lease.py",ROOT/"camera_inventory.py",NATIVE/"linux_a64.h",NATIVE/"bootstrap.c",NATIVE/"lifecycle_worker.c",KERNEL_MANIFEST,ko,POLICY/"completion.json",POLICY/"execution/proc_version"]+[KERNEL_MANIFEST.parent/p for p in km["source_hashes"]]
    sources += [ROOT/"output/kernel-resident-metadata-02/execution/lease_status", ROOT/"output/kernel-resident-metadata-02/completion.json"]
    meta={"schema":"camera-kernel-lease/1","model_only":model_only,"scope":SCOPE,"nonce":nonce.hex(),"job_dir":directory,"kernel":km,"worker":worker,"compact_worker_sha256":sha(out/"worker.elf"),"bootstrap":bootstrap,"sources":{str(p.relative_to(ROOT)):sha(p) for p in sources},"generated":{name:sha(out/name) for name in ("job.h","kernel_module_blob.h","worker_blob.h")},"compiler_sha256":sha(compiler),"upstream_commit":COMMIT,"expected_version_hex":version.hex(),"automatic_retry":False,"init_module_limit":1,"kernel_resident_until":"reboot","module_file_written":False,"device_execution_performed":False,"kernel_blob_readonly_address":positions[0],"serial_binding_sha256":sha(ROOT/"dumps/20261026-031555/backup_preset.bin")}
    save(out/"job.json",meta)
    for p in sources:
        dest=out/"sources"/p.relative_to(ROOT);dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(p.read_bytes())
    print(json.dumps({"job":str(out),"scope":SCOPE,"libJit_bytes":bootstrap["size"],"kernel_module_bytes":km["module_bytes"],"device_execution":False}))

def run(out, scope):
    require(sys.platform != "darwin" or os.geteuid() == 0,
            "macOS MSC access requires sudo: sudo -n env DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib .venv-offline/bin/python camera_kernel_lease.py run --job JOB")
    meta = json.loads((out / "job.json").read_text())
    run_guard(meta)
    scope_guard(meta, scope)
    require(sha(ROOT/"dumps/20261026-031555/backup_preset.bin")==meta["serial_binding_sha256"], "Original body binding changed")
    require(all(sha(ROOT / p) == value for p, value in meta["sources"].items()), "Reviewed source changed; rebuild/retest")
    require(sha(out / "libJit.so") == meta["bootstrap"]["sha256"] and sha(out / "worker.elf") == meta["compact_worker_sha256"], "Job binary changed")
    require((out / "emulation.json").exists(), "Offline emulation is required")
    emulation = json.loads((out / "emulation.json").read_text())
    require(emulation.get("all_passed") is True and emulation.get("worker_sha256") == meta["compact_worker_sha256"]
            and emulation.get("bootstrap_sha256") == meta["bootstrap"]["sha256"]
            and emulation.get("kernel_sha256") == meta["kernel"]["module_sha256"]
            and emulation.get("cases") == 33, "Emulation differs from sealed job")
    require(all(sha(out/p)==h for p,h in meta["generated"].items()), "Generated build input changed")
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
              "scope": SCOPE, "nor_requests": 0, "kernel_loads_maximum": 1, "kernel_resident_until": "reboot", "cleanup_does_not_unload_kernel": True}
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
        report["start_attempts"] = 1;report["verdict"] = "START_ATTEMPTED_KERNEL_RESIDENCY_UNKNOWN_UNTIL_REBOOT";save(evidence / "run.json", report)
        write("start", start_packet(meta))
        result = decode(poll("result", RESULT.size), meta);report["native"] = result
        require(result["phase"] in (4, 90), "Native lifecycle publication invalid")
        lease = decode_lease(poll("lease", LEASE.size), meta);report["lease"] = lease
        require(lease["version"] == 1 and lease["attempts"] in (0, 1), "Invalid lease attempt count")
        report["kernel_load_attempts"] = lease["attempts"]
        report["verdict"] = "REJECTED_BEFORE_KERNEL_LOAD" if not lease["attempts"] else "KERNEL_LOAD_FAILED_OR_RESIDENCY_UNKNOWN_UNTIL_REBOOT"
        status=read("module_status", 8192, True)
        if status is not None: (evidence/"module_status").write_bytes(status)
        if lease["stage"] == 4 and lease["error"] == 0 and result["phase"] == 4 and not result["error"]:
            require(result["flags"] == 3 and lease["attempts"] == 1 and lease["load_return"] == 0, "Invalid successful load claim")
            require(status is not None, "Successful lease has no raw status evidence")
            require(validate_status(status,meta)==lease["page_phys"], "Page report mismatch")
            report["verdict"] = "LEASE_READY_RESIDENT_UNTIL_REBOOT"
        for name, cap in (("loader_maps", 524288), ("loader_fds", 131072)):
            data = read(name, cap, True)
            if data is not None: (evidence / name).write_bytes(data)
        write("ack", b"M4KACK01" + bytes.fromhex(meta["nonce"]) + struct.pack("<Q", 1))
        cleaned = decode(poll("cleaned", RESULT.size), meta)
        require(cleaned["phase"] == 5 and cleaned["error"] == 0, "Cleanup failed")
        require(read_path("/tmp/jiritsu/libJit.so", 65520, True) is None, "Module cleanup not confirmed")
        report["ap_cleanup_verified"] = True
    try:
        senserShellCommand(complete=complete)
        require(report.get("ap_cleanup_verified") is True, "No completed AP cleanup callback")
    except BaseException as error:
        report["error"] = {"type": type(error).__name__, "message": str(error)}
        raise
    finally:
        save(evidence / "run.json", report)
    print(json.dumps({"verdict": report["verdict"], "evidence": str(evidence), "block_writes": False}))
    require(report["verdict"] == "LEASE_READY_RESIDENT_UNTIL_REBOOT", "Lease failed/rejected/unknown; do not retry until independently reviewed and rebooted")

if __name__ == "__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action",nargs="?",choices=("prepare","run"),default="prepare")
    parser.add_argument("--job",type=Path,required=True)
    parser.add_argument("--scope",default="",help="Separate authorization gate: job nonce:kernel-lease-only")
    parser.add_argument("--model-only",action="store_true",help="Seal an offline regression artifact; run will reject it")
    args=parser.parse_args()
    if args.action=="prepare": prepare(args.job.resolve(),args.model_only)
    else:
        code=0
        try: run(args.job.resolve(),args.scope)
        except BaseException:
            import traceback
            traceback.print_exc();code=1
        finally: sys.stdout.flush();sys.stderr.flush()
        os._exit(code)
