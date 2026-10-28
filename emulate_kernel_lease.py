import hashlib
"""Offline Unicorn model of the sealed lease AP worker; never invokes kernel APIs."""
import argparse
import json
import struct
from pathlib import Path

from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_INTR
from unicorn.arm64_const import UC_ARM64_REG_PC, UC_ARM64_REG_SP, UC_ARM64_REG_X0, UC_ARM64_REG_X8
from camera_kernel_lease import ROOT, RESULT, LEASE, decode, decode_lease, require, save, sha, start_packet, scope_guard, validate_status, run_guard


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
        directory + "/start": start_packet(meta),
        directory + "/ack": b"M4KACK01" + bytes.fromhex(meta["nonce"]) + struct.pack("<Q", 1),
        "/proc/123/maps": (b"1000 r-x /tmp/jiritsu/libJit.so\n" if scenario == "loader_busy" else b"1000 r-x /usr/lib/libJiritsu.so\n"),
        "/proc/version": bytes.fromhex(meta["expected_version_hex"]),
        "/proc/self/status": b"Name:\tworker\nCapEff:\t0000003fffffffff\n",
        "/proc/sys/kernel/modules_disabled": b"0\n",
        "/sys/module/module/parameters/sig_enforce": b"N\n",
    }
    state_path="/sys/module/m4btl_lease_01/initstate"
    status_path="/sys/module/m4btl_lease_01/parameters/status"
    if scenario=="bad_version": files["/proc/version"] += b"wrong"
    if scenario=="missing_version": del files["/proc/version"]
    if scenario=="no_cap": files["/proc/self/status"]=b"CapEff:\t0000000000020000\n"
    if scenario=="bad_cap": files["/proc/self/status"]=b"CapEff:\txyz\n"
    if scenario=="modules_disabled": files["/proc/sys/kernel/modules_disabled"]=b"1\n"
    if scenario=="sig_enforced": files["/sys/module/module/parameters/sig_enforce"]=b"Y\n"
    if scenario=="sig_missing": del files["/sys/module/module/parameters/sig_enforce"]
    if scenario=="already_loaded": files[state_path]=b"live\n"
    if scenario=="bad_start": files[directory+"/start"]=b"WRONG___"+files[directory+"/start"][8:]
    if scenario=="wrong_scope": files[directory+"/start"]=files[directory+"/start"][:32]+b"module-policy".ljust(32,b"\0")
    if scenario=="wrong_nonce": files[directory+"/start"]=files[directory+"/start"][:8]+bytes(16)+files[directory+"/start"][24:]
    if scenario=="no_start": del files[directory+"/start"]
    if scenario=="no_ack": del files[directory+"/ack"]
    directories = {"/proc/123/fd": entry(".", 4) + entry("0")}
    descriptors, opened, syscalls = {}, [], []
    state = {"nextfd": 3, "exit": None, "clock": 1, "published": {}, "loads":0, "start_consumed":False}
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
            if path==state_path and scenario=="initstate_error": ret(-13);return
            creating = flags & 3
            if creating:
                require(path.startswith(directory + "/") and flags == 0x880c1, "Write outside fixed tmpfs scope")
                if path in files:
                    ret(-17);return
                files[path] = b""
            else:
                require(flags in (0x88000, 0x8c000), "Unapproved source open flags")
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
            if path in (directory+"/lease",directory+"/module_status"):
                state["published"][path] = files[path]
            ret(c)
        elif number == 35:
            path = cstring(b);require(path.startswith(directory + "/"), "Out-of-scope unlink")
            if path in files:
                if path==directory+"/start": state["start_consumed"]=True
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
            ret(999 if scenario=="not_adopted" else 1)
        elif number == 113:
            uc.mem_write(b,struct.pack("<2q",state["clock"],0));state["clock"] += 1;ret(0)
        elif number == 101:
            ret(0)
        elif number == 78:
            require(descriptors[a][0] == "/proc/123/fd", "Unexpected readlink")
            uc.mem_write(c,b"/dev/null");ret(9)
        elif number == 105:
            require(state["loads"]==0 and state["start_consumed"],"Load before scoped START or repeated load")
            require(cstring(c)=="", "Nonempty module parameters")
            blob=bytes(uc.mem_read(a,b))
            require(hashlib.sha256(blob).hexdigest()==meta["kernel"]["module_sha256"] and b==meta["kernel"]["module_bytes"], "Embedded module changed")
            require(not any(p.endswith(".ko") for p,_ in opened), "Module file TOCTOU")
            state["loads"]+=1
            if scenario=="load_failed": ret(-1);return
            files[state_path]=b"coming\n" if scenario=="post_coming" else b"live\n"
            # Model the custom getter and actual kernel sysfs wrapper separately.
            getter_output=meta["kernel"]["synthetic_success_status"].encode()
            status=getter_output+b"\n"
            if scenario=="actual_sample": status=(ROOT/"output/kernel-resident-metadata-02/execution/lease_status").read_bytes()
            if scenario=="post_single_lf": status=getter_output
            if scenario=="post_third_lf": status+=b"\n"
            if scenario=="post_crlf": status=getter_output[:-1]+b"\r\n\n"
            if scenario=="post_tail_space": status+=b" "
            if scenario=="post_nonce": status=status.replace(meta["kernel"]["module_nonce"].encode(),b"0"*32)
            if scenario=="post_unaligned": status=status.replace(b"0x400000000",b"0x400000001")
            if scenario=="post_range": status=status.replace(b"0x400000000",b"0x500000000")
            if scenario=="post_malformed": status+=b"extra\n"
            files[status_path]=status
            if scenario=="post_missing": del files[status_path]
            ret(0)
        elif number == 94:
            state["exit"] = a;uc.emu_stop()
        else:
            raise RuntimeError(f"Unapproved syscall: {number}")
    uc.hook_add(UC_HOOK_INTR, interrupt)
    uc.emu_start(start, 0, count=4000000)
    require(state["exit"] is not None, "Worker exceeded instruction budget")
    result = decode(files[directory+"/result"],meta)
    lease=decode_lease(state["published"][directory+"/lease"],meta)
    success=scenario in ("success","short_reads","no_ack","actual_sample")
    load_cases=("success","short_reads","no_ack","load_failed","post_coming","post_nonce","post_unaligned","post_range","post_malformed","post_missing","actual_sample","post_single_lf","post_third_lf","post_crlf","post_tail_space")
    require(state["loads"]==int(scenario in load_cases), "Unexpected load count for "+scenario)
    require((result["phase"]==4 and not result["error"])==success,"Unexpected native outcome: "+scenario+str(result))
    require(lease["attempts"]==state["loads"],"Attempt report differs")
    if success:
        require(lease["stage"]==4 and not lease["error"] and lease["page_phys"]==(0x4037a5000 if scenario=="actual_sample" else 0x400000000),"Successful lease report")
        validate_status(state["published"][directory+"/module_status"],meta)
    elif state["loads"]:
        require(lease["stage"]==3 and lease["error"]<0,"Load failure/unknown lost")
    if state["loads"] and scenario not in ("load_failed","post_coming","post_missing"):
        require(state["published"][directory+"/module_status"]==files[status_path],"Raw poststatus not saved before validation")
    cleaned=decode(files[directory+"/cleaned"],meta)
    require(cleaned["phase"]==5 and not cleaned["error"],"AP cleanup failed")
    require(directory+"/lease" not in files and directory+"/module_status" not in files,"AP chunks retained")
    require(all(n not in syscalls for n in (29,106,222,226,273)),"Forbidden ioctl/unload/map/finit")
    allowed=("/proc/123/maps","/proc/123/fd","/proc/self/fd","/proc/version","/proc/self/status","/proc/sys/kernel/modules_disabled","/sys/module/module/parameters/sig_enforce",state_path,status_path)
    require(all(p in allowed or p.startswith(directory+"/") for p,_ in opened),"Read outside fixed scope")
    require(not any(p.startswith("/dev/") or p.endswith(".ko") for p,_ in opened),"Device or module file opened")
    return {"scenario":scenario,"passed":True,"init_module_model_calls":state["loads"],"native":result,"lease":lease,"syscalls":sorted(set(syscalls)),"kernel_effects_simulated_only":True,"no_unload":True,"ap_cleanup_verified":True}

CASES=("success","short_reads","not_root","not_tmpfs","inherited_fd","loader_busy","bad_start","wrong_scope","wrong_nonce","no_start","not_adopted","bad_version","missing_version","no_cap","bad_cap","modules_disabled","sig_enforced","sig_missing","already_loaded","initstate_error","load_failed","post_coming","post_nonce","post_unaligned","post_range","post_missing","no_ack","post_malformed","actual_sample","post_single_lf","post_third_lf","post_crlf","post_tail_space")
# Host parser and scope guards are tested independently of guest emulation.
def main(job):
    meta=json.loads((job/"job.json").read_text())
    tests=[emulate(job,s) for s in CASES]
    if meta.get("model_only"):
        try: run_guard(meta)
        except RuntimeError: pass
        else: raise RuntimeError("MODEL_ONLY run gate accepted regression job")
    for scope in ("",meta["nonce"]+":module-policy","0"*32+":kernel-lease-only"):
        try: scope_guard(meta,scope)
        except RuntimeError: pass
        else: raise RuntimeError("Host scope gate accepted wrong authorization")
    scope_guard(meta,meta["nonce"]+":kernel-lease-only")
    for raw in (meta["kernel"]["synthetic_success_status"].encode()+b"extra\n",):
        try: validate_status(raw,meta)
        except RuntimeError: pass
        else: raise RuntimeError("Malformed poststatus accepted")
    evidence={"all_passed":True,"cases":len(tests),"tests":tests,"worker_sha256":sha(job/"worker.elf"),"bootstrap_sha256":sha(job/"libJit.so"),"kernel_sha256":meta["kernel"]["module_sha256"],"model_only":True,"camera_execution":False,"host_scope_negative_checks":3,"kernel_loads_performed":0,"model_only_run_guard_rejected":bool(meta.get("model_only")),"actual_recovered_status_sha256":sha(ROOT/"output/kernel-resident-metadata-02/execution/lease_status"),"invalid_raw_status_saved_before_validation":True}
    save(job/"emulation.json",evidence);print(json.dumps({"all_passed":True,"cases":len(tests),"camera_execution":False}))
if __name__=="__main__":
    parser=argparse.ArgumentParser();parser.add_argument("job",type=Path);main(parser.parse_args().job.resolve())
