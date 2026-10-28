import hashlib
"""Offline Unicorn model of the sealed lease AP worker; never invokes kernel APIs."""
import argparse
import json
import struct
from pathlib import Path
from unittest.mock import patch
import camera_kernel_cspi52 as host

from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_INTR
from unicorn.arm64_const import UC_ARM64_REG_PC, UC_ARM64_REG_SP, UC_ARM64_REG_X0, UC_ARM64_REG_X8
from camera_kernel_cspi52 import ROOT, RESULT, CSPI, decode, decode_cspi, require, save, sha, start_packet, scope_guard, validate_status, validate_success, run_guard


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
        directory + "/ack": b"M4CACK01" + bytes.fromhex(meta["nonce"]) + struct.pack("<Q", 1),
        "/proc/123/maps": (b"1000 r-x /tmp/jiritsu/libJit.so\n" if scenario == "loader_busy" else b"1000 r-x /usr/lib/libJiritsu.so\n"),
        "/proc/version": bytes.fromhex(meta["expected_version_hex"]),
        "/proc/self/status": b"Name:\tworker\nCapEff:\t0000003fffffffff\n",
        "/proc/sys/kernel/modules_disabled": b"0\n",
        "/sys/module/module/parameters/sig_enforce": b"N\n",
    }
    state_path="/sys/module/m4btl_cspi52_01/initstate"
    status_path="/sys/module/m4btl_cspi52_01/parameters/status"
    submit_path="/sys/module/m4btl_cspi52_01/parameters/submit"
    payload=bytes(range(52))
    if scenario=="done_zero":payload=bytes(52)
    if scenario=="done_ones":payload=bytes([255])*52
    fake_page=payload+bytes([0xa5])*(4096-52)
    def status_wire(kind="ready",page=0x400000000):
        submitted,done,err,rc,valid={"ready":(0,0,0,-115,0),"pending":(1,0,0,0,0),"done":(1,1,0,0,1),"error":(1,1,-5,0,0),"submit-error":(1,0,0,-5,0)}[kind]
        raw=payload.hex() if kind=="done" else "0"*104
        getter=(f"schema=1 profile=cspi52-once nonce={meta['kernel']['module_nonce']} state={kind} page_bytes=4096 page_phys=0x{page:x} submitted={submitted} done={done} err={err} rc={rc} raw_valid={valid} raw={raw} resident=boot source=0x4011e74d4 pci=0 dmac=4 size=52").encode()
        wire=getter+b"\n" # The custom getter has no LF; actual sysfs adds one.
        if scenario=="double_lf":wire+=b"\n"
        if scenario=="no_lf":wire=getter
        if scenario=="crlf":wire=getter+b"\r\n"
        if scenario=="tail_space":wire+=b" "
        if scenario=="bad_nonce":wire=wire.replace(meta['kernel']['module_nonce'].encode(),b"0"*32)
        if scenario=="bad_source":wire=wire.replace(b"source=0x4011e74d4",b"source=0x4011e74d8")
        if scenario=="bad_size":wire=wire.replace(b"size=52\n",b"size=56\n")
        if scenario=="bad_ready":wire=wire.replace(b"rc=-115",b"rc=0")
        if kind=="done":
            if scenario=="raw_short":wire=wire.replace(raw.encode(),raw[:-1].encode())
            if scenario=="raw_long":wire=wire.replace(raw.encode(),(raw+"00").encode())
            if scenario=="raw_upper":wire=wire.replace(raw.encode(),raw.upper().encode())
            if scenario=="done_invalid":wire=wire.replace(b"raw_valid=1",b"raw_valid=0")
        if scenario=="pending_claims_raw" and kind=="pending":wire=wire.replace(b"raw_valid=0",b"raw_valid=1")
        if scenario=="error_claims_raw" and kind=="error":wire=wire.replace(b"raw_valid=0",b"raw_valid=1")
        return wire
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
    if scenario in ("no_ack","pending_no_ack"): del files[directory+"/ack"]
    if scenario=="ack_wrong":files[directory+"/ack"]=b"M4CACK01"+bytes(16)+struct.pack("<Q",1)
    if scenario=="ack_partial":files[directory+"/ack"]=files[directory+"/ack"][:31]
    directories = {"/proc/123/fd": entry(".", 4) + entry("0")}
    descriptors, opened, syscalls = {}, [], []
    state = {"nextfd": 3, "exit": None, "clock": 1, "published": {}, "loads":0, "start_consumed":False,"submits":0,"status_reads":0,"payload_read_indices":[],"payload_cached":False}
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
            if path==submit_path:
                require(flags==0x88001 and state["loads"]==1 and state["submits"]==0,"Bad/repeated submit open")
                require(directory+"/submit_intent" in files and directory+"/load_intent" in files,"Missing pre-action intent")
                if scenario=="submit_open_error":ret(-13);return
                fd=state["nextfd"];state["nextfd"]+=1;descriptors[fd]=[path,0,True];ret(fd);return
            if path==status_path and state["submits"]:
                state["status_reads"]+=1
                if scenario=="status_lost":files.pop(status_path,None)
                elif scenario not in ("pending","pending_claims_raw","pending_no_ack","late_after_deadline","submit_error","early_submit_error","callback_error","error_claims_raw","short_write","write_eintr"):
                    kind="pending" if scenario=="delayed_done" and state["status_reads"]<4 else "done"
                    files[status_path]=status_wire(kind,0x400001000 if scenario=="post_page_change" else 0x400000000)
                if scenario=="post_nonce":files[status_path]=status_wire("done").replace(meta['kernel']['module_nonce'].encode(),b"1"*32)
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
            if number==63 and path==status_path and pos==0 and b" state=done " in raw and b" err=0 rc=0 raw_valid=1 " in raw and not state["payload_cached"]:
                # Fake kernel status getter, not AP pointer access. Model exactly
                #52 single-byte READ_ONCE after DONE/noerror; never read sentinel.
                captured=bytearray()
                for i in range(52):state["payload_read_indices"].append(i);captured.append(fake_page[i])
                require(bytes(captured)==payload,"Mock kernel read outside exact52")
                state["payload_cached"]=True
            n = min(len(raw) - pos, c)
            if scenario == "short_reads" and number == 63:
                n = min(n, 3)
            if n:
                uc.mem_write(b, raw[pos:pos+n])
            descriptors[a][1] += n;ret(n)
        elif number == 64:
            path,_,creating = descriptors[a]
            if path==submit_path:
                require(creating and state["submits"]==0 and state["loads"]==1,"Repeated/early submit")
                require(c==32 and bytes(uc.mem_read(b,c))==meta["kernel"]["module_nonce"].encode(),"Wrong submit bytes")
                state["submits"]+=1
                kind="submit-error" if scenario in ("submit_error","early_submit_error") else "error" if scenario in ("callback_error","error_claims_raw") else "done" if scenario=="early_done" else "pending"
                files[status_path]=status_wire(kind)
                if scenario=="early_submit_error":files[status_path]=files[status_path].replace(b"done=0",b"done=1")
                ret(-5 if scenario in ("submit_error","early_submit_error") else -4 if scenario=="write_eintr" else 31 if scenario=="short_write" else 32);return
            require(creating and path.startswith(directory + "/"), "Write descriptor escaped tmpfs")
            files[path] += bytes(uc.mem_read(b,c))
            if path==directory+"/cspi" or path.startswith(directory+"/status") or path.endswith("_intent"):
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
            require(directory+"/load_intent" in files,"No load intent before105")
            files[state_path]=b"coming\n" if scenario=="post_coming" else b"live\n"
            files[status_path]=status_wire("pending" if scenario=="already_pending" else "ready",0x400000001 if scenario=="unaligned" else 0x500000000 if scenario=="range" else 0x400000000)
            if scenario=="post_missing":del files[status_path]
            ret(0)
        elif number == 94:
            state["exit"] = a;uc.emu_stop()
        else:
            raise RuntimeError(f"Unapproved syscall: {number}")
    uc.hook_add(UC_HOOK_INTR, interrupt)
    uc.emu_start(start, 0, count=4000000)
    require(state["exit"] is not None, "Worker exceeded instruction budget")
    # Completion may arrive AFTER this worker stops observing. It must not
    # trigger any implicit retry/reset or retroactively turn pending into done.
    if scenario=="late_after_deadline":files[status_path]=status_wire("done")
    result=decode(files[directory+"/result"],meta)
    cspi=decode_cspi(state["published"][directory+"/cspi"],meta)
    load_cases=("success","short_reads","no_ack","load_failed","post_coming","post_missing","double_lf","no_lf","crlf","tail_space","bad_nonce","bad_source","bad_size","bad_ready","already_pending","unaligned","range","submit_open_error","early_done","delayed_done","pending","late_after_deadline","submit_error","early_submit_error","callback_error","short_write","write_eintr","status_lost","post_page_change","post_nonce","done_zero","done_ones","raw_short","raw_long","raw_upper","done_invalid","pending_claims_raw","error_claims_raw","pending_no_ack","ack_wrong","ack_partial")
    submit_cases=("success","short_reads","no_ack","early_done","delayed_done","pending","late_after_deadline","submit_error","early_submit_error","callback_error","short_write","write_eintr","status_lost","post_page_change","post_nonce","done_zero","done_ones","raw_short","raw_long","raw_upper","done_invalid","pending_claims_raw","error_claims_raw","pending_no_ack","ack_wrong","ack_partial")
    success=scenario in ("success","short_reads","no_ack","early_done","delayed_done","done_zero","done_ones","ack_wrong","ack_partial")
    require(state["loads"]==int(scenario in load_cases),"Unexpected105 count: "+scenario)
    require(state["submits"]==int(scenario in submit_cases),"Unexpected sysfs submit count: "+scenario)
    require(cspi["loads"]==state["loads"],"Load report differs")
    require(cspi["submits"]==(state["submits"]+int(scenario=="submit_open_error")),"Submit intent report differs")
    require((result["phase"]==4 and not result["error"])==success,"Unexpected outcome "+scenario+str(cspi))
    for i in range(cspi["snapshots"]):
        raw=state["published"][directory+f"/status{i:02d}"]
        require(raw is not None,"Raw status lost before parse")
    if success:
        require(cspi["stage"]==6 and cspi["raw_hex"]==payload.hex() and cspi["state"]==3,"Wrong terminal raw52 payload")
        require(state["payload_read_indices"]==list(range(52)),"Kernel mock did not capture exactly52 bytes once")
        snapshots=[validate_status(state["published"][directory+f"/status{i:02d}"],meta,cspi["page_phys"]) for i in range(cspi["snapshots"])]
        validate_success(cspi,result,snapshots)
        for key,bad in (("state",2),("done",0),("err",-5),("rc",-5),("raw_valid",0),("raw_hex",("01" if cspi["raw_hex"][:2]!="01" else "02")+cspi["raw_hex"][2:]),("page_phys",0x400001000)):
            broken=dict(cspi);broken[key]=bad
            try:validate_success(broken,result,snapshots)
            except RuntimeError:pass
            else:raise RuntimeError("Inconsistent report accepted: "+key)
    if scenario in ("pending","pending_no_ack","late_after_deadline"):
        require(cspi["polls"]==50 and cspi["state"]==2 and cspi["error"]==-110,"Pending deadline reset/retry/terminal fabrication")
    if scenario in ("pending","pending_no_ack","pending_claims_raw","late_after_deadline","submit_error","early_submit_error","callback_error","error_claims_raw","short_write","write_eintr","status_lost"):
        require(not state["payload_read_indices"],"Pending/error state claimed payload read")
        require(cspi["raw_valid"]==0,"Pending/error report claimed data")
    cleaned=decode(files[directory+"/cleaned"],meta)
    if scenario in ("no_ack","pending_no_ack","ack_wrong","ack_partial"):
        require(cleaned["phase"]==5 and cleaned["error"]==-110,"Missing ACK incorrectly claimed cleanup")
        require(directory+"/cspi" in files and directory+"/submit_intent" in files and directory+"/status00" in files,"Unknown/noACK raw evidence was deleted")
    else:
        require(cleaned["phase"]==5 and not cleaned["error"],"AP cleanup failed")
        require(directory+"/cspi" not in files and directory+"/status00" not in files,"Acknowledged AP records not cleaned")
    require(all(n not in syscalls for n in (29,106,222,226,273)),"Forbidden ioctl/unload/map/finit")
    allowed=("/proc/123/maps","/proc/123/fd","/proc/self/fd","/proc/version","/proc/self/status","/proc/sys/kernel/modules_disabled","/sys/module/module/parameters/sig_enforce",state_path,status_path,submit_path)
    require(all(p in allowed or p.startswith(directory+"/") for p,_ in opened),"Read outside fixed scope")
    require(not any(p.startswith("/dev/") or p.endswith(".ko") for p,_ in opened),"Device/module file opened")
    return {"scenario":scenario,"passed":True,"native":result,"cspi":cspi,"syscalls":sorted(set(syscalls)),"init_module_calls_modeled":state["loads"],"submit_writes_modeled":state["submits"],"no_unload_reset_free_retry":True,"mock_payload_read_indices":state["payload_read_indices"],"mock_only_not_actual_kernel_execution":True,"AP_cleanup_separate_from_kernel_lifetime":True,"AP_cleanup_verified":not bool(cleaned["error"]),"AP_raw_retained_without_valid_ACK":scenario in ("no_ack","pending_no_ack","ack_wrong","ack_partial"),"camera_execution":False}

CASES=("success","short_reads","not_root","not_tmpfs","inherited_fd","loader_busy","bad_start","wrong_scope","wrong_nonce","no_start","not_adopted","bad_version","missing_version","no_cap","bad_cap","modules_disabled","sig_enforced","sig_missing","already_loaded","initstate_error","load_failed","post_coming","post_missing","double_lf","no_lf","crlf","tail_space","bad_nonce","bad_source","bad_size","bad_ready","already_pending","unaligned","range","submit_open_error","early_done","delayed_done","pending","late_after_deadline","submit_error","early_submit_error","callback_error","short_write","write_eintr","status_lost","post_page_change","post_nonce","no_ack","done_zero","done_ones","raw_short","raw_long","raw_upper","done_invalid","pending_claims_raw","error_claims_raw","pending_no_ack","ack_wrong","ack_partial")
def main(job):
    meta=json.loads((job/"job.json").read_text());tests=[emulate(job,s) for s in CASES]
    if meta.get("model_only"):
        try:run_guard(meta)
        except RuntimeError:pass
        else:raise RuntimeError("MODEL_ONLY allowed")
    if not meta.get("model_only"):run_guard(meta)
    for admission in (None,{},dict(meta["source_admission"],sha256="0"*64)):
        broken=dict(meta);broken["source_admission"]=admission
        try:run_guard(broken)
        except RuntimeError:pass
        else:raise RuntimeError("Missing/mismatched static source admission accepted")
    # Test receipt and EACH referenced evidence hash without touching sealed files.
    original_sha=host.sha
    for target in [host.SOURCE_ADMISSION]+[host.ROOT/p for p in meta["source_admission"]["evidence"]]:
        with patch.object(host,"sha",side_effect=lambda p,target=target: "0"*64 if Path(p)==target else original_sha(p)):
            try:host.verify_source_admission()
            except RuntimeError:pass
            else:raise RuntimeError("Changed admission/evidence hash accepted: "+str(target))
    for scope in ("",meta["nonce"]+":kernel-lease-only","0"*32+":kernel-cspi52-once"):
        try:scope_guard(meta,scope)
        except RuntimeError:pass
        else:raise RuntimeError("Wrong scope accepted")
    scope_guard(meta,meta["nonce"]+":kernel-cspi52-once")
    evidence={"all_passed":True,"cases":len(tests),"tests":tests,"worker_sha256":sha(job/"worker.elf"),"bootstrap_sha256":sha(job/"libJit.so"),"kernel_sha256":meta["kernel"]["module_sha256"],"model_only":True,"camera_execution":False,"kernel_loads_performed":0,"DMA_submits_performed":0,"host_scope_negative_checks":3,"host_source_admission_negative_checks":9,"opaque_raw52_only_no_controller_state_interpretation":True}
    save(job/"emulation.json",evidence);print(json.dumps({"all_passed":True,"cases":len(tests),"camera_execution":False}))
if __name__=="__main__":
    parser=argparse.ArgumentParser();parser.add_argument("job",type=Path);main(parser.parse_args().job.resolve())
