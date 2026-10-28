"""Offline CSPI52 one-shot candidate; execution requires a distinct explicit scope.
One module load and one fixed nonce submit; objects remain resident until reboot.
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
SCOPE = "kernel-cspi52-once"
CSPI = struct.Struct("<8s16s16q52s4x")
CSPI_FIELDS = ("version","stage","error","loads","load_return","submits","write_return","polls","snapshots","page_phys","state","reserved","done","err","rc","raw_valid")
IMPORTS = {"__get_free_pages", "arch_va_to_phys", "arch_p32_to_p64", "scnprintf", "__udif_cache_ctrl", "pcidma_transfer_async"}
KERNEL_MANIFEST = ROOT / "output/pcidma-OFFLINE_CSPI52_ONCE-01/manifest.json"
POLICY = ROOT / "output/module-policy-01"
SOURCE_FACTS=ROOT/"output/rea-study/cspi-fixed-metadata-review-01/review.json"
SOURCE_ADMISSION=ROOT/"output/rea-study/cspi-fixed-metadata-review-01/root-source-admission.json"
SOURCE_FACTS_SHA="8e3c63c4574b09cba0dc33aced9ebe7750ccea7f651d6151519e2a9f4fead79c"
SOURCE_ADMISSION_SHA="8c991b0321ac575d7eb7745f1a92bd8c6c6b7fced9ed0e599e6cc27e7d1fd055"

def decode(raw, meta):
    require(len(raw) == RESULT.size, "Partial native result")
    magic, nonce, *values = RESULT.unpack(raw)
    require(magic == b"M4C52001" and nonce.hex() == meta["nonce"], "Native identity changed")
    return dict(zip(FIELDS, values))

def decode_cspi(raw, meta):
    require(len(raw)==CSPI.size,"Partial CSPI52 report")
    magic,nonce,*values=CSPI.unpack(raw)
    require(magic==b"M4C52PT1" and nonce.hex()==meta["nonce"],"CSPI52 report identity changed")
    item=dict(zip(CSPI_FIELDS,values[:-1]));item["raw_hex"]=values[-1].hex()
    require(item["reserved"]==0,"Unexpected CSPI report reserved field")
    return item

def start_packet(meta):
    return b"M4CSTART" + bytes.fromhex(meta["nonce"]) + struct.pack("<Q", 1) + SCOPE.encode().ljust(32, b"\0")

def validate_status(raw, meta, expected_page=None):
    # Request/helper state only; no CSPI controller readiness interpretation.
    # Getter has no LF, actual sysfs adds exactly one LF.
    nonce=meta["kernel"]["module_nonce"]
    pattern=(rb"schema=1 profile=cspi52-once nonce="+nonce.encode()+
             rb" state=(ready|pending|done|error|submit-error) page_bytes=4096 page_phys=0x([0-9a-f]+) submitted=([01]) done=([01]) err=(-?[0-9]+) rc=(-?[0-9]+) raw_valid=([01]) raw=([0-9a-f]{104}) resident=boot source=0x4011e74d4 pci=0 dmac=4 size=52\n")
    match=re.fullmatch(pattern,raw);require(match is not None,"CSPI52 status wire/identity/source/raw-length mismatch")
    state,pa,submitted,done,err,rc,valid,payload=match.groups()
    require(not (len(pa)>1 and pa.startswith(b"0")),"Noncanonical physical hex")
    for value in (err,rc):require(str(int(value)).encode()==value and -(1<<31)<=int(value)<(1<<31),"Noncanonical status integer")
    item={"state":state.decode(),"page_phys":int(pa,16),"submitted":int(submitted),"done":int(done),"err":int(err),"rc":int(rc),"raw_valid":int(valid),"raw_hex":payload.decode()}
    require(0x400000000<=item["page_phys"]<=0x4fffff000 and item["page_phys"]%4096==0,"Own page outside range/alignment")
    require(expected_page is None or expected_page==item["page_phys"],"Own page changed during request")
    s,d,e,r,v=[item[k] for k in ("submitted","done","err","rc","raw_valid")];zero=payload==b"0"*104
    conditions={"ready":s==0 and d==0 and e==0 and r==-115 and v==0 and zero,
                "pending":s==1 and d==0 and e==0 and r==0 and v==0 and zero,
                "done":s==1 and d==1 and e==0 and r==0 and v==1,
                "error":s==1 and d==1 and e!=0 and r==0 and v==0 and zero,
                "submit-error":s==1 and r!=0 and v==0 and zero and (d==1 or e==0)}
    require(conditions[item["state"]],"CSPI52 request-state fields inconsistent")
    return item

def validate_success(cspi,native,snapshots):
    require(cspi["stage"]==6 and cspi["error"]==0 and native["phase"]==4 and native["error"]==0 and native["flags"]==3,"CSPI52 lifecycle not successful")
    require(cspi["loads"]==cspi["submits"]==1 and cspi["load_return"]==0 and cspi["write_return"]==32,"Invalid CSPI52 success counters")
    require(cspi["state"]==3 and cspi["done"]==1 and cspi["err"]==0 and cspi["rc"]==0 and cspi["raw_valid"]==1,"CSPI52 report terminal fields inconsistent")
    require(snapshots and all("parse_error" not in item for item in snapshots) and snapshots[0].get("state")=="ready" and snapshots[-1].get("state")=="done","CSPI52 raw status-state mismatch")
    require(all(snapshots[-1][k]==cspi[k] for k in ("page_phys","raw_hex","done","err","rc","raw_valid")),"CSPI52 report differs from terminal raw snapshot")

def verify_source_facts():
    require(sha(SOURCE_FACTS)==SOURCE_FACTS_SHA,"CSPI52 source facts changed")
    facts=json.loads(SOURCE_FACTS.read_text());span=facts["preferred_single_span"];source=facts["source"]
    require(int(span["p32"],16)==0x011e74d4 and span["bytes"]==52 and int(span["end_exclusive"],16)==0x011e7508,"Fixed CSPI52 metadata span changed")
    require(span["no_ready_or_initialized_flag"] is True and span["atomic_snapshot_not_established"] is True and span["no_build_or_hardware_admission"] is True,"Raw-only facts boundary changed")
    require(int(facts["BSS"]["bulkclear_start"],16)<=0x011e74d4 and 0x011e7508<=int(facts["BSS"]["end_exclusive"],16) and facts["BSS"]["state_and_table_in_bulkcleared_BSS"] is True,"Fixed source not within reviewed software BSS")
    require(sha(ROOT/source["path"])==source["sha256"] and (ROOT/source["path"]).stat().st_size==source["bytes"],"Original CP source changed")
    for path,h in facts["source_proof_hashes"].items():require(sha(ROOT/path)==h,"CSPI52 source evidence changed: "+path)
    return {"path":str(SOURCE_FACTS.relative_to(ROOT)),"sha256":SOURCE_FACTS_SHA,"original_source":source}

def verify_source_admission():
    require(sha(SOURCE_ADMISSION)==SOURCE_ADMISSION_SHA,"Explicit CSPI52 source admission changed")
    receipt=json.loads(SOURCE_ADMISSION.read_text())
    require(receipt["schema"]=="camera-use/cp-cspi52-probe-source-admission/1" and receipt["static_ordinary_ram_basis_accepted"] is True and receipt["eligible_for_single_probe_review"] is True,"CSPI52 source not admitted for diagnostic review")
    profile=receipt["profile"]
    require(profile["cp_p32"]=="0x011e74d4" and profile["pci_source_u64"]=="0x4011e74d4" and profile["bytes"]==52 and profile["end_exclusive_cp_p32"]=="0x011e7508","CSPI52 admission profile changed")
    require(receipt["source_facts"]=={"path":str(SOURCE_FACTS.relative_to(ROOT)),"sha256":SOURCE_FACTS_SHA},"CSPI52 facts/admission disagree")
    for key in ("runtime_endpoint_route_verified","current_epoch_binding_verified","prior_BSS4_word_match_proves_this_span","hardware_execution_authorized","snapshot_atomic","controller_pointer_follow_allowed","initialized_or_NOR_ready_inference_allowed"):
        require(receipt[key] is False,"Admission is raw-only, not readiness/route/epoch/authorization")
    require(receipt["max_loads"]==receipt["max_submit_writes"]==1 and receipt["expected_content"] is None and receipt["new_user_scope_required"]==SCOPE,"CSPI52 one-shot/raw-only boundary changed")
    for path,h in receipt["evidence"].items():require(sha(ROOT/path)==h,"CSPI52 admission evidence changed: "+path)
    return {"path":str(SOURCE_ADMISSION.relative_to(ROOT)),"sha256":SOURCE_ADMISSION_SHA,"evidence":receipt["evidence"]}

def run_guard(meta):
    require(meta.get("model_only") is not True, "MODEL_ONLY regression artifact cannot run on a device")
    require(meta.get("source_admission")==verify_source_admission(),"Job lacks exact explicit source admission pin")
    require(meta.get("current_endpoint_binding_unproven") is True,"Diagnostic cannot assume current endpoint binding")

def scope_guard(meta, scope):
    require(meta.get("schema") == "camera-kernel-cspi52/1" and meta.get("scope") == SCOPE, "Wrong fixed scope")
    require(scope == meta["nonce"] + ":" + SCOPE, "Separate explicit nonce:kernel-cspi52-once scope required")

def check_kernel(manifest):
    require(sha(manifest)=="3b4a281e1596daf2d7d8e3794e8b1c695cd729546eec23e18d74a34b51b372f0", "Sealed CSPI manifest changed")
    m = json.loads(manifest.read_text()); require(m["schema"] == "m4btl-offline-cspi52-once/1", "Wrong kernel manifest")
    require(m["module_name"]=="m4btl_cspi52_01" and m["module_nonce"]=="459b4806b1851c82afaf9ad5a2d8ac61" and m["module_bytes"]==8112 and m["module_sha256"]=="6b3208beb42fc6240196f9b5afec532ce861fe4a0a9ca59577f7da11c1dbe2cc","CSPI sealed identity mismatch")
    require(m["module_loads_performed"]==0 and m["real_DMA_requests"]==0 and m["camera_io"] is False and m["exact_analysis_binding"] is True, "Not sealed offline evidence")
    require(m["getter_supplies_LF"] is False and m["submit_bytes_count"]==32 and m["submit_bytes_ascii"]==m["module_nonce"], "CSPI wire contract changed")
    require(m["source"]["required_p64"]=="0x4011e74d4" and m["source"]["region_verified"] is False and m["source"]["source_admission_pending"] is True, "Source admission metadata changed")
    require(m["source_proof_refs"]["sourceproof/original-cp-source-review.json"]["sha256"]==SOURCE_FACTS_SHA and m["source_proof_refs"]["sourceproof/root-cspi-prefix-model.json"]["sha256"]==ROOT_SOURCE_MODEL_SHA,"Kernel sourceproof refs differ")
    require(m["request"]["pci"]==0 and m["request"]["dmac"]==4 and m["request"]["size"]==52 and m["request"]["max_submissions"]==1, "Fixed request changed")
    for p,item in m["files"].items():require(sha(manifest.parent/p)==item["sha256"] and (manifest.parent/p).stat().st_size==item["bytes"], "Sealed evidence changed: "+p)
    kernel_model=json.loads((manifest.parent/"offline-model.json").read_text())
    require(kernel_model["assertions_passed"] is True and kernel_model["candidate_sha256"]==m["module_sha256"] and len(kernel_model["cases"])==23, "Kernel model/binding failed")
    require(m["status_path"] == "/sys/module/m4btl_cspi52_01/parameters/status" and m["status_permissions"] == "0400", "Status getter changed")
    require(m["submit_path"]=="/sys/module/m4btl_cspi52_01/parameters/submit" and m["submit_permissions"]=="0200", "Submit node changed")
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
        require(elf.get_section_by_name(".gnu.linkonce.this_module").data()[0x18:0x50].split(b"\0",1)[0] == b"m4btl_cspi52_01" and b"vermagic=4.9.337-scel SMP preempt mod_unload aarch64" in modinfo, "Kernel name/vermagic mismatch")
    return m,ko

def prepare(out, model_only=False):
    require(not out.exists(), "Choose a fresh job directory")
    require(subprocess.check_output(["git","-C",str(UPSTREAM),"rev-parse","HEAD"],text=True).strip()==COMMIT, "Upstream commit changed")
    require(not subprocess.check_output(["git","-C",str(UPSTREAM),"status","--porcelain"],text=True).strip(), "Upstream checkout changed")
    source_facts=verify_source_facts()
    source_admission=verify_source_admission()
    km,ko=check_kernel(KERNEL_MANIFEST)
    require(sha(POLICY/"completion.json")=="ff140e3b32122ca7a4cb5fb2fbbfc927d245bb4f1bdd857fe9015ccbc83e307a", "Host policy evidence changed")
    policy=json.loads((POLICY/"completion.json").read_text())
    require(policy["metadata_verified"] is True and policy["policy_unchanged"] is True and policy["kernel_module_loads"]==0, "Policy evidence changed")
    version=(POLICY/"execution/proc_version").read_bytes(); require(version.startswith(b"Linux version 4.9.337-scel ") and version.endswith(b"\n"), "Wrong captured kernel")
    nonce=secrets.token_bytes(16); directory="/tmp_wbshd/m4c52_"+nonce.hex();out.mkdir(parents=True)
    def array(name,payload): return "static const unsigned char "+name+"[]={"+",".join(map(str,payload))+"};\n"
    (out/"job.h").write_text('#define JOB_DIR "'+directory+'"\n'+array("job_nonce",nonce))
    prefix="schema=1 profile=cspi52-once nonce="+km["module_nonce"]+" state="
    (out/"kernel_module_blob.h").write_text(array("kernel_lease_module",ko.read_bytes())+array("expected_version",version)+'static const char lease_scope[32]="kernel-cspi52-once";\nstatic const char cspi_prefix[]='+json.dumps(prefix)+';\nstatic const char cspi_nonce[]='+json.dumps(km["module_nonce"])+';\n')
    compiler=ROOT/"local/zig-aarch64-macos-0.15.2/zig"
    flags=["cc","-target","aarch64-linux-gnu","-mcpu=generic","-Os","-g","-ffreestanding","-fno-builtin","-fno-stack-protector","-fno-unwind-tables","-fno-asynchronous-unwind-tables","-nostdlib","-ffunction-sections","-fdata-sections","-Wl,--gc-sections","-Wl,--no-undefined","-Wl,--build-id=none","-Wl,-z,noexecstack","-Wl,-z,max-page-size=4096","-Wl,-z,common-page-size=4096","-I",str(out),"-I",str(NATIVE)]
    def compile(source,name,extra):
        r=subprocess.run([str(compiler),*flags,*extra,str(source),"-o",str(out/name)],capture_output=True,text=True,timeout=120)
        (out/(name+".compile.log")).write_text(r.stdout+r.stderr); require(r.returncode==0,r.stderr[-3000:])
    compile(ROOT/"native/kernel_cspi52_once.c","worker.debug.elf",["-static","-fno-pic","-Wl,-e,_start"])
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
    sources=[ROOT/"native/kernel_cspi52_once.c",Path(__file__),ROOT/"emulate_kernel_cspi52.py",ROOT/"camera_inventory.py",NATIVE/"linux_a64.h",NATIVE/"bootstrap.c",NATIVE/"lifecycle_worker.c",KERNEL_MANIFEST,ko,POLICY/"completion.json",POLICY/"execution/proc_version"]+[KERNEL_MANIFEST.parent/p for p in km["source_hashes"]]

    sources += [SOURCE_FACTS,SOURCE_ADMISSION,ROOT/source_facts["original_source"]["path"]]+[ROOT/p for p in source_admission["evidence"]]
    meta={"schema":"camera-kernel-cspi52/1","source_facts":source_facts,"source_admission":source_admission,"model_only":model_only,"current_endpoint_binding_unproven":True,"payload_semantics":"opaque exact52B metadata only; no initialization/readiness or value interpretation","pre_device_conditions":["user confirms charged camera with normal viewfinder and menu","fresh kernel/body/policy match","separate future nonce:kernel-cspi52-once grant"],"scope":SCOPE,"nonce":nonce.hex(),"job_dir":directory,"kernel":km,"worker":worker,"compact_worker_sha256":sha(out/"worker.elf"),"bootstrap":bootstrap,"sources":{str(p.relative_to(ROOT)):sha(p) for p in sources},"generated":{name:sha(out/name) for name in ("job.h","kernel_module_blob.h","worker_blob.h")},"compiler_sha256":sha(compiler),"upstream_commit":COMMIT,"expected_version_hex":version.hex(),"automatic_retry":False,"init_module_limit":1,"submit_write_limit":1,"poll_limit":50,"poll_interval_ms":100,"fixed_source":"0x4011e74d4","fixed_bytes":52,"kernel_resident_until":"reboot","module_file_written":False,"device_execution_performed":False,"kernel_blob_readonly_address":positions[0],"serial_binding_sha256":sha(ROOT/"dumps/20261026-031555/backup_preset.bin")}
    save(out/"job.json",meta)
    for p in sources:
        dest=out/"sources"/p.relative_to(ROOT);dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(p.read_bytes())
    print(json.dumps({"job":str(out),"scope":SCOPE,"libJit_bytes":bootstrap["size"],"kernel_module_bytes":km["module_bytes"],"device_execution":False}))

def run(out, scope):
    require(sys.platform != "darwin" or os.geteuid() == 0,
            "macOS MSC access requires sudo: sudo -n env DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib .venv-offline/bin/python camera_kernel_cspi52.py run --job JOB")
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
            and emulation.get("cases") == 59 and len(emulation.get("tests",[]))==59 and all(t.get("passed") is True for t in emulation["tests"]), "Emulation differs from sealed job")
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
              "scope": SCOPE, "nor_requests": 0, "kernel_loads_maximum": 1,"submit_writes_maximum":1,"fixed_source":"0x4011e74d4","fixed_bytes":52,"static_source_admission_receipt":SOURCE_ADMISSION_SHA,"current_endpoint_binding_unproven":True,"payload_semantics":"opaque52B metadata; no controller readiness/value interpretation", "kernel_resident_until": "reboot", "cleanup_does_not_unload_kernel": True}
    with (out / "attempt.json").open("x") as f:
        json.dump({"time": time.time(), "body": body, "automatic_retry": False}, f);f.flush();os.fsync(f.fileno())
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
        with (out/"action-intent.json").open("x") as journal:
            json.dump({"scope":SCOPE,"job_nonce":meta["nonce"],"kernel_nonce":meta["kernel"]["module_nonce"],"load_limit":1,"submit_limit":1,"source":"0x4011e74d4","bytes":52,"pending_policy":"retain-until-reboot-no-retry"},journal);journal.flush();os.fsync(journal.fileno())
        report["start_attempts"] = 1;report["verdict"] = "START_ATTEMPTED_KERNEL_RESIDENCY_UNKNOWN_UNTIL_REBOOT";save(evidence / "run.json", report)
        write("start", start_packet(meta))
        result = decode(poll("result", RESULT.size), meta);report["native"] = result
        require(result["phase"] in (4, 90), "Native lifecycle publication invalid")
        cspi=decode_cspi(poll("cspi",CSPI.size),meta);report["cspi"]=cspi
        require(cspi["version"]==1 and cspi["loads"] in (0,1) and cspi["submits"] in (0,1) and 0<=cspi["snapshots"]<=51,"CSPI attempt report invalid")
        report["verdict"]="REJECTED_BEFORE_KERNEL_LOAD" if not cspi["loads"] else "CSPI_OUTCOME_UNKNOWN_RESIDENT_UNTIL_REBOOT"
        snapshots=[];page=None
        for i in range(cspi["snapshots"]):
            raw=read(f"status{i:02d}",8192);(evidence/f"status{i:02d}").write_bytes(raw)
            try:
                item=validate_status(raw,meta,page)
                if page is None: page=item["page_phys"]
                snapshots.append(item)
            except RuntimeError as error:
                snapshots.append({"parse_error":str(error)})
        report["snapshots"]=snapshots
        for name in ("load_intent","submit_intent"):
            raw=read(name,32,True)
            if raw is not None:(evidence/name).write_bytes(raw)
        if cspi["stage"]==6 and not cspi["error"] and result["phase"]==4 and not result["error"]:
            validate_success(cspi,result,snapshots)
            report["transport"]="DONE"
            payload=bytes.fromhex(snapshots[-1]["raw_hex"]);require(len(payload)==52,"Decoded CSPI payload size changed")
            (evidence/"raw52.bin").write_bytes(payload)
            report["raw52_sha256"]=hashlib.sha256(payload).hexdigest()
            report["binding_or_epoch_confirmed"]=False
            report["controller_initialized_or_ready_inferred"]=False
            report["verdict"]="CSPI52_DONE_RAW_CAPTURED"
        elif cspi["submits"] and snapshots and snapshots[-1].get("state")=="pending": report["verdict"]="CSPI52_PENDING_RESIDENT_NO_RETRY"
        for name, cap in (("loader_maps", 524288), ("loader_fds", 131072)):
            data = read(name, cap, True)
            if data is not None: (evidence / name).write_bytes(data)
        write("ack", b"M4CACK01" + bytes.fromhex(meta["nonce"]) + struct.pack("<Q", 1))
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
    require(report["verdict"] == "CSPI52_DONE_RAW_CAPTURED", "CSPI verdict="+report["verdict"]+"; no retry or expanded reads. Reboot does not authorize another attempt; fresh review and authorization are required")

if __name__ == "__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action",nargs="?",choices=("prepare","run"),default="prepare")
    parser.add_argument("--job",type=Path,required=True)
    parser.add_argument("--scope",default="",help="Separate authorization gate: job nonce:kernel-cspi52-once")
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
