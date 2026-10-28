"""Prepare and simulate an independent OSAL IPCmap queue probe.

Run is a separate scope from metadata: one /dev/uipc FD, SDK init, fixed 2 MiB
IPC shared alias, one newly granted QID, empty nonblocking receive, exact-QID
free, munmap/close. No DMM message, direct alias access, CP, NOR or DMA.
"""
import argparse
import hashlib
import json
import os
import secrets
import struct
import subprocess
import sys
import time
from pathlib import Path
from camera_inventory import ROOT, UPSTREAM, NATIVE, COMMIT, RESULT, LAUNCH, FIELDS, LIBRARIES as LOADER_LIBRARIES
from camera_inventory import require, sha, save, inspect, CameraStatusError

SCOPE = 'osal-ipcmap-queue'
LIBRARIES = dict(LOADER_LIBRARIES, **{'/usr/lib/libosal_uipc.so':'09ebf5980237fc473077dc844763dcb00cba423f431646e3be7c0ca49ea70ff3','/usr/kmod/osal_uipc.ko':'bb14e0b18255d8ff346696aa0865864d44a6fab752ae3a26463bd15ba040963f'})
PROBE = struct.Struct('<17q')
PROBE_FIELDS = ('version','profile','label','open_rc','init_rc','map_rc','alloc_rc','recv_rc','free_rc','unmap_rc','close_rc','init_words01','init_words23','id','message','unknown','completed')

def decode(raw,meta):
    require(len(raw)==RESULT.size,'Partial lifecycle result')
    magic,nonce,*values=RESULT.unpack(raw)
    require(magic==b'M4OSAL01' and nonce.hex()==meta['nonce'],'Wrong lifecycle identity')
    return dict(zip(FIELDS,values))

def prepare(out):
    require(not out.exists(),'Choose a new job directory')
    require(subprocess.check_output(['git','-C',str(UPSTREAM),'rev-parse','HEAD'],text=True).strip()==COMMIT,'Upstream revision changed')
    require(not subprocess.check_output(['git','-C',str(UPSTREAM),'status','--porcelain'],text=True).strip(),'Upstream checkout changed')
    out.mkdir(parents=True)
    nonce=secrets.token_bytes(16);directory='/tmp_wbshd/m4osal_'+nonce.hex()
    def array(name,b):return 'static const unsigned char '+name+'[]={'+','.join(map(str,b))+'};\n'
    (out/'job.h').write_text('#define JOB_DIR "'+directory+'"\n'+array('job_nonce',nonce))
    compiler=ROOT/'local/zig-aarch64-macos-0.15.2/zig'
    flags=['cc','-target','aarch64-linux-gnu','-mcpu=generic','-Os','-g','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-unwind-tables','-fno-asynchronous-unwind-tables','-nostdlib','-ffunction-sections','-fdata-sections','-Wl,--gc-sections','-Wl,--no-undefined','-Wl,--build-id=none','-Wl,-z,noexecstack','-Wl,-z,max-page-size=4096','-Wl,-z,common-page-size=4096','-I',str(out),'-I',str(NATIVE)]
    def build(source,name,extra):
        r=subprocess.run([str(compiler),*flags,*extra,str(source),'-o',str(out/name)],capture_output=True,text=True,timeout=120)
        (out/(name+'.compile.log')).write_text(r.stdout+r.stderr);require(r.returncode==0,r.stderr[-3000:])
    build(ROOT/'native/osal_probe.c','worker.debug.elf',['-static','-fno-pic','-Wl,-e,_start'])
    worker=inspect(out/'worker.debug.elf',True);raw=(out/'worker.debug.elf').read_bytes()
    limit=max(s['p_offset']+s['p_filesz'] for s in worker['segments'] if s['p_type']=='PT_LOAD')
    compact=bytearray(raw[:limit]);struct.pack_into('<Q',compact,40,0);struct.pack_into('<3H',compact,58,0,0,0)
    (out/'worker.elf').write_bytes(compact);(out/'worker_blob.h').write_text(array('worker_blob',compact))
    build(NATIVE/'bootstrap.c','libJit.so',['-shared','-fPIC','-Wl,-Bsymbolic','-s'])
    bootstrap=inspect(out/'libJit.so',False);require(bootstrap['size']<=65520,'Module too large')
    sources=[ROOT/'native/osal_probe.c',Path(__file__),ROOT/'emulate_osal_probe.py',ROOT/'camera_inventory.py',NATIVE/'linux_a64.h',NATIVE/'bootstrap.c',NATIVE/'lifecycle_worker.c',ROOT/'local/analysis/cspi-coldboot/scripts/system/sbin/initrc/insmod_drv2']
    meta={'schema':'camera-use-osal-probe/1','scope':SCOPE,'nonce':nonce.hex(),'job_dir':directory,'worker':worker,'compact_worker_sha256':sha(out/'worker.elf'),'bootstrap':bootstrap,'compiler_sha256':sha(compiler),'upstream_commit':COMMIT,'sources':{str(p.relative_to(ROOT)):sha(p) for p in sources},'automatic_retry':False,'module_uploads_allowed':1,'diagnostic_label':0x3f,'ipcmap':{'length':0x200000,'prot':3,'flags':1,'offset':0,'direct_alias_access':False},'body_binding_backup_sha256':sha(ROOT/'dumps/20261026-031555/backup_preset.bin'),'authorization':'NOT_GRANTED_METADATA_SCOPE_DOES_NOT_COVER_THIS','block_writes':False,'dmm_messages':0,'nor_requests':0}
    save(out/'job.json',meta)
    for p in sources:
        dest=out/'sources'/p.relative_to(ROOT);dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(p.read_bytes())
    print(json.dumps({'job':str(out),'scope':SCOPE,'requires_new_user_scope_confirmation':True,'module_bytes':bootstrap['size']}))

def run(out, confirm_scope):
    require(sys.platform != "darwin" or os.geteuid() == 0,
            "macOS MSC access requires sudo: sudo -n env DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib .venv-offline/bin/python camera_osal_probe.py run --job JOB --confirm-scope NONCE:osal-ipcmap-queue")
    meta = json.loads((out / "job.json").read_text())
    require(meta["schema"] == "camera-use-osal-probe/1", "Wrong job type")
    require(confirm_scope == meta["nonce"] + ":" + SCOPE, "New explicit user scope confirmation is required; metadata authorization is insufficient")
    scope = meta["scope"];require(scope == SCOPE,"Wrong scope")
    require(sha(ROOT/"dumps/20261026-031555/backup_preset.bin")==meta["body_binding_backup_sha256"],"Original same-body binding changed")
    require(all(sha(ROOT / p) == value for p, value in meta["sources"].items()), "Reviewed source changed; rebuild/retest")
    require(sha(out / "libJit.so") == meta["bootstrap"]["sha256"] and sha(out / "worker.elf") == meta["compact_worker_sha256"], "Job binary changed")
    require((out / "emulation.json").exists(), "Offline emulation is required")
    emulation = json.loads((out / "emulation.json").read_text())
    require(emulation.get("all_passed") is True and len(emulation.get("tests", [])) == 24 and emulation.get("original_dispatch_gate_verified") is True and emulation.get("lifecycle_full_worker_emulated") is True and emulation.get("raw_error_sign_extension_verified") is True
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
        require(result["phase"] in (4,90), "Invalid probe terminal phase")
        raw=read("probe",PROBE.size,True)
        if raw is not None:
            require(len(raw)==PROBE.size,"Partial probe publication")
            (evidence/"probe.bin").write_bytes(raw)
            report["probe"]=dict(zip(PROBE_FIELDS,PROBE.unpack(raw)))
        for name, cap in (("loader_maps",524288),("loader_fds",131072)):
            data=read(name,cap,True)
            if data is not None:(evidence/name).write_bytes(data)
        save(evidence/"run.json",report)
        write("ack", b"M4ACK001" + bytes.fromhex(meta["nonce"]) + struct.pack("<Q", 1))
        cleaned = decode(poll("cleaned", RESULT.size), meta);report["cleaned"] = cleaned
        require(cleaned["phase"] == 5 and cleaned["error"] == result["error"], "Lifecycle cleanup/result changed")
        p=report.get("probe",{})
        require(result["phase"]==4 and result["error"]==0 and result["flags"]==3
                and p.get("version")==1 and p.get("profile")==1 and p.get("label")==0x3f
                and p.get("completed")==1 and p.get("unknown")==0
                and all(p.get(k)==0 for k in ("init_rc","alloc_rc","free_rc","unmap_rc","close_rc"))
                and p.get("recv_rc")==-0x3fe and p.get("message")==0
                and p.get("open_rc",-1)>=0 and p.get("map_rc",0)>0
                and p.get("init_words01")==0x0008000000200000
                and (p.get("init_words23",0)&0xffffffff)==0x20000
                and p.get("id",0)!=((p.get("init_words23",0)>>32)&0xffffffff)
                and (p.get("id",0)&0xffff8000)==0x803f0000 and (p.get("id",0)&0x7fff)!=0,
                "Probe publication invalid/failed/unknown; raw results retained, no retry")
        require(read_path("/tmp/jiritsu/libJit.so", 65520, True) is None, "Module cleanup not confirmed")
        report["verdict"] = "OSAL_EMPTY_QUEUE_PROBE_VERIFIED"
    try:
        senserShellCommand(complete=complete)
        require(report["verdict"] == "OSAL_EMPTY_QUEUE_PROBE_VERIFIED", "No successful inventory callback")
    except BaseException as error:
        report["error"] = {"type": type(error).__name__, "message": str(error)}
        raise
    finally:
        save(evidence / "run.json", report)
    print(json.dumps({"verdict": report["verdict"], "evidence": str(evidence), "block_writes": False}))


if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('action',nargs='?',default='prepare',choices=('prepare','run'))
    p.add_argument('--job',type=Path,required=True)
    p.add_argument('--confirm-scope')
    a=p.parse_args()
    if a.action=='prepare':prepare(a.job.resolve())
    else:
        code=0
        try:run(a.job.resolve(),a.confirm_scope)
        except BaseException:
            import traceback
            traceback.print_exc();code=1
        finally:sys.stdout.flush();sys.stderr.flush()
        os._exit(code)
