"""Emulate the compiled reader and optional bootstrap over synthetic syscalls."""
import argparse
from collections import Counter
import hashlib
import io
import json
from pathlib import Path
import struct
import sys
from tempfile import TemporaryDirectory

sys.path.insert(0,str(Path(__file__).resolve().parent))
import unicorn
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_INTR, UC_HOOK_BLOCK
from unicorn.arm64_const import UC_ARM64_REG_SP, UC_ARM64_REG_LR, UC_ARM64_REG_X0, UC_ARM64_REG_X8
from elftools.elf.elffile import ELFFile
from install_patch_read_profile import ROOT, contract, require, sha
from verify_install_patch_read_offline import verify

from camera_stream_execution import LAUNCH
from model_toolchain_bootstraps_offline import CASES as BASE_BOOTSTRAP_CASES
READ_BOOTSTRAP_CASES=BASE_BOOTSTRAP_CASES+('bounded_short_completion','short_write_budget_exhaustion')
BOOTSTRAP_CASES=READ_BOOTSTRAP_CASES

SUCCESS={'original_original','patched_patched','mixed','other','pread_eintr','transient_parent_then_init'}
PUBLICATION={name+'_'+fault for name in ('ready','result') for fault in
             ('open_error','write_error','half_write_error','close_error')}
FAULTS={'missing_lib_pid','missing_app_pid','lib_maps_change','app_maps_change_after',
    'lib_base_change','app_stat_change','lib_stat_malformed','app_stat_pid_mismatch',
    'lib_word_change','app_word_change','lib_anchor_error','app_anchor_mismatch','lib_version_mismatch',
    'lib_word_short','app_word_error','lib_version_short','app_mem_close_error','lib_mem_close_error',
    'lib_maps_close_error','app_stat_close_error','result_rename_error','result_destination_exists',
    'wrong_START_magic','wrong_START_nonce','wrong_START_patch_nonce','wrong_START_version','half_START',
    'missing_START','not_root','wrong_tmpfs','parent_never_settles','interrupted_first_word','interrupted_both_passes'}
CASES=tuple(sorted(SUCCESS|PUBLICATION|FAULTS))


def emulate(directory, scenario, manifest):
    require(scenario in CASES,'Unknown current-read case')
    spec=json.loads((directory/'target-spec.json').read_text())
    nonce=bytes.fromhex(manifest['nonce']);job=manifest['job_dir']
    token=contract.START_FRAME.pack(contract.START_MAGIC,nonce,bytes.fromhex(spec['original_patch_nonce']),1)
    if scenario=='wrong_START_magic':token=b'BADSTART'+token[8:]
    if scenario=='wrong_START_nonce':token=token[:8]+b'x'*16+token[24:]
    if scenario=='wrong_START_patch_nonce':token=token[:24]+b'x'*16+token[40:]
    if scenario=='wrong_START_version':token=token[:40]+struct.pack('<Q',2)
    if scenario=='half_START':token=token[:24]
    files={job+'/worker':b'SYNTHETIC_WORKER',job+'/start':token}
    if scenario=='missing_START':files.pop(job+'/start')
    sentinel=b'EXISTING_RESULT_MUST_SURVIVE'
    if scenario=='result_destination_exists':files[job+'/result']=sentinel
    u=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
    elf=ELFFile(io.BytesIO((directory/'worker.debug.elf').read_bytes()))
    pages=set()
    for segment in elf.iter_segments():
        if segment['p_type']=='PT_LOAD':pages.update(range(segment['p_vaddr']&~4095,(segment['p_vaddr']+segment['p_memsz']+4095)&~4095,4096))
    for page in sorted(pages):u.mem_map(page,4096)
    for segment in elf.iter_segments():
        if segment['p_type']=='PT_LOAD':u.mem_write(segment['p_vaddr'],segment.data())
    u.mem_map(0x90000000,0x100000);sp=0x90080000;u.reg_write(UC_ARM64_REG_SP,sp)
    u.mem_write(sp,struct.pack('<4Q',2,sp+256,sp+300,0));u.mem_write(sp+256,b'worker\0');u.mem_write(sp+300,b'888\0')
    targets=spec['targets'];memory={};word_reads=Counter();maps_reads=Counter();stat_reads=Counter()
    for name,p in targets.items():
        anchor=bytearray.fromhex(p['anchor_hex']);offset=p['patch_offset']-p['anchor_offset']
        word=p['patch_hex'] if scenario=='patched_patched' or (scenario=='mixed' and name=='app') else p['original_hex']
        if scenario=='other' and name=='lib':word='44332211'
        anchor[offset:offset+4]=bytes.fromhex(word)
        if scenario=='app_anchor_mismatch' and name=='app':anchor[0]^=1
        memory[name]={p['base_addr']+p['anchor_offset']:anchor,
                      p['base_addr']+p['global_version_offset']:bytearray(p['stock_version'].to_bytes(p['version_bytes'],'little'))}
        if scenario=='lib_version_mismatch' and name=='lib':memory[name][p['base_addr']+p['global_version_offset']][0]^=1
    state=dict(next_fd=3,exit=None,interrupted=False,blocks=0,clock=1000000000,eintr=False,published=False)
    fds={};calls=Counter();trace=[];preads=[];opens=[];pubwrites=[];blockhash=hashlib.sha256()
    def text(address):
        raw=bytes(u.mem_read(address,512));require(b'\0' in raw,'Unbounded path');return raw.split(b'\0',1)[0].decode()
    def ret(value):u.reg_write(UC_ARM64_REG_X0,value&((1<<64)-1))
    def target_for(path):
        for name,p in targets.items():
            if path.startswith('/proc/'+str(p['pid'])+'/'):return name
        raise AssertionError('Access outside original fixed PIDs: '+path)
    def map_data(name):
        p=targets[name];count=maps_reads[name];inode=112 if name=='lib' else 114
        if scenario=='lib_maps_change' and name=='lib' and count>=2:inode+=1
        if scenario=='app_maps_change_after' and name=='app' and count>=3:inode+=1
        base=p['base_addr']+(4096 if scenario=='lib_base_change' and name=='lib' else 0)
        span=0x8000 if name=='lib' else 0x3000000
        return (f'{base:x}-{base+span:x} r-xp 00000000 00:01 {inode} /usr/lib/'+
                ('libupdaterufp.so' if name=='lib' else 'appFw.so')+'\n').encode()
    def stat_data(name):
        p=targets[name];pid=p['pid'];tick=111 if name=='lib' else 222
        if scenario=='app_stat_change' and name=='app' and stat_reads[name]>=2:tick+=1
        if scenario=='app_stat_pid_mismatch' and name=='app':pid+=1
        if scenario=='lib_stat_malformed' and name=='lib':return b'malformed stat\n'
        return (f'{pid} (synthetic ) task) S '+' '.join(['1']*18)+f' {tick} 0 0 0\n').encode()
    def memory_read(name,address,count):
        hits=[(base,raw) for base,raw in memory[name].items() if base<=address and address+count<=base+len(raw)]
        require(len(hits)==1,'Read outside fixed anchor/version/word fixture')
        base,raw=hits[0];return bytes(raw[address-base:address-base+count])
    def syscall(_u,number,_data):
        require(number==2,'Only AArch64 SVC modeled')
        no=u.reg_read(UC_ARM64_REG_X8);a,b,c,d,e,f=[u.reg_read(UC_ARM64_REG_X0+i) for i in range(6)];calls[no]+=1
        if no==56:
            path=text(b)
            if path.startswith('/proc/'):
                name=target_for(path);kind=path.rsplit('/',1)[1]
                require(kind in ('maps','mem','stat') and c==0x88000,'Every process fd must be fixed and O_RDONLY')
                opens.append(dict(path=path,kind=kind,target=name,flags=c,readonly=True))
                if scenario=='missing_'+name+'_pid':ret(-2);return
                if kind=='maps':maps_reads[name]+=1;data=map_data(name)
                elif kind=='stat':stat_reads[name]+=1;data=stat_data(name)
                else:data=b''
                row=dict(kind=kind,target=name,data=data,pos=0,path=path)
            else:
                require(path in {job+'/'+n for n in ('start','ready','result.pending')},'Unexpected job path')
                writing=c==0x880c1;require(writing or c==0x88000,'Unexpected job flags')
                label='result' if path.endswith('result.pending') else path.rsplit('/',1)[1]
                if writing:
                    if scenario==label+'_open_error':ret(-13);return
                    if path in files:ret(-17);return
                    files[path]=b''
                elif path not in files:ret(-2);return
                row=dict(kind='file',path=path,pos=0,write=writing,label=label)
            fd=state['next_fd'];state['next_fd']+=1;fds[fd]=row;ret(fd)
        elif no==57:
            row=fds.pop(a,None);code=0 if row else -9
            if row:
                if row['kind']=='mem' and scenario==row['target']+'_mem_close_error':code=-5
                if row['kind']=='maps' and scenario==row['target']+'_maps_close_error':code=-5
                if row['kind']=='stat' and scenario==row['target']+'_stat_close_error':code=-5
                if row['kind']=='file' and row.get('write') and scenario==row['label']+'_close_error':code=-5
                trace.append(dict(event='close',kind=row['kind'],target=row.get('target'),returned=code))
            ret(code)
        elif no==63:
            row=fds[a];require(row['kind']!='mem','Memory reads must use pread')
            raw=files[row['path']] if row['kind']=='file' else row['data'];pos=row['pos'];part=raw[pos:pos+c]
            if part:u.mem_write(b,part)
            row['pos']+=len(part);ret(len(part))
        elif no==64:
            row=fds[a];require(row['kind']=='file' and row.get('write') and c<=424,'Only bounded fresh publications writable')
            raw=bytes(u.mem_read(b,c));label=row['label'];count=c
            if scenario==label+'_write_error':count=-5
            if scenario==label+'_half_write_error':count=c//2 if not files[row['path']] else -5
            if count>0:files[row['path']]+=raw[:count]
            pubwrites.append(dict(record=label,requested=c,returned=count,cumulative=len(files[row['path']])));ret(count)
        elif no==67:
            row=fds[a];require(row['kind']=='mem','Only readonly memory fds may pread');name=row['target'];p=targets[name]
            require(c in (2,4,20,32),'Unexpected read size');kind='word' if d==p['target_addr'] else 'version' if d==p['base_addr']+p['global_version_offset'] else 'anchor'
            if kind=='word':
                word_reads[name]+=1
                if scenario==name+'_word_change' and word_reads[name]>=2:
                    base=p['base_addr']+p['anchor_offset'];off=p['patch_offset']-p['anchor_offset'];memory[name][base][off:off+4]=bytes.fromhex(p['patch_hex'])
            raw=memory_read(name,d,c);count=c
            if scenario==name+'_'+kind+'_short':count=c//2
            if scenario==name+'_'+kind+'_error':count=-5
            if scenario=='pread_eintr' and not state['eintr']:state['eintr']=True;count=-4
            if count>0:u.mem_write(b,raw[:count])
            preads.append(dict(target=name,kind=kind,address=hex(d),requested=c,returned=count,raw_hex=raw[:max(0,count)].hex()))
            trace.append(dict(event='pread',target=name,kind=kind,returned=count))
            ret(count)
            stop=scenario=='interrupted_first_word' and kind=='word' and name=='lib'
            stop|=scenario=='interrupted_both_passes' and kind=='word' and name=='app' and word_reads[name]>=2
            if stop:state['interrupted']=True;u.emu_stop()
        elif no==35:
            path=text(b);require(path in (job+'/worker',job+'/start'),'Unexpected unlink')
            if path in files:files.pop(path);ret(0)
            else:ret(-2)
        elif no==43:
            require(text(a)=='/tmp_wbshd','Unexpected statfs');u.mem_write(b,struct.pack('<15q',0 if scenario=='wrong_tmpfs' else 0x1021994,4096,100000,100000,100000,0,0,0,255,4096,0,0,0,0,0));ret(0)
        elif no==113:
            require(a==1,'Unexpected clock');now=state['clock'];state['clock']+=100000000000;u.mem_write(b,struct.pack('<2q',now//1000000000,now%1000000000));ret(0)
        elif no==101:ret(0)
        elif no==175:ret(1 if scenario=='not_root' else 0)
        elif no==172:ret(999)
        elif no==173:
            if scenario=='parent_never_settles':ret(2)
            elif scenario=='transient_parent_then_init' and calls[173]<3:ret(2)
            else:ret(1)
        elif no==276:
            require(a==((1<<64)-100) and c==((1<<64)-100) and text(b)==job+'/result.pending' and text(d)==job+'/result' and e==1,'Unexpected rename')
            if scenario=='result_rename_error':ret(-5)
            elif job+'/result' in files:ret(-17)
            else:files[job+'/result']=files.pop(job+'/result.pending');state['published']=True;trace.append(dict(event='published',pread_count=len(preads)));ret(0)
        elif no==94:state['exit']=a;trace.append(dict(event='exit',code=a));u.emu_stop()
        else:raise AssertionError('Forbidden/unmodeled syscall '+str(no))
    def block(_u,address,size,_data):state['blocks']+=1;blockhash.update(struct.pack('<QI',address,size))
    u.hook_add(UC_HOOK_INTR,syscall);u.hook_add(UC_HOOK_BLOCK,block);u.emu_start(elf['e_entry'],0,count=6000000)
    require(state['exit'] is not None or state['interrupted'],'Instruction budget exhausted')
    ready=files.get(job+'/ready');result=files.get(job+'/result');terminal=None;accepted=None
    if result and len(result)==424:terminal=contract.decode_record(result,nonce,spec)
    if scenario in SUCCESS:
        require(state['exit']==0 and ready and result,'Expected complete current observation')
        accepted=contract.validate_publications(ready,result,nonce=nonce,loader_pid=888,spec=spec)
        expected={'original_original':'ORIGINAL','patched_patched':'PATCHED','mixed':'MIXED','other':'OTHER','pread_eintr':'ORIGINAL','transient_parent_then_init':'ORIGINAL'}[scenario]
        require(accepted['observation']==expected,'Classification differs')
        require(not any(row['kind']=='mem' for row in fds.values()),'Memory fd survived successful publication')
        published=next(i for i,event in enumerate(trace) if event['event']=='published')
        require(not any(event['event']=='pread' for event in trace[published:]),'Memory read occurred after publication')
        require(sum(event['event']=='close' and event['kind']=='mem' and event['returned']==0 for event in trace[:published])==2,'Both readonly memory fds must close before publication')
    elif state['interrupted']:require(result is None,'Interrupted model produced terminal')
    elif scenario.startswith('result_'):
        require(state['exit']==1 and terminal is None,'Failed publication produced accepted terminal')
        if scenario=='result_destination_exists':require(result==sentinel,'NOREPLACE overwrote existing result')
    else:require(state['exit']==1 and terminal and terminal['phase']==90 and terminal['error']<0,'Failed observation falsely succeeded')
    if state['published']:
        published=next(i for i,event in enumerate(trace) if event['event']=='published')
        require(not any(event['event']=='pread' for event in trace[published:]),'Delayed memory access after publication')
    require(calls[68]==calls[117]==calls[29]==0,'Process write/ptrace/ioctl observed')
    require(all(item['readonly'] and item['flags']==0x88000 for item in opens),'Non-readonly process open')
    return dict(case=scenario,passed=True,actual_native_instruction_execution=True,native_exit=state['exit'],
        model_interrupted=state['interrupted'],native_terminal=terminal,observation=accepted,
        process_memory_writes=0,all_memory_opens_readonly=True,process_opens=opens,pread_events=preads,
        trace=trace,publication_write_events=pubwrites,publication_hex={name:(files.get(job+'/'+name) or b'').hex() for name in ('ready','result','result.pending')},
        native_basic_blocks_executed=state['blocks'],basic_block_trace_sha256=blockhash.hexdigest(),
        syscall_counts=dict(calls),hardware_operations=0,original_mm_continuity_proven=False,restoration_proven=False,
        installation_authorized=False)



def _bootstrap_case(job, scenario):
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
    state = {"next": 3, "clone": 0, "wait": 0, "exec": False, "exit": None,
             "worker_write_calls": 0, "worker_write_bytes": 0}

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
            if path.endswith("/worker"):state["worker_write_calls"] += 1
            if scenario == "write_error" and path.endswith("/worker"):
                ret(-28); return
            if scenario == "short_write":n = min(c, 31)
            elif scenario == "bounded_short_completion":n = min(c, (len(compact) + 127) // 128)
            elif scenario == "short_write_budget_exhaustion":n = min(c, 1)
            else:n = c
            if path.endswith("/worker"):state["worker_write_bytes"] += n
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
    if scenario in ("success", "wait_eintr", "bounded_short_completion") or (scenario == "short_write" and len(compact) <= 31 * 256):
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
    if scenario == "bounded_short_completion":
        require(state["worker_write_calls"] <= 128 and state["worker_write_bytes"] == len(compact),
                "Finite positive short-write completion not reached")
    if scenario == "short_write_budget_exhaustion":
        require(len(compact) > 256 and state["worker_write_calls"] == 256 and state["worker_write_bytes"] == 256,
                "Finite one-byte write budget exhaustion not reached")
    return {"scenario": scenario, "passed": True, "syscalls": sorted(set(calls)),
            "exec_observed_not_executed": state["exec"],
            "short_write_expected_completion": scenario == "bounded_short_completion" or (scenario == "short_write" and len(compact) <= 31 * 256),
            "worker_bytes": len(compact), "worker_write_calls": state["worker_write_calls"],
            "worker_write_bytes": state["worker_write_bytes"],
            "synthetic_syscall_count": len(calls)}


def _output_path(value):
    path=Path(value).absolute()
    require('..' not in path.parts and path.is_relative_to(ROOT/'output')
            and all(not p.is_symlink() for p in (path,*path.parents))
            and path.parent.is_dir(), 'Nonsymlink workspace output report path required')
    return path


def bootstrap_report(job,manifest,destination):
    destination=_output_path(destination)
    from model_toolchain_bootstraps_offline import module_info,PINS
    from camera_stream_execution import LAUNCH
    for path,digest in PINS.items():require(sha(ROOT/path)==digest,'Bootstrap source/model changed')
    module=(job/'libJit.so').read_bytes();worker=(job/'worker.elf').read_bytes();info=module_info(module)
    require(module.count(worker)==1,'Worker embedding differs')
    adapter=dict(schema='MODEL_ONLY_BOOTSTRAP_ADAPTER_NOT_A_RELEASE/1',model_fixture_only=True,
        admission='MODEL_ONLY_NO_DEVICE_PERMISSION',body_binding=None,nonce=manifest['nonce'],job_dir=manifest['job_dir'],
        module=info,compact_worker_sha256=hashlib.sha256(worker).hexdigest(),metadata_source_sha256=sha(job/'manifest.json'))
    before={name:sha(job/name) for name in ('manifest.json','verification.json','libJit.so','worker.elf')}
    with TemporaryDirectory(prefix='read-bootstrap-MODEL-',dir=ROOT/'output') as path:
        fixture=Path(path);(fixture/'libJit.so').write_bytes(module);(fixture/'worker.elf').write_bytes(worker)
        (fixture/'bootstrap.json').write_text(json.dumps(adapter));cases=[_bootstrap_case(fixture,name) for name in READ_BOOTSTRAP_CASES]
    require(len(cases)==len(READ_BOOTSTRAP_CASES) and all(case['passed'] for case in cases),'Bootstrap matrix failed')
    require(before=={name:sha(job/name) for name in before},'Bootstrap inputs changed')
    report=dict(schema='camera-install-patch-read-bootstrap-model/1',all_passed=True,case_count=len(cases),declared_cases=list(READ_BOOTSTRAP_CASES),
        coverage_complete_for_declared_matrix=True,cases=cases,module=info,
        input_hashes=before,pinned_source_and_model_hashes=PINS,adapter_helper_sha256=sha(ROOT/'tools/model_toolchain_bootstraps_offline.py'),
        runner_sha256=sha(Path(__file__)),
        engine_reference_sha256=sha(ROOT/'tools/emulate_stream_bootstrap.py'),
        short_write_rule='31-byte writes complete iff worker length <= 31*256; actual parent outcome verified',
        bootstrap_CPU_emulated=True,worker_executed=False,real_ARM_process_executed=False,
        hardware_operations=0,original_inputs_unchanged=True,model_only_adapter=adapter)
    with Path(destination).open('x') as f:json.dump(report,f,indent=2);f.write('\n')


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--job',type=Path,required=True)
    p.add_argument('--case',choices=CASES,action='append');p.add_argument('--report',type=Path);p.add_argument('--bootstrap-report',type=Path)
    a=p.parse_args();job=a.job.absolute();verify(job);m=json.loads((job/'manifest.json').read_text())
    selected=tuple(a.case) if a.case else CASES;require(len(set(selected))==len(selected),'Duplicate cases')
    results=[emulate(job,case,m) for case in selected];verify(job)
    report=dict(schema='camera-install-patch-read-native-model/1',all_passed=True,case_count=len(results),cases=results,
        declared_cases=list(CASES),coverage_complete_for_declared_matrix=set(selected)==set(CASES),
        manifest_sha256=sha(job/'manifest.json'),verification_sha256=sha(job/'verification.json'),
        debug_worker_sha256=sha(job/'worker.debug.elf'),emulator_sha256=sha(Path(__file__)),
        contract_sha256=sha(ROOT/'camera_install_patch_read.py'),profile_sha256=sha(ROOT/'tools/install_patch_read_profile.py'),
        verifier_sha256=sha(ROOT/'tools/verify_install_patch_read_offline.py'),source_bindings=m['sources'],artifact_bindings=m['artifacts'],
        native_fault_model_executed=True,execution_kind='EMULATED_INSTRUCTIONS_ONLY',real_ARM_process_executed=False,
        bootstrap_executed=False,hardware_operations=0,process_memory_writes=0,all_memory_opens_readonly=True,
        original_mm_continuity_proven=False,restoration_proven=False,installation_authorized=False,
        runtime_executor_created=False,workflow_unlocked=False,admission='OFFLINE_NOT_BODY_BOUND',
        limitations=['Synthetic syscall, PID, maps, stat, and sparse memory fixtures only',
            'No real scheduling, original-mm continuity, /proc permissions, cache coherence, or device behavior proven',
            'Interruption stops emulation at a selected syscall boundary, not a physical crash',
            'Current byte classification never authorizes cancellation, restoration, READY or firmware entry'])
    destination=_output_path(a.report or job/'native-model-report.json')
    with destination.open('x') as f:json.dump(report,f,indent=2);f.write('\n')
    if a.bootstrap_report:bootstrap_report(job,m,a.bootstrap_report)
    print(json.dumps(dict(all_passed=True,case_count=len(results),hardware_operations=0,process_memory_writes=0)))


if __name__=='__main__':main()
