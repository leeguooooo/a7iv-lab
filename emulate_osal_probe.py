"""Offline Unicorn execution of candidate C and original ko dispatch gate.

All syscalls are mocks; no target library constructors, device or USB imports.
The shared alias is not backed by emulator memory: dereference would fail.
"""
import argparse,json,struct
from pathlib import Path
from elftools.elf.elffile import ELFFile
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_INTR,UC_HOOK_CODE
from unicorn.arm64_const import *
from camera_osal_probe import PROBE,PROBE_FIELDS,require,save,sha,ROOT
MASK=(1<<64)-1

def image(job):
    u=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
    with (job/'worker.debug.elf').open('rb') as f:
        e=ELFFile(f);pages=set()
        for s in e.iter_segments():
            if s['p_type']=='PT_LOAD':pages.update(range(s['p_vaddr']&~4095,(s['p_vaddr']+s['p_memsz']+4095)&~4095,4096))
        for p in pages:u.mem_map(p,4096)
        for s in e.iter_segments():
            if s['p_type']=='PT_LOAD':u.mem_write(s['p_vaddr'],s.data())
        sym=e.get_section_by_name('.symtab');address=next(s['st_value'] for s in sym.iter_symbols() if s.name=='osal_candidate_sequence')
    u.mem_map(0x80000000,0x100000);u.mem_map(0x90000000,4096)
    return u,address

def candidate(job,scenario):
    u,start=image(job);out=0x80001000;alias=0x70000000;calls=[];qid=0x803f6002
    u.reg_write(UC_ARM64_REG_SP,0x800f0000);u.reg_write(UC_ARM64_REG_X0,out)
    u.reg_write(UC_ARM64_REG_X1,0 if scenario=='label_zero' else 0x3f)
    u.reg_write(UC_ARM64_REG_X2,0 if scenario=='nomap_profile' else 1)
    u.reg_write(UC_ARM64_REG_LR,0x90000000)
    def ret(v):u.reg_write(UC_ARM64_REG_X0,v&MASK)
    def string(a):return bytes(u.mem_read(a,128)).split(b'\0')[0]
    def intr(uc,number,data):
        nr=u.reg_read(UC_ARM64_REG_X8);a=[u.reg_read(UC_ARM64_REG_X0+i) for i in range(6)];calls.append(nr)
        if nr==56:
            require(string(a[1])==b'/dev/uipc' and a[2]==0x88002,'Unexpected device open')
            ret(-13 if scenario=='open_error' else 8)
        elif nr==29:
            require(a[0]==8,'Wrong FD');selector,pad,ptr=struct.unpack('<IIQ',u.mem_read(a[2],16));require(not pad,'Padding changed')
            if a[1]==0x80000010:
                require(selector==0 and calls.count(29)==1,'Init repeated')
                u.mem_write(ptr,struct.pack('<4I',0x200001 if scenario=='init_bad' else 0x200000,0x80000,0x20000,0x803f6001))
                ret(-14 if scenario=='init_error' else 0)
            elif a[1]==0x8000000c:
                op,label,value=struct.unpack('<IIQ',u.mem_read(ptr,16));require(selector==0,'Wrong dynamic selector')
                if op==0x2a:
                    require(label==0x3f and calls.count(29)==2,'Allocation replay or wrong label')
                    if scenario!='alloc_copyout':u.mem_write(value,struct.pack('<I',0x803e6002 if scenario=='alloc_bad' else 0x803f6001 if scenario=='alloc_bootstrap' else qid))
                    ret(-14 if scenario=='alloc_copyout' else -5 if scenario=='alloc_error' else 0)
                else:
                    require(op==0x4a and label==0 and value==qid and calls.count(29)==4,'Free was not exact granted QID')
                    ret(-5 if scenario=='free_error' else 0)
            elif a[1]==0x80000007:
                pointer,timeout,padding=struct.unpack('<QII',u.mem_read(ptr,16))
                require(selector==qid and timeout==padding==0 and calls.count(29)==3,'Receive repeated or not nonblocking')
                if scenario=='recv_payload':u.mem_write(pointer,struct.pack('<Q',alias+128))
                ret(-5 if scenario=='recv_error' else 0 if scenario=='recv_success' else -0x3fe)
            else:raise RuntimeError('Unapproved ioctl')
        elif nr==222:
            require(a==[0,0x200000,3,1,8,0] and calls.count(222)==1,'Mapping differs from SDK')
            ret(-12 if scenario=='mmap_error' else 0 if scenario=='mmap_zero' else alias)
        elif nr==215:
            require(a[:2]==[0 if scenario=='mmap_zero' else alias,0x200000],'Wrong unmap')
            ret(-5 if scenario=='unmap_error' else 0)
        elif nr==57:
            require(a[0]==8 and calls.count(57)==1,'FD close replay');ret(-4 if scenario=='close_error' else 0)
        else:raise RuntimeError('Unapproved syscall '+str(nr))
    u.hook_add(UC_HOOK_INTR,intr);u.emu_start(start,0x90000000,count=300000)
    raw=bytes(u.mem_read(out,PROBE.size));r=dict(zip(PROBE_FIELDS,PROBE.unpack(raw)))
    returned=u.reg_read(UC_ARM64_REG_X0);returned=returned-(1<<64) if returned>>63 else returned
    if scenario=='success':require(returned==0 and r['completed']==1 and r['unknown']==0,'Success failed')
    else:require(returned!=0,'Fault scenario unexpectedly succeeded')
    require(calls.count(56)<=1 and calls.count(222)<=1 and calls.count(57)<=1,'Automatic retry')
    if scenario in ('recv_error','recv_payload','recv_success','alloc_error','alloc_copyout','alloc_bad','alloc_bootstrap'):
        require(r['free_rc']==-999,'Unknown state was freed')
    if scenario in ('label_zero','nomap_profile'):require(not calls,'Invalid profile touched OS')
    if scenario in ('open_error',):require(calls==[56],'Open failure continued')
    if scenario in ('init_error','init_bad'):require(calls==[56,29,57],'Init failure continued')
    if scenario=='success':require(calls==[56,29,222,29,29,29,215,57],'Sequence changed')
    return {'scenario':scenario,'passed':True,'return':returned,'syscalls':calls,'probe':r,'alias_accesses':0,'mock_boundary':'all syscalls, allocation identity, pool and scheduler'}

def original_gate():
    p=ROOT/'local/analysis/cspi-coldboot/osal_uipc.ko'
    require(sha(p)=='bb14e0b18255d8ff346696aa0865864d44a6fab752ae3a26463bd15ba040963f','Original module changed')
    with p.open('rb') as f:d=ELFFile(f).get_section_by_name('.text').data()
    result=[]
    for base in (0,0x70000000):
        for nr in (7,12,16):
            u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.mem_map(0x100000,0x10000);u.mem_write(0x100000,d)
            u.mem_map(0x200000,4096);u.mem_write(0x200030,struct.pack('<Q',base));u.reg_write(UC_ARM64_REG_X20,0x200000);u.reg_write(UC_ARM64_REG_X19,nr)
            state=[]
            def stop(uc,addr,size,data):
                if addr in (0x100510,0x100554):state.append(addr);uc.emu_stop()
            u.hook_add(UC_HOOK_CODE,stop);u.emu_start(0x100544,0,count=20)
            allowed=state==[0x100554];require(allowed==(base!=0 or nr==16),'Original dispatcher gate differs')
            result.append({'control_map_base':base,'request_nr':nr,'allowed_to_next_check':allowed,'passed':True,'original_range':'.text544..550'})
    return result

def entry(name,kind=8):
    name=name.encode()+b'\0';size=(19+len(name)+7)&~7
    return struct.pack('<QqHB',1,0,size,kind)+name+bytes(size-19-len(name))

def lifecycle(job,scenario):
    meta=json.loads((job/'job.json').read_text());directory=meta['job_dir'];u,_=image(job)
    with (job/'worker.debug.elf').open('rb') as f:start=ELFFile(f)['e_entry']
    sp=0x80080000;u.mem_write(sp,struct.pack('<4Q',2,sp+256,sp+300,0));u.mem_write(sp+256,b'worker\0');u.mem_write(sp+300,b'123\0');u.reg_write(UC_ARM64_REG_SP,sp)
    nonce=bytes.fromhex(meta['nonce'])
    files={directory+'/worker':b'x',directory+'/start':(b'BADSTART' if scenario=='bad_start' else b'M4START1')+nonce+struct.pack('<Q',1),directory+'/ack':b'M4ACK001'+nonce+struct.pack('<Q',1),'/proc/123/maps':b'1000 r-x '+(b'libJit.so' if scenario=='loader_busy' else b'libJiritsu.so')+b'\n'}
    dirs={'/proc/123/fd':entry('.',4)+entry('0')};fds={};opened=[];state={'fd':3,'clock':1,'exit':None,'ioctls':0,'mapped':False}
    def ret(v):u.reg_write(UC_ARM64_REG_X0,v&MASK)
    def string(a):return bytes(u.mem_read(a,512)).split(b'\0')[0].decode()
    def intr(uc,number,data):
        nr=u.reg_read(UC_ARM64_REG_X8);a=[u.reg_read(UC_ARM64_REG_X0+i) for i in range(6)];x,b,c,d,_,_=a
        if nr==56:
            p=string(b);opened.append(p)
            if p=='/dev/uipc':
                require(c==0x88002,'Bad live candidate device flags');fd=state['fd'];state['fd']+=1;fds[fd]=[p,0,False];state['devicefd']=fd;ret(fd);return
            writing=c==0x880c1
            if writing:
                require(p.startswith(directory+'/'),'Write outside tmpfs')
                if p in files:ret(-17);return
                files[p]=b''
            else:
                require(c in (0x88000,0x8c000),'Bad lifecycle read flags')
                if p=='/proc/self/fd':dirs[p]=entry('.',4)+entry(str(state['fd']))+(entry('900') if scenario=='inherited_fd' else b'')
                if p not in files and p not in dirs:ret(-2);return
            fd=state['fd'];state['fd']+=1;fds[fd]=[p,0,writing];ret(fd)
        elif nr==57:fds.pop(x,None);ret(0)
        elif nr in (63,61):
            p,pos,_=fds[x];raw=(dirs if nr==61 else files)[p];n=min(c,len(raw)-pos)
            if n:u.mem_write(b,raw[pos:pos+n])
            fds[x][1]+=n;ret(n)
        elif nr==64:
            p,_,writing=fds[x];require(writing and p.startswith(directory+'/'),'Wrong write FD');files[p]+=bytes(u.mem_read(b,c));ret(c)
        elif nr==35:
            p=string(b);require(p.startswith(directory+'/'),'Unlink outside tmpfs')
            if p in files:del files[p];ret(0)
            else:ret(-2)
        elif nr==43:
            require(string(x)=='/tmp_wbshd','Wrong statfs');u.mem_write(b,struct.pack('<15q',0xef53 if scenario=='not_tmpfs' else 0x1021994,4096,100000,100000,100000,0,0,0,255,4096,0,0,0,0,0));ret(0)
        elif nr==175:ret(1000 if scenario=='not_root' else 0)
        elif nr==172:ret(234)
        elif nr==173:ret(1)
        elif nr==113:u.mem_write(b,struct.pack('<2q',state['clock'],0));state['clock']+=1;ret(0)
        elif nr==101:ret(0)
        elif nr==78:
            require(fds[x][0]=='/proc/123/fd','Wrong readlink');u.mem_write(c,b'/dev/null');ret(9)
        elif nr==29:
            require(x==state['devicefd'],'Wrong device FD');selector,pad,ptr=struct.unpack('<IIQ',u.mem_read(c,16));require(not pad,'Padding');state['ioctls']+=1
            if b==0x80000010:u.mem_write(ptr,struct.pack('<4I',0x200000,0x80000,0x20000,0x803f6001));ret(0)
            elif b==0x80000007:
                pointer,timeout,pad=struct.unpack('<QII',u.mem_read(ptr,16));require(selector==0x803f6002 and timeout==pad==0,'Wrong recipient receive');ret(-0x3fe)
            elif b==0x8000000c:
                op,label,value=struct.unpack('<IIQ',u.mem_read(ptr,16));require(selector==0,'Dynamic selector')
                if op==0x2a:require(label==0x3f,'Label');u.mem_write(value,struct.pack('<I',0x803f6002));ret(0)
                else:require(op==0x4a and label==0 and value==0x803f6002,'Free wrong ID');ret(0)
            else:raise RuntimeError('Unapproved ioctl')
        elif nr==222:require(a==[0,0x200000,3,1,state['devicefd'],0],'Wrong IPC alias');state['mapped']=True;ret(0x70000000)
        elif nr==215:require(a[:2]==[0x70000000,0x200000],'Wrong unmap');state['mapped']=False;ret(0)
        elif nr==94:state['exit']=x;u.emu_stop()
        else:raise RuntimeError('Unapproved lifecycle syscall '+str(nr))
    u.hook_add(UC_HOOK_INTR,intr);u.emu_start(start,0,count=4000000)
    require(state['exit'] is not None,'Lifecycle instruction limit')
    from camera_osal_probe import decode
    r=decode(files[directory+'/result'],meta);clean=decode(files[directory+'/cleaned'],meta)
    if scenario=='success':
        require(r['phase']==4 and r['error']==0 and state['ioctls']==4,'Lifecycle sequence failed')
        require(not state['mapped'] and not fds,'Resources left after success')
    else:require(r['phase']==90 and r['error']<0 and state['ioctls']==0,'Lifecycle guard touched OSAL')
    require(clean['phase']==5 and clean['error']==r['error'],'Cleanup publication inconsistent')
    require(directory+'/probe' not in files and directory+'/ack' not in files,'Output cleanup incomplete')
    return {'scenario':'lifecycle_'+scenario,'passed':True,'phase':r['phase'],'error':r['error'],'ioctls':state['ioctls'],'opened':opened,'mock_boundary':'all Linux syscalls, filesystem, processes and SDK driver'}

def error_sign_extension():
    p=ROOT/'local/analysis/normal-kernel-6.02.elf'
    require(sha(p)=='a145e0c9fa81166fb52db7b24b874aa995c67d3ff4d7a50e21fcc402f9881213','Kernel artifact changed')
    address=0xffffff80083978ac
    with p.open('rb') as f:
        e=ELFFile(f);section=next(s for s in e.iter_sections() if s['sh_addr']<=address<s['sh_addr']+s['sh_size']);raw=section.data()[address-section['sh_addr']:address-section['sh_addr']+4]
    rows=[]
    for value in (-1022,-14,0):
        u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.mem_map(0x100000,4096);u.mem_write(0x100000,raw);u.reg_write(UC_ARM64_REG_X19,value&0xffffffff);u.emu_start(0x100000,0x100004,count=1)
        actual=u.reg_read(UC_ARM64_REG_X0);require(actual==value&MASK,'Raw ioctl sign extension changed');rows.append({'driver_int':value,'syscall_long_bits':hex(actual),'passed':True})
    return rows

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--job',type=Path,required=True);a=p.parse_args();job=a.job.resolve()
    scenarios=['success','open_error','init_error','init_bad','mmap_error','mmap_zero','alloc_error','alloc_copyout','alloc_bad','alloc_bootstrap','recv_error','recv_payload','recv_success','free_error','unmap_error','close_error','label_zero','nomap_profile']
    rows=[candidate(job,s) for s in scenarios];rows += [lifecycle(job,s) for s in ("success","bad_start","inherited_fd","loader_busy","not_root","not_tmpfs")];gate=original_gate()
    report={'schema':'camera-use-osal-emulation/1','all_passed':True,'worker_sha256':sha(job/'worker.elf'),'bootstrap_sha256':sha(job/'libJit.so'),'tests':rows,'original_dispatch_gate_verified':True,'original_dispatch_gate':gate,'raw_error_sign_extension_verified':True,'raw_error_sign_extension':error_sign_extension(),'physical_acceptance':False,'scope_authorization':False,'lifecycle_full_worker_emulated':True,'limitations':['OS syscalls and driver return/copyout mocked in candidate tests','original gate is real raw instructions but starts after usercopy','does not prove device permissions, live pool cleanliness or teardown after transport loss']}
    save(job/'emulation.json',report);print(json.dumps({'all_passed':True,'candidate_cases':len(rows),'original_gate_cases':len(gate),'device_actions':0}))
if __name__=='__main__':main()
