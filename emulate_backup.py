"""Tiny-image protocol tests plus fail-closed tests on the production ARM64 ELF.

Tiny-image execution tests identical C with smaller generated target constants;
it does not certify real-device geometry or a full-size hash execution.
"""
import argparse
import json
import struct
from pathlib import Path

from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_INTR
from unicorn.arm64_const import UC_ARM64_REG_SP, UC_ARM64_REG_X0, UC_ARM64_REG_X8
from camera_inventory import require, save, sha
from camera_backup import decode
from emulate_inventory import entry


def emulate(job,scenario):
    meta=json.loads((job/'job.json').read_text());directory=meta['job_dir'];u=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
    with (job/'worker.debug.elf').open('rb') as f:
        elf=ELFFile(f);pages=set()
        for s in elf.iter_segments():
            if s['p_type']=='PT_LOAD':pages.update(range(s['p_vaddr']&~4095,(s['p_vaddr']+s['p_memsz']+4095)&~4095,4096))
        # Mapping thousands of pages individually makes Unicorn's teardown
        # rebuild its memory topology for each page. Preserve the same address
        # coverage using contiguous ranges instead.
        ranges=[]
        for page in sorted(pages):
            if ranges and ranges[-1][1]==page:ranges[-1][1]+=4096
            else:ranges.append([page,page+4096])
        for first,last in ranges:u.mem_map(first,last-first)
        for s in elf.iter_segments():
            if s['p_type']=='PT_LOAD':u.mem_write(s['p_vaddr'],s.data())
        start=elf['e_entry']
    stack=0x80000000;u.mem_map(stack,0x100000);sp=stack+0x80000;u.reg_write(UC_ARM64_REG_SP,sp)
    u.mem_write(sp,struct.pack('<4Q',2,sp+256,sp+300,0));u.mem_write(sp+256,b'worker\0');u.mem_write(sp+300,b'123\0')
    nonce=bytes.fromhex(meta['nonce'])
    files={directory+'/worker':b'x',directory+'/start':b'M4START1'+nonce+struct.pack('<Q',1),
           '/proc/123/maps':b'1000 r-x /usr/lib/libJiritsu.so\n','/proc/self/mountinfo':b'1 0 252:130 / /setting rw - vfat /dev/nflasha2 rw\n'}
    for i in range(5):files[directory+f'/ack{i}']=b'M4ACK001'+nonce+struct.pack('<Q',i+1)
    if scenario=='bad_ack':files[directory+'/ack0']=b'M4ACK001'+nonce+struct.pack('<Q',9)
    devs={}
    for name,minor,size in meta['targets']:
        devs['/dev/'+name]={'size':size,'rdev':(252<<8)|minor,'reads':0}
        files['/sys/class/block/'+name+'/dev']=f'252:{minor}\n'.encode()
        files['/sys/class/block/'+name+'/size']=f'{size//512}\n'.encode()
    if scenario=='bad_sysfs':files['/sys/class/block/'+meta['targets'][0][0]+'/dev']=b'999:1\n'
    fds={};dirs={'/proc/123/fd':entry('.',4)+entry('0')};calls=[];opened=[];state={'next':3,'exit':None,'clock':1}
    def text(p):
        raw=bytes(u.mem_read(p,1024));require(b'\0' in raw,'String bound');return raw.split(b'\0',1)[0].decode()
    def ret(n):u.reg_write(UC_ARM64_REG_X0,n&((1<<64)-1))
    def syscall(_u,_n,_d):
        no=u.reg_read(UC_ARM64_REG_X8);a,b,c,d,e,f=[u.reg_read(UC_ARM64_REG_X0+i) for i in range(6)];calls.append(no)
        if no==56:
            path=text(b);opened.append((path,c));creating=c&3
            if creating:
                require(path.startswith(directory+'/') and c==0x880c1,'Writable source/block handle')
                if path in files:ret(-17);return
                files[path]=b''
            else:
                require(c in (0x88000,0x8c000),'Unexpected flags')
                if path=='/proc/self/fd':dirs[path]=entry('.',4)+entry(str(state['next']))
                if path not in files and path not in dirs and path not in devs:ret(-2);return
                if path in devs:require(c==0x88000,'Block source is not O_RDONLY|CLOEXEC|NOFOLLOW')
            fd=state['next'];state['next']+=1;fds[fd]=[path,0,creating];ret(fd)
        elif no==57:fds.pop(a,None);ret(0)
        elif no in (61,63):
            path,pos,_=fds[a];raw=(dirs if no==61 else files)[path];n=min(c,len(raw)-pos)
            if scenario=='short_reads' and no==63:n=min(n,31)
            if n:u.mem_write(b,raw[pos:pos+n])
            fds[a][1]+=n;ret(n)
        elif no==64:
            path,_,creating=fds[a];require(creating and path.startswith(directory+'/'),'Write outside tmpfs')
            files[path]+=bytes(u.mem_read(b,c));ret(c)
        elif no==35:
            path=text(b);require(path.startswith(directory+'/'),'Unlink outside tmpfs')
            if path in files:del files[path];ret(0)
            else:ret(-2)
        elif no==43:
            require(text(a)=='/tmp_wbshd','Wrong statfs');u.mem_write(b,struct.pack('<15q',0x1021994,4096,100000,100000,100000,0,0,0,255,4096,0,0,0,0,0));ret(0)
        elif no==80:
            path=fds[a][0];require(path in devs,'Non-device fstat');raw=bytearray(128)
            struct.pack_into('<I',raw,16,0o020600 if scenario=='not_block' else 0o060600)
            struct.pack_into('<Q',raw,32,devs[path]['rdev']+(1 if scenario=='wrong_device' else 0));u.mem_write(b,bytes(raw));ret(0)
        elif no==29:
            path=fds[a][0];require(path in devs and b==0x80081272,'Only BLKGETSIZE64 may be issued')
            u.mem_write(c,struct.pack('<Q',devs[path]['size']+(512 if scenario=='wrong_size' else 0)));ret(0)
        elif no==67:
            path=fds[a][0];require(path in devs and not fds[a][2],'Non-read-only device')
            if scenario=='read_error':ret(-5);return
            require(d+c<=devs[path]['size'],'Source read outside geometry')
            n=min(c,31) if scenario=='short_reads' else c
            require(n<=65536,'Unexpected read size')
            raw=bytes(((d+i)*7+3)&255 for i in range(n));devs[path]['reads']+=1
            if scenario=='changed_second_read' and devs[path]['reads']>1:raw=bytes([raw[0]^1])+raw[1:]
            u.mem_write(b,raw);ret(n)
        elif no==78:require(fds[a][0]=='/proc/123/fd','Wrong readlink');u.mem_write(c,b'/dev/null');ret(9)
        elif no==175:ret(1000 if scenario=='not_root' else 0)
        elif no==172:ret(234)
        elif no==173:ret(1)
        elif no==113:u.mem_write(b,struct.pack('<2q',state['clock'],0));state['clock']+=1;ret(0)
        elif no==101:ret(0)
        elif no==94:state['exit']=a;u.emu_stop()
        else:raise RuntimeError(f'Unapproved syscall {no}')
    u.hook_add(UC_HOOK_INTR,syscall);u.emu_start(start,0,count=10000000)
    require(state['exit'] is not None,'Instruction budget exceeded')
    r=decode(files[directory+'/result'],meta);success=scenario in ('success','short_reads')
    require((r['phase']==6 and r['error']==0)==success,f'Unexpected {scenario}: {r}')
    if success:
        import hashlib
        for i,(name,minor,size) in enumerate(meta['targets']):
            part=decode(files[directory+f'/part{i}'],meta);expected=hashlib.sha256(bytes((j*7+3)&255 for j in range(size))).hexdigest()
            require(part['first_sha256']==part['second_sha256']==expected and part['bytes']==size and part['flags']==127,'Snapshot/hash mismatch')
            require(not any(path.startswith(directory+f'/t{i}c') for path in files),'ACK cleanup failed')
    else:require(r['phase']==90 and r['error']<0,'Missing rejection')
    require(all(flags&3==0 for path,flags in opened if path.startswith('/dev/')),'Writable device handle')
    return {'scenario':scenario,'passed':True,'phase':r['phase'],'error':r['error'],'syscalls':sorted(set(calls))}


def main():
    p=argparse.ArgumentParser();p.add_argument('--job',type=Path,required=True);p.add_argument('--test-job',type=Path,required=True);a=p.parse_args()
    prod=json.loads((a.job/'job.json').read_text());tiny=json.loads((a.test_job/'job.json').read_text())
    require(prod['schema']=='camera-use-backup/1' and tiny['schema']=='camera-use-backup-test/1' and prod['sources']==tiny['sources'],'Tiny/production sources differ')
    tests=[];rejected=[]
    for s in ['success','short_reads','changed_second_read','bad_ack','bad_sysfs','not_block','wrong_device','wrong_size','read_error','not_root']:
        tests.append(emulate(a.test_job,s));print('tiny '+s+' passed',flush=True)
    for s in ['not_root','not_block','wrong_device','wrong_size','bad_sysfs','read_error']:
        rejected.append(emulate(a.job,s));print('production '+s+' passed',flush=True)
    r={'all_passed':True,'worker_sha256':prod['worker_sha256'],'module_sha256':prod['module']['sha256'],
       'tiny_image_tests':tests,'production_rejection_tests':rejected,'full_size_emulation':False,'hardware_acceptance':False}
    save(a.job/'emulation.json',r);print(json.dumps({'all_passed':True,'tiny_tests':len(tests),'production_rejections':len(rejected)}))


if __name__=='__main__':main()
