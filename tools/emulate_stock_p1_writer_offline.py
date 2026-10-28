"""Synthetic AArch64 syscall models only; never opens a camera or real block node.

Production artifacts run only early-refusal cases, never a successful write.
Unknown host USB outcomes and media power-loss behavior remain unproven.
"""
import argparse
from pathlib import Path
import json
import struct
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from tools.build_stock_p1_writer_offline import validate_job, file_sha, sha, require, ROW, RESULT, FIELDS
from emulate_inventory import entry
from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_INTR
from unicorn.arm64_const import UC_ARM64_REG_SP, UC_ARM64_REG_X0, UC_ARM64_REG_X8

EARLY=('not_root','low_tmpfs','wrong_tmpfs','parent_not_detached','worker_unlink_error',
       'bad_prepare_nonce','bad_prepare_hash','bad_prepare_mode','bad_prepare_magic','prepare_timeout',
       'bad_table_size','bad_table_hash','bad_packet_size','bad_packet_before','bad_packet_after','packet_not_regular',
       'mounted_clear','mounted_raw','wrong_device','not_block','wrong_size','bad_sysfs_dev','bad_sysfs_size')
# Production models deliberately stop in admission/staging; full guard matrix uses TEST_ONLY.
PROD_CASES=EARLY[:16]
PRECOMMIT=EARLY+('inherited_fd_leak','loader_still_mapped','real_camera_geometry_refused','source_mismatch_prepare','source_mismatch_exclusive','exclusive_open_refused','existing_intent',
                'bad_commit_nonce','bad_commit_hash','bad_commit_mode','bad_commit_magic','commit_timeout')
POST=('staged_files_change_after_prepare','success','short_writes','write_eintr','write_error_rollback_ok','readback_error_rollback_ok',
      'fsync_error_rollback_ok','rollback_fail','result_publication_failure')


def emulate(job, scenario):
    job=Path(job).resolve();m=validate_job(job,allow_test=True);tiny=m['test_only']
    require(scenario in (PRECOMMIT+POST if tiny else PROD_CASES),'Production writes/success cannot be emulated')
    u=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
    with (job/'worker.debug.elf').open('rb') as f:
        elf=ELFFile(f);pages=set()
        for s in elf.iter_segments():
            if s['p_type']=='PT_LOAD':pages.update(range(s['p_vaddr']&~4095,(s['p_vaddr']+s['p_memsz']+4095)&~4095,4096))
        ranges=[]
        for p in sorted(pages):
            if ranges and ranges[-1][1]==p:ranges[-1][1]+=4096
            else:ranges.append([p,p+4096])
        for first,last in ranges:u.mem_map(first,last-first)
        for s in elf.iter_segments():
            if s['p_type']=='PT_LOAD':u.mem_write(s['p_vaddr'],s.data())
        start=elf['e_entry']
    stack=0x80000000;u.mem_map(stack,0x100000);sp=stack+0x80000
    u.reg_write(UC_ARM64_REG_SP,sp);u.mem_write(sp,struct.pack('<4Q',2,sp+256,sp+300,0));u.mem_write(sp+256,b'worker\0');u.mem_write(sp+300,b'123\0')
    directory=m['job_dir'];nonce=bytes.fromhex(m['nonce']);size=m['bytes'];device='/dev/cnflasha1'
    token=lambda magic:magic+nonce+bytes.fromhex(m['table_sha256'])+struct.pack('<Q',1)
    files={directory+'/worker':b'worker',directory+'/prepare':token(b'M4PREP01'),directory+'/commit':token(b'M4COMMIT'),
           '/sys/class/block/cnflasha1/dev':b'252:129\n','/sys/class/block/cnflasha1/size':f'{size//512}\n'.encode(),
           '/proc/self/mountinfo':b'1 2 0:1 / / rw - tmpfs tmpfs rw\n',
           '/proc/123/maps':b'1000 r-x /usr/lib/libJiritsu.so\n'}
    for p in (job/'assets').iterdir():files[directory+'/'+p.name]=p.read_bytes()
    for phase in ('prepare','commit'):
        data=bytearray(files[directory+'/'+phase])
        for suffix,offset in [('nonce',8),('hash',24),('mode',56),('magic',0)]:
            if scenario==f'bad_{phase}_{suffix}':data[offset]^=1
        if scenario==phase+'_timeout':del files[directory+'/'+phase]
        else:files[directory+'/'+phase]=bytes(data)
    if scenario=='bad_table_size':files[directory+'/table']=files[directory+'/table'][:-1]
    if scenario=='bad_table_hash':files[directory+'/table']=bytes([files[directory+'/table'][0]^1])+files[directory+'/table'][1:]
    first=m['windows'][0];packet=directory+'/'+first['name']
    if scenario=='bad_packet_size':files[packet]=files[packet][:-1]
    if scenario in ('bad_packet_before','bad_packet_after'):
        data=bytearray(files[packet]);data[0 if scenario.endswith('before') else first['length']]^=1;files[packet]=bytes(data)
    if scenario in ('mounted_clear','mounted_raw'):
        files['/proc/self/mountinfo']=b'1 2 '+(b'252:129' if scenario=='mounted_clear' else b'252:1')+b' / /x rw - ext2 /dev/source rw\n'
    if scenario=='loader_still_mapped':files['/proc/123/maps']+=b'2000 r-x /tmp/jiritsu/libJit.so\n'
    if scenario=='bad_sysfs_dev':files['/sys/class/block/cnflasha1/dev']=b'252:130\n'
    if scenario=='bad_sysfs_size':files['/sys/class/block/cnflasha1/size']=f'{size//512+1}\n'.encode()
    preserved={}
    if scenario=='existing_intent':preserved[directory+'/intent']=b'KEEP_EXISTING';files.update(preserved)
    before=(ROOT/m['source_image']).read_bytes() if tiny else None
    after=(ROOT/m['target_image']).read_bytes() if tiny else None
    block=bytearray(before) if tiny else None
    if scenario=='source_mismatch_prepare':block[42]^=1
    state={'next':3,'clock':1,'exit':None,'pwrite_calls':0,'pwrite_bytes':0,'pread_bytes':0,'opens':0,
           'failed':False,'partial':False,'eintr':False,'fsync':0,'close_events':0,'terminal_open':False,
           'terminal_after_close':True,'prepared':False,'commit_consumed':0,'prepare_consumed':0}
    fds={};dirs={};calls=[];publications=[]

    def text(ptr):
        raw=bytes(u.mem_read(ptr,1024));require(b'\0' in raw,'Unbounded native path');return raw.split(b'\0',1)[0].decode()
    def ret(value):u.reg_write(UC_ARM64_REG_X0,value&((1<<64)-1))
    def live_device():return any(row[0]==device for row in fds.values())

    def syscall(_u,_n,_data):
        no=u.reg_read(UC_ARM64_REG_X8);a,b,c,d,e,f=[u.reg_read(UC_ARM64_REG_X0+i) for i in range(6)];calls.append(no)
        if no==56:
            path=text(b);writing=c&3
            if path==device:
                require(c in (0x88000,0x88082),'Wrong block open flags');state['opens']+=1
                if c==0x88082:
                    require(state['prepared'] and state['commit_consumed']==1,'Writable open before bound COMMIT')
                    if scenario=='exclusive_open_refused':ret(-16);return
                    if scenario=='source_mismatch_exclusive':block[42]^=1
                fd=state['next'];state['next']+=1;fds[fd]=[path,0,writing];ret(fd);return
            if writing:
                allowed={directory+'/'+n for n in ('ready','prepared','intent','result','loader_maps','loader_fds')}
                allowed|={directory+f'/rb{i:04d}' for i in range(len(m['windows']))}
                require(path in allowed and c==0x880c1 and d==0o600,'Unexpected native write/create path')
                if path==directory+'/result':
                    state['terminal_open']=True;state['terminal_after_close']=not live_device()
                    require(state['terminal_after_close'],'Terminal publication before device close')
                    if scenario=='result_publication_failure':ret(-28);return
                if path in files:ret(-17);return
                files[path]=b''
            else:
                require(c in (0x88000,0x8c000),'Unexpected read flags')
                if path=='/proc/self/fd':dirs[path]=entry('.',4)+entry(str(state['next']))+(entry('99') if scenario=='inherited_fd_leak' else b'')
                elif path=='/proc/123/fd':dirs[path]=entry('.',4)+entry('0')
                if path not in files and path not in dirs:ret(-2);return
            fd=state['next'];state['next']+=1;fds[fd]=[path,0,writing];ret(fd)
        elif no==57:
            row=fds.pop(a,None)
            if row and row[0]==device:state['close_events']+=1
            if row and row[0]==directory+'/prepared':
                state['prepared']=True
                if scenario=='staged_files_change_after_prepare':files[packet]=b'CHANGED_AFTER_VERIFIED_MEMORY_STAGE'
            ret(0)
        elif no in (61,63):
            path,pos,_=fds[a];raw=(dirs if no==61 else files)[path];n=min(c,len(raw)-pos)
            if n:u.mem_write(b,raw[pos:pos+n])
            fds[a][1]+=n;ret(n)
        elif no==64:
            path,_,writing=fds[a];require(writing and path.startswith(directory+'/'),'Unexpected native file write')
            files[path]+=bytes(u.mem_read(b,c));publications.append(path);ret(c)
        elif no==35:
            path=text(b);require(path in {directory+'/'+n for n in ('worker','prepare','commit')},'Unexpected unlink')
            if path==directory+'/worker' and scenario=='worker_unlink_error':ret(-13);return
            if path not in files:ret(-2);return
            del files[path]
            if path.endswith('/commit'):state['commit_consumed']+=1
            if path.endswith('/prepare'):state['prepare_consumed']+=1
            ret(0)
        elif no==43:
            require(text(a)=='/tmp_wbshd','Wrong statfs path');free=1 if scenario=='low_tmpfs' else 100000
            u.mem_write(b,struct.pack('<15q',0 if scenario=='wrong_tmpfs' else 0x1021994,4096,100000,free,free,0,0,0,255,4096,0,0,0,0,0));ret(0)
        elif no==80:
            path=fds[a][0];raw=bytearray(128)
            if path==device:
                struct.pack_into('<I',raw,16,0o020600 if scenario=='not_block' else 0o060600)
                struct.pack_into('<Q',raw,32,64642 if scenario=='wrong_device' else 64641)
            else:
                mode=0o020600 if scenario=='packet_not_regular' and path==packet else 0o100600
                struct.pack_into('<I',raw,16,mode);struct.pack_into('<Q',raw,48,len(files[path]))
            u.mem_write(b,bytes(raw));ret(0)
        elif no==29:
            require(fds[a][0]==device and b==0x80081272,'Unexpected ioctl')
            u.mem_write(c,struct.pack('<Q',25100288 if scenario=='real_camera_geometry_refused' else size+512 if scenario=='wrong_size' else size));ret(0)
        elif no==67:
            path,pos,_=fds[a]
            if path==device:
                require(tiny,'Production source read is not modeled');require(c<=65536 and d+c<=size,'Out-of-bounds source read')
                if scenario=='readback_error_rollback_ok' and state['pwrite_bytes'] and not state['failed']:
                    state['failed']=True;ret(-5);return
                raw=bytes(block[d:d+c]);state['pread_bytes']+=c
            else:
                require(d+c<=len(files[path]),'Out-of-bounds stage read');raw=files[path][d:d+c]
            u.mem_write(b,raw);ret(len(raw))
        elif no==68:
            require(tiny and fds[a][0]==device and fds[a][2]==2 and state['prepared']
                    and state['commit_consumed']==1 and not state['terminal_open'],'Unadmitted pwrite')
            require(0<c<=16384 and d+c<=size,'Out-of-bounds block write');state['pwrite_calls']+=1
            if scenario=='write_eintr' and not state['eintr']:state['eintr']=True;ret(-4);return
            if scenario in ('write_error_rollback_ok','rollback_fail'):
                if not state['partial']:
                    n=max(1,c//2);state['partial']=True
                elif not state['failed']:
                    state['failed']=True;ret(-5);return
                elif scenario=='rollback_fail':ret(-5);return
                else:n=c
            else:n=min(c,31) if scenario=='short_writes' else c
            block[d:d+n]=bytes(u.mem_read(b,n));state['pwrite_bytes']+=n;ret(n)
        elif no==82:
            require(fds[a][0]==device,'Unexpected fsync');state['fsync']+=1
            ret(-5 if scenario=='fsync_error_rollback_ok' and state['fsync']==1 else 0)
        elif no==78:
            require(fds[a][0]=='/proc/123/fd','Unexpected readlink');u.mem_write(c,b'/dev/null');ret(9)
        elif no==175:ret(1000 if scenario=='not_root' else 0)
        elif no==172:ret(234)
        elif no==173:ret(123 if scenario=='parent_not_detached' else 1)
        elif no==113:
            u.mem_write(b,struct.pack('<2q',state['clock'],0));state['clock']+=100;ret(0)
        elif no==101:ret(0)
        elif no==94:state['exit']=a;u.emu_stop()
        else:raise RuntimeError(f'Unapproved writer syscall {no}')
    u.hook_add(UC_HOOK_INTR,syscall);u.emu_start(start,0,count=30000000)
    require(state['exit'] is not None,'Native instruction budget exceeded')
    raw=files.get(directory+'/result');final=None
    if raw is not None:
        require(len(raw)==RESULT.size,'Incomplete terminal record');magic,n,*values=RESULT.unpack(raw)
        require(magic==b'M4P1WR01' and n==nonce,'Terminal identity mismatch')
        final=dict(zip(FIELDS,values[:15]));final['before_sha256']=values[15].hex();final['after_sha256']=values[16].hex()
    success=scenario in ('success','short_writes','write_eintr','staged_files_change_after_prepare')
    if success:
        require(state['exit']==0 and final and final['phase']==6 and final['error']==0 and final['flags']==255
                and final['rollback']==0 and final['io_status']==0 and bytes(block)==after
                and final['before_sha256']==m['source_sha256'] and final['after_sha256']==m['target_sha256'],'Native success mismatch')
        require(state['prepare_consumed']==state['commit_consumed']==1,'Triggers not consumed exactly once')
    elif scenario=='result_publication_failure':
        require(state['exit']==0 and final is None and bytes(block)==after,'Missing-publication model mismatch')
    else:
        require(state['exit']==1 and final and final['phase']==90 and final['error']<0,'Failure published success')
    if scenario in PRECOMMIT:
        require(state['pwrite_calls']==0 and state['pwrite_bytes']==0,'Pre-write gate failure wrote block bytes')
    if scenario.endswith('rollback_ok'):
        require(final['rollback']==1 and bytes(block)==before and final['after_sha256']==m['source_sha256'],
                'Known I/O failure did not verify exact native rollback')
    if scenario=='rollback_fail':require(final['rollback']==2 and bytes(block)!=before,'Rollback failure falsely reported restored')
    require(not live_device() and state['terminal_after_close'],'Device descriptor not closed before terminal boundary')
    require(all(files.get(path)==data for path,data in preserved.items()),'Existing intent overwritten')
    return {'scenario':scenario,'passed':True,'pwrite_calls':state['pwrite_calls'],'pwrite_bytes':state['pwrite_bytes'],
            'source_bytes_read':state['pread_bytes'],'native_exit':state['exit'],'terminal':final,
            'device_closed_before_terminal_publication':state['terminal_after_close'],'syscalls':sorted(set(calls)),
            'unknown_host_USB_reconciliation_proven':False}


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--job',type=Path,required=True);args=p.parse_args()
    meta=validate_job(args.job,allow_test=True);cases=PRECOMMIT+POST if meta['test_only'] else PROD_CASES;tests=[]
    for scenario in cases:
        tests.append(emulate(args.job,scenario));print(scenario+' PASS',flush=True)
    report={'all_passed':True,'schema':'camera-stock-p1-writer-model-report/1','test_only':meta['test_only'],
            'job_manifest_sha256':file_sha(args.job/'job.json'),'debug_sha256':meta['debug_sha256'],
            'module_sha256':meta['module']['sha256'],'emulator_sha256':file_sha(Path(__file__)),
            'tests':tests,'production_success_or_write_emulated':False,'hardware_operations':0,
            'admission':'OFFLINE_NATIVE_GUARDS_VALIDATED_NO_EXECUTOR','unknown_after_COMMIT_reconciliation_proven':False}
    with (args.job/'emulation.json').open('x') as f:
        import os
        os.fchmod(f.fileno(),0o600);json.dump(report,f,indent=2);f.write('\n')


if __name__=='__main__':main()
