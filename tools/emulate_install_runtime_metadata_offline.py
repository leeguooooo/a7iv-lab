"""Actual AArch64 metadata instructions with synthetic fixed-path syscalls."""
import argparse,hashlib,io,json,struct,sys
from collections import Counter
from pathlib import Path
from tempfile import TemporaryDirectory
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_INTR
from unicorn.arm64_const import UC_ARM64_REG_SP,UC_ARM64_REG_X0,UC_ARM64_REG_X8
from elftools.elf.elffile import ELFFile
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
sys.path.insert(0,str(Path(__file__).resolve().parent))
from camera_install_runtime_metadata import FRAME,START_FRAME,START_MAGIC,ALIAS,NUMBERS,decode_frame
from install_runtime_metadata_profile import ROOT,require,sha,jobpath
from verify_install_runtime_metadata_offline import verify
from emulate_install_patch_read_offline import _bootstrap_case,READ_BOOTSTRAP_CASES
from model_toolchain_bootstraps_offline import module_info
BOOTSTRAP_CASES=READ_BOOTSTRAP_CASES
CASES=('success','relative_alias','positive_short_read','read_eintr','transient_parent','parent_never_settles',
 'not_root','wrong_tmpfs','missing_proc','proc_error','proc_close_error','proc_overflow','missing_alias',
 'readlink_error','readlink_oversize','wrong_target','stat_error','not_block','alias_change','rdev_change',
 'wrong_START','partial_START','missing_START','ready_open_error','ready_write_error','ready_close_error',
 'payload_open_error','payload_write_error','payload_close_error','result_open_error','result_write_error',
 'result_close_error','rename_error','destination_exists','interrupted_after_payload')
SUCCESS={'success','relative_alias','positive_short_read','read_eintr','transient_parent'}
def emulate(job,case,m):
 require(case in CASES,'Unknown metadata case');nonce=bytes.fromhex(m['nonce']);directory=m['job_dir'];token=START_FRAME.pack(START_MAGIC,nonce,1)
 if case=='wrong_START':token=b'WRONG123'+token[8:]
 if case=='partial_START':token=token[:20]
 files={directory+'/worker':b'worker',directory+'/start':token};proc=b'major minor  #blocks  name\n'+b''.join(f'252 {128+n} 16384 cnflasha{n}\n252 {n} 16384 pnflasha{n}\n'.encode() for n in NUMBERS)
 if case=='proc_overflow':proc=b'x'*65537
 if case!='missing_proc':files['/proc/partitions']=proc
 if case=='missing_START':files.pop(directory+'/start')
 if case=='destination_exists':files[directory+'/result']=b'KEEP'
 u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);elf=ELFFile(io.BytesIO((job/'worker.debug.elf').read_bytes()));pages=set()
 for s in elf.iter_segments():
  if s['p_type']=='PT_LOAD':pages.update(range(s['p_vaddr']&~4095,(s['p_vaddr']+s['p_memsz']+4095)&~4095,4096))
 for p in sorted(pages):u.mem_map(p,4096)
 for s in elf.iter_segments():
  if s['p_type']=='PT_LOAD':u.mem_write(s['p_vaddr'],s.data())
 u.mem_map(0x90000000,0x100000);sp=0x90080000;u.reg_write(UC_ARM64_REG_SP,sp);u.mem_write(sp,struct.pack('<4Q',2,sp+256,sp+300,0));u.mem_write(sp+256,b'worker\0');u.mem_write(sp+300,b'888\0')
 fds={};state=dict(next=3,exit=None,clock=0,interrupted=False,eintr=False,parent=0);counts=Counter();opens=[];stats=[];links=[];trace=[]
 def text(at):return bytes(u.mem_read(at,512)).split(b'\0',1)[0].decode()
 def ret(value):u.reg_write(UC_ARM64_REG_X0,value&((1<<64)-1))
 def fault(path,kind):
  prefix='ready' if path.endswith('/ready.pending') else 'result' if path.endswith('/result.pending') else 'payload' if path.endswith('/partitions.pending') else ''
  return case==prefix+'_'+kind+'_error'
 def syscall(_u,number,_data):
  require(number==2,'SVC only');no=u.reg_read(UC_ARM64_REG_X8);args=[u.reg_read(UC_ARM64_REG_X0+i) for i in range(6)];a,b,c,d,e,f=args;counts[no]+=1;trace.append(no)
  if no==57:
   if a not in fds:ret(-9);return
   path,pos,flags=fds.pop(a);ret(-5 if fault(path,'close') or (case=='proc_close_error' and path=='/proc/partitions') else 0)
  elif no in (172,173,175):
   if no==173:state['parent']+=1
   ret(777 if no==172 else (0 if case!='not_root' else 1000) if no==175 else (2 if case=='parent_never_settles' or (case=='transient_parent' and state['parent']<3) else 1))
  elif no==35:
   path=text(b);require(path in (directory+'/worker',directory+'/start'),'Unexpected unlink');ret(0 if files.pop(path,None) is not None else -2)
  elif no==43:
   require(text(a)=='/tmp_wbshd','Unexpected statfs');u.mem_write(b,struct.pack('<15q',0 if case=='wrong_tmpfs' else 0x1021994,4096,100000,100000,100000,0,0,0,255,4096,0,0,0,0,0));ret(0)
  elif no==113:state['clock']+=1;u.mem_write(b,struct.pack('<2q',state['clock'],0));ret(0)
  elif no==101:ret(0)
  elif no==56:
   path=text(b);opens.append(dict(path=path,flags=c));require(not path.startswith('/dev/') and (path=='/proc/partitions' or path.startswith(directory+'/')),'Forbidden open')
   require(c==(0x88000 if path in ('/proc/partitions',directory+'/start') else 0x880c1),'Wrong open flags')
   if fault(path,'open'):ret(-5);return
   if c==0x880c1:
    if path in files:ret(-17);return
    files[path]=b''
   if path not in files:ret(-2);return
   fd=state['next'];state['next']+=1;fds[fd]=[path,0,c];ret(fd)
  elif no==63:
   path,pos,flags=fds[a]
   if path=='/proc/partitions' and case=='proc_error':ret(-5);return
   if path=='/proc/partitions' and case=='read_eintr' and not state['eintr']:state['eintr']=True;ret(-4);return
   raw=files[path][pos:pos+min(c,17 if case=='positive_short_read' else c)];u.mem_write(b,raw);fds[a][1]+=len(raw);ret(len(raw))
  elif no==64:
   path,pos,flags=fds[a];require(path.startswith(directory+'/') and flags==0x880c1,'Non-output write')
   if fault(path,'write'):ret(-5);return
   raw=bytes(u.mem_read(b,c));files[path]+=raw;fds[a][1]+=len(raw);ret(len(raw))
  elif no in (78,79):
   path=text(b);require(path in tuple('/dev/nflasha'+str(n) for n in NUMBERS),'Arbitrary metadata path');n=int(path[12:]);index=NUMBERS.index(n)
   if no==78:
    links.append(path)
    if case in ('missing_alias','readlink_error') and n==3:ret(-2 if case=='missing_alias' else -5);return
    raw=(('' if case=='relative_alias' else '/dev/')+'cnflasha'+str(n)).encode()
    if case=='wrong_target' and n==3:raw=b'../../etc/passwd'
    if case=='alias_change' and n==1 and len(links)>6:raw=b'/dev/pnflasha1'
    if case=='readlink_oversize':raw=b'x'*128
    u.mem_write(c,raw[:d]);ret(min(len(raw),d))
   else:
    require(d==0,'stat must follow fixed verified alias');stats.append(path)
    if case=='stat_error' and n==3:ret(-5);return
    raw=bytearray(128);struct.pack_into('<I',raw,16,0o60000 if case!='not_block' else 0o100000);rdev=(252<<8)|(128+n)
    if case=='rdev_change' and n==1 and len(stats)>6:rdev+=1
    struct.pack_into('<Q',raw,32,rdev);u.mem_write(c,bytes(raw));ret(0)
  elif no==276:
   old,new=text(b),text(d);require(old.startswith(directory+'/') and new.startswith(directory+'/') and e==1,'Wrong rename')
   if case=='rename_error' and new.endswith('/result'):ret(-5);return
   if new in files:ret(-17);return
   files[new]=files.pop(old);ret(0)
   if case=='interrupted_after_payload' and new.endswith('/aliases.bin'):state['interrupted']=True;u.emu_stop()
  elif no==94:state['exit']=a;u.emu_stop()
  else:raise AssertionError('Forbidden syscall '+str(no))
 u.hook_add(UC_HOOK_INTR,syscall);u.emu_start(elf['e_entry'],0,count=6000000)
 require(state['exit'] is not None or state['interrupted'],'Model instruction budget exhausted');final=files.get(directory+'/result')
 if case in SUCCESS:
  require(state['exit']==0 and final is not None,'Success missing terminal');row,ps,als=decode_frame(final,nonce=m['nonce'],loader_pid=888,phase=7)
  require(hashlib.sha256(files[directory+'/partitions.bin']).digest()==ps and hashlib.sha256(files[directory+'/aliases.bin']).digest()==als,'Native SHA mismatch');require(not fds,'Native leaked FDs')
 else:require(state['exit']!=0 or state['interrupted'],'Fault false success')
 require(not counts[67] and not counts[68] and not counts[29] and not counts[117],'Forbidden process/block operations')
 return dict(case=case,passed=True,exit=state['exit'],interrupted=state['interrupted'],syscalls=dict(counts),opens=opens,readlink_calls=len(links),stat_calls=len(stats),block_opens=0,process_memory_writes=0,terminal_hex=final.hex() if final else None,
  ready_hex=files.get(directory+'/ready',b'').hex(),partitions_hex=files.get(directory+'/partitions.bin',b'').hex(),aliases_hex=files.get(directory+'/aliases.bin',b'').hex(),trace_sha256=hashlib.sha256(bytes(no%256 for no in trace)).hexdigest())
def _base(job,m,verification,cases):
 return dict(all_passed=True,manifest_sha256=sha(job/'manifest.json'),verification_sha256=hashlib.sha256(json.dumps(verification,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest(),source_bindings=m['sources'],artifact_bindings=m['artifacts'],cases=list(cases),declared_cases=list(cases),coverage_complete_for_declared_matrix=True,debug_worker_sha256=sha(job/'worker.debug.elf'),emulator_sha256=sha(Path(__file__)),contract_sha256=sha(ROOT/'camera_install_runtime_metadata.py'),profile_sha256=sha(ROOT/'tools/install_runtime_metadata_profile.py'),hardware_operations=0,real_ARM_process=False,execution_kind='EMULATED_INSTRUCTIONS_ONLY')
def run(job):
 job=jobpath(job);verification=verify(job);m=json.loads((job/'manifest.json').read_bytes());results=[emulate(job,c,m) for c in CASES];verify(job)
 native=dict(_base(job,m,verification,CASES),schema='camera-install-runtime-metadata-native-model/1',results=results)
 with (job/'native-model-report.json').open('x') as f:json.dump(native,f,indent=2)
 with TemporaryDirectory(prefix='metadata-bootstrap-MODEL-',dir=ROOT/'output') as temp:
  fixture=Path(temp);module=(job/'libJit.so').read_bytes();worker=(job/'worker.elf').read_bytes();(fixture/'libJit.so').write_bytes(module);(fixture/'worker.elf').write_bytes(worker)
  (fixture/'bootstrap.json').write_text(json.dumps(dict(nonce=m['nonce'],job_dir=m['job_dir'],module=module_info(module),model_fixture_only=True)))
  results=[_bootstrap_case(fixture,c) for c in BOOTSTRAP_CASES]
 boot=dict(_base(job,m,verification,BOOTSTRAP_CASES),schema='camera-install-runtime-metadata-bootstrap-model/1',results=results,model_only_adapter=True)
 with (job/'bootstrap-model-report.json').open('x') as f:json.dump(boot,f,indent=2)
 return native,boot
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--job',required=True);a=p.parse_args();n,b=run(a.job);print(json.dumps(dict(native_cases=len(n['cases']),bootstrap_cases=len(b['cases']),all_passed=True,hardware_operations=0)))
