"""Compiled candidate A64 instructions in synthetic Unicorn RAM, never kernel.
Only allocator/translation/free/scnprintf imports are mocked. Analysis ELF is
relocated from the preserved .ko; no host exec, module load or device calls.
"""
from pathlib import Path
import struct,json,hashlib
from elftools.elf.elffile import ELFFile
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_MEM_READ
from unicorn.arm64_const import *
R=Path(__file__).resolve().parent;DIR=R/'local/build/pcidma-lease-only-02/build/lease-only';P=DIR/'m4btl_lease_01.analysis.elf'
SP=0x40008000;STOP=0x40009000;BUF=0x50000000;PAGE=0xffffffc000010000

def model(va=PAGE,pa=0x480000000):
 u=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
 with P.open('rb')as f:
  e=ELFFile(f);symbols={s.name:s['st_value']for s in e.get_section_by_name('.symtab').iter_symbols()};lo=min(s['p_vaddr']for s in e.iter_segments()if s['p_type']=='PT_LOAD');hi=max(s['p_vaddr']+s['p_memsz']for s in e.iter_segments()if s['p_type']=='PT_LOAD');lo&=~4095;hi=(hi+4095)&~4095;u.mem_map(lo,hi-lo)
  for s in e.iter_segments():
   if s['p_type']=='PT_LOAD':u.mem_write(s['p_vaddr'],s.data())
 for a,n in [(0x11000000,0x1000),(0x40000000,0x10000),(BUF,0x4000),(PAGE,0x2000)]:u.mem_map(a,n)
 events=[];done=[False];page_reads=[]
 def cstr(p):
  out=bytearray()
  for n in range(4096):
   v=bytes(u.mem_read(p+n,1))
   if v==b'\0':return out.decode('ascii')
   out.extend(v)
  raise AssertionError('unbounded string')
 def ret(x=0):u.reg_write(UC_ARM64_REG_X0,x&0xffffffffffffffff);u.reg_write(UC_ARM64_REG_PC,u.reg_read(UC_ARM64_REG_LR))
 def hook(_,pc,size,x):
  if pc==STOP:done[0]=True;u.emu_stop()
  elif pc==0x11000000:
   order=u.reg_read(UC_ARM64_REG_W1);assert order==0;flags=u.reg_read(UC_ARM64_REG_W0);assert flags==0x2018000;events.append(dict(mock='__get_free_pages',flags=hex(flags),order=order,returned=hex(va)));ret(va)
  elif pc==0x11000010:
   arg=u.reg_read(UC_ARM64_REG_X0);assert arg==va and va;events.append(dict(mock='arch_va_to_phys',arg=hex(arg),returned=hex(pa)));ret(pa)
  elif pc==0x11000020:raise AssertionError('No freeing is allowed in revision02')
  elif pc==0x11000030:
   dst=u.reg_read(UC_ARM64_REG_X0);cap=u.reg_read(UC_ARM64_REG_X1);fmt=cstr(u.reg_read(UC_ARM64_REG_X2));args=[u.reg_read(UC_ARM64_REG_X3+i)for i in range(5)]
   assert cap==4096 and dst==BUF
   if fmt=='%s\n':s=cstr(args[0])+'\n'
   elif fmt=='%u\n':s=str(args[0]&0xffffffff)+'\n'
   elif fmt=='0x%llx\n':s=hex(args[0])+'\n'
   elif fmt.startswith('schema=1 '):s='schema=1 profile=lease-only nonce='+cstr(args[0])+' state='+cstr(args[1])+' page_bytes='+str(args[2]&0xffffffff)+' page_phys='+hex(args[3])+' resident='+cstr(args[4])+' dma=0\n'
   else:raise AssertionError('unreviewed format '+fmt)
   data=s.encode();assert len(data)<cap;u.mem_write(dst,data+b'\0');events.append(dict(mock='scnprintf',format=fmt,bytes=len(data)));ret(len(data))
 def mem(_,access,address,size,value,data):
  if PAGE<=address<PAGE+0x2000:page_reads.append(hex(address))
 u.hook_add(UC_HOOK_CODE,hook);u.hook_add(UC_HOOK_MEM_READ,mem)
 def invoke(name,args=()):
  done[0]=False;u.reg_write(UC_ARM64_REG_SP,SP);u.reg_write(UC_ARM64_REG_LR,STOP)
  for n,v in enumerate(args):u.reg_write(UC_ARM64_REG_X0+n,v)
  u.emu_start(symbols[name],0,count=10000);assert done[0],'model budget';v=u.reg_read(UC_ARM64_REG_W0);return v-(1<<32)if v>>31 else v
 result=invoke('init_module');state=struct.unpack('<I',u.mem_read(symbols['lease_state'],4))[0];savedva,savedpa=[struct.unpack('<Q',u.mem_read(symbols[n],8))[0]for n in ['owned_va','owned_pa']]
 shape=va>=0xffffffc000000000 and va<=0xfffffffffffff000 and not(va&4095)
 expect=0 if va and shape and pa>=0x400000000 and pa<=0x500000000-4096 and not(pa&4095) else(-12 if not va else-14 if not shape else-34)
 assert result==expect
 assert bool([x for x in events if x['mock']=='arch_va_to_phys'])==bool(va and shape)
 frees=[x for x in events if x['mock']=='free_pages'];assert not frees
 assert(state==2 and savedva==va and savedpa==pa)if result==0 else(state==(3 if not va else 4) and savedva==0 and savedpa==0)
 getters={};setters={}
 for name in ['nonce','state','bytes','phys','profile','version','status']:
  k=symbols['__param_'+name];n=invoke('metadata_get',[BUF,k]);assert 0<=n<4096;s=bytes(u.mem_read(BUF,n)).decode('ascii');getters[name]=s
  setters[name]=invoke('reject_set',[BUF,k]);assert setters[name]==-1
 assert sum(len(x)for x in getters.values())<4096 and not page_reads
 if result==0:assert 'state=ready page_bytes=4096 page_phys='+hex(pa)+' resident=boot dma=0\n'in getters['status']
 # Unknown selector is a synthetic own-metadata corruption, not a public input.
 u.mem_write(BUF+0x2000,struct.pack('<I',99));u.mem_write(BUF+0x2100,bytes(40));u.mem_write(BUF+0x2120,struct.pack('<Q',BUF+0x2000));assert invoke('metadata_get',[BUF,BUF+0x2100])==-22
 return dict(synthetic_input=dict(allocator_return=hex(va),physical_return=hex(pa)),init_result=result,state=state,saved_va=hex(savedva),saved_pa=hex(savedpa),free_calls=len(frees),getters=getters,setter_results=setters,page_content_reads=page_reads,events=events)

def main():
 cases=[model(pa=x)for x in [0x400000000,0x480000000,0x4fffff000,0,0x3fffff000,0x500000000,0x480000001,0xfffffffffffff000]]
 cases.extend([model(va=x)for x in [0,PAGE+1,0x60000000,0xffffff8008000000,0x8000000000000000,0xffffffbffffff000,0xfffffffffffff001]])
 o=dict(camera_io=False,real_kernel_calls=False,model='Original candidate A64 instructions after ELF relocation; three imported APIs mocked; no free import',candidate_sha256=hashlib.sha256((DIR/'m4btl_lease_01.stripped.ko').read_bytes()).hexdigest(),analysis_elf_sha256=hashlib.sha256(P.read_bytes()).hexdigest(),assertions_passed=True,cases=cases,limits=['Synthetic allocator/physical results are not real body page allocations.','scnprintf only modeled for the exact fixed formats; no real kernel sysfs path run.','No module loading, DMA/cache, CP/NOR, physical mapping or foreign memory access.'])
 out=R/'output/pcidma-OFFLINE_LEASE_ONLY-02';out.mkdir(exist_ok=True);(out/'offline-model.json').write_text(json.dumps(o,indent=2)+'\n');print(json.dumps(dict(cases=len(cases),assertions_passed=True,camera_io=False,real_kernel_calls=False)))
if __name__=='__main__':main()
