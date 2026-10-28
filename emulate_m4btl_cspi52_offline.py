"""Offline A64 module + actual normal sysfs-wrapper instruction model.
No native ELF execution, module load, DMA, cache maintenance or device API.
Kernel imports are mocks; page writes represent synthetic device data only.
"""
from pathlib import Path
from elftools.elf.elffile import ELFFile
import struct,json,re,hashlib
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_MEM_READ
from unicorn.arm64_const import *
R=Path(__file__).resolve().parent;D=R/'local/build/pcidma-cspi52-once-01/build/cspi52-once';PAGE=0xffffffc000010000;BUF=0x50000000;INPUT=BUF+0x1000;ATTR=BUF+0x2000;MK=BUF+0x3000;SP=0x40008000;STOP=0x40009000;CBRET=0x11000100
class Model:
 def __init__(self,early=False,api_rc=0,cb_err=0,cookie_bad=False,va=PAGE,pa=0x480000000,src=0x4011e74d4,pattern=bytes(range(52))):
  self.u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u=self.u;self.events=[];self.lock=0;self.irq=False;self.stopped=False;self.bridge=None;self.early=early;self.api_rc=api_rc;self.cb_err=cb_err;self.cookie_bad=cookie_bad;self.va=va;self.pa=pa;self.src=src;self.pattern=pattern;self.reads=0;self.api_count=0;self.cache_count=0
  with (D/'m4btl_cspi52_01.analysis.elf').open('rb')as f:
   e=ELFFile(f);self.sy={s.name:s['st_value']for s in e.get_section_by_name('.symtab').iter_symbols()};sg=[s for s in e.iter_segments()if s['p_type']=='PT_LOAD'];lo=min(s['p_vaddr']for s in sg)&~4095;hi=(max(s['p_vaddr']+s['p_memsz']for s in sg)+4095)&~4095;u.mem_map(lo,hi-lo)
   for s in sg:u.mem_write(s['p_vaddr'],s.data())
  with (R/'local/analysis/normal-kernel-6.02.elf').open('rb')as f:
   e=ELFFile(f);s=next(s for s in e.iter_segments()if s['p_type']=='PT_LOAD');u.mem_map(s['p_vaddr'],0x800000);u.mem_write(s['p_vaddr'],s.data())
  for a,n in [(0x11000000,0x1000),(0x40000000,0x10000),(BUF,0x10000),(PAGE,0x1000)]:u.mem_map(a,n)
  u.mem_write(MK+0x40,struct.pack('<Q',self.sy['__this_module']));self.nonce=self.cstr(self.sy['diag_nonce']);u.hook_add(UC_HOOK_CODE,self.code);u.hook_add(UC_HOOK_MEM_READ,self.memory)
 def val(self,name):return struct.unpack('<I',self.u.mem_read(self.sy[name],4))[0]
 def cstr(self,p):
  out=bytearray()
  for i in range(4096):
   v=bytes(self.u.mem_read(p+i,1))
   if v==b'\0':return out.decode('ascii')
   out.extend(v)
  raise AssertionError('unbounded string')
 def ret(self,v=0):self.u.reg_write(UC_ARM64_REG_X0,v&0xffffffffffffffff);self.u.reg_write(UC_ARM64_REG_PC,self.u.reg_read(UC_ARM64_REG_LR))
 def begin_callback(self,err,cookie):
  self.irq=True;self.u.reg_write(UC_ARM64_REG_W0,err&0xffffffff);self.u.reg_write(UC_ARM64_REG_X1,cookie);self.u.reg_write(UC_ARM64_REG_LR,CBRET);self.u.reg_write(UC_ARM64_REG_PC,self.sy['dma_complete']);self.events.append(dict(event='callback-enter',err=err,cookie=hex(cookie)))
 def code(self,uc,pc,size,data):
  u=self.u
  if pc==STOP:self.stopped=True;u.emu_stop();return
  if pc==CBRET:
   self.events.append(dict(event='callback-return'));self.irq=False
   if self.bridge is not None:
    c=self.bridge;self.bridge=None;u.context_restore(c);self.ret(self.api_rc)
   else:self.stopped=True;u.emu_stop()
   return
  if pc==0x11000000:
   assert u.reg_read(UC_ARM64_REG_W0)==0x2018000 and u.reg_read(UC_ARM64_REG_W1)==0;self.events.append(dict(event='alloc-mock',flags='0x2018000',returned=hex(self.va)));self.ret(self.va)
  elif pc==0x11000010:assert u.reg_read(UC_ARM64_REG_X0)==self.va;self.events.append(dict(event='own-VA-translate-mock'));self.ret(self.pa)
  elif pc==0x11000020:assert u.reg_read(UC_ARM64_REG_W0)==0x011e74d4;self.events.append(dict(event='fixed-p32-conversion-mock',returned=hex(self.src)));self.ret(self.src)
  elif pc==0x11000030:
   assert not self.irq and self.lock==1;assert [u.reg_read(x)for x in [UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_W2]]==[PAGE,4096,2]
   stage='predma'if self.api_count==0 else'postdma';self.cache_count+=1
   if stage=='postdma':assert self.val('context')==1 # claimed first
   self.events.append(dict(event='cache-mock',stage=stage,address=hex(PAGE),bytes=4096,direction=2));self.ret()
  elif pc==0x11000040:
   assert not self.irq and self.lock==1;self.api_count+=1;assert self.api_count==1;req=u.reg_read(UC_ARM64_REG_X0);assert req==self.sy['request']
   d=bytes(u.mem_read(req,64));pci,ch,direction,pad,n,src,dst,cb,cookie=struct.unpack_from('<4BI4Q',d);assert(pci,ch,direction,n,src,dst,cb,cookie)==(0,4,0,52,0x4011e74d4,self.pa,self.sy['dma_complete'],self.sy['context']);assert self.events[-1]['event']=='cache-mock'and self.events[-1]['stage']=='predma'
   self.events.append(dict(event='pcidma-transfer-mock',request=hex(req),cookie=hex(cookie),src=hex(src),dst=hex(dst),size=n,pcie=pci,dmac=ch,direction=direction,returns=self.api_rc))
   if self.early:
    u.mem_write(PAGE,self.pattern);self.bridge=u.context_save();self.begin_callback(self.cb_err,0xdeadbeef if self.cookie_bad else cookie)
   else:self.ret(self.api_rc)
  elif pc==0x11000050:
   assert not self.irq and self.lock==1;dst=u.reg_read(UC_ARM64_REG_X0);cap=u.reg_read(UC_ARM64_REG_X1);fmt=self.cstr(u.reg_read(UC_ARM64_REG_X2));assert dst==BUF and cap==4096 and '\n'not in fmt
   vals=[u.reg_read(UC_ARM64_REG_X3+i)for i in range(5)]+[struct.unpack('<Q',u.mem_read(u.reg_read(UC_ARM64_REG_SP)+8*i,8))[0]for i in range(10)];idx=0
   def sub(m):
    nonlocal idx
    v=vals[idx];idx+=1;t=m.group()
    if t=='%s':return self.cstr(v)
    if t=='%u':return str(v&0xffffffff)
    if t=='%d':v&=0xffffffff;return str(v-(1<<32)if v>>31 else v)
    if t=='%llx':return format(v,'x')
    if t=='%08x':return format(v&0xffffffff,'08x')
    raise AssertionError(t)
   result=re.sub(r'%llx|%08x|%s|%u|%d',sub,fmt).encode();assert len(result)<4096;u.mem_write(BUF,result+b'\0');self.ret(len(result))
  elif pc==0xffffff80084a45f0:assert self.lock==0 and not self.irq;self.lock=1;self.events.append(dict(event='module-param-lock'));self.ret()
  elif pc==0xffffff80084a46c0:assert self.lock==1 and not self.irq;self.lock=0;self.events.append(dict(event='module-param-unlock'));self.ret()
  elif pc==0xffffff8008270e60:self.ret(len(self.cstr(u.reg_read(UC_ARM64_REG_X0))))
 def memory(self,uc,access,address,size,value,data):
  if PAGE<=address<PAGE+4096:
   assert not self.irq and self.lock==1 and address==PAGE+self.reads and size==1;assert 0<=self.reads<52;assert any(e.get('stage')=='postdma'for e in self.events if e['event']=='cache-mock');self.reads+=1;self.events.append(dict(event='CPU-own-byte-read',address=hex(address),bytes=size))
 def invoke(self,addr,args=()):
  u=self.u;self.stopped=False;u.reg_write(UC_ARM64_REG_SP,SP);u.reg_write(UC_ARM64_REG_LR,STOP)
  for i,v in enumerate(args):u.reg_write(UC_ARM64_REG_X0+i,v)
  u.emu_start(addr,0,count=50000);assert self.stopped and self.lock==0;v=u.reg_read(UC_ARM64_REG_X0);return v-(1<<64)if v>>63 else v
 def init(self):
  v=self.invoke(self.sy['init_module']);return (v&0xffffffff)-(1<<32)if v&0x80000000 else v&0xffffffff
 def get(self):
  self.u.mem_write(ATTR+0x38,struct.pack('<Q',self.sy['__param_status']));n=self.invoke(0xffffff80080bbd48,[ATTR,MK,BUF]);s=bytes(self.u.mem_read(BUF,n)).decode();assert s.endswith('\n')and not s.endswith('\n\n');raw=re.search(r' raw=([0-9a-f]{104}) ',s);assert raw
  if ' raw_valid=0 'in s:assert raw[1]=='0'*104
  return s
 def submit(self,value=None):
  value=self.nonce if value is None else value;raw=value.encode();self.u.mem_write(INPUT,raw+b'\0');self.u.mem_write(ATTR+0x38,struct.pack('<Q',self.sy['__param_submit']));return self.invoke(0xffffff80080bbe30,[ATTR,MK,INPUT,len(raw)])
 def callback(self,err=0,bad=False):
  if not bad:self.u.mem_write(PAGE,self.pattern)
  self.stopped=False;self.u.reg_write(UC_ARM64_REG_SP,SP);self.begin_callback(err,0xdeadbeef if bad else self.sy['context']);self.u.emu_start(self.sy['dma_complete'],0,count=10000);assert self.stopped and not self.irq
 def record(self,name,status):return dict(name=name,status=status,api_calls=self.api_count,cache_calls=self.cache_count,page_reads=self.reads,events=self.events)
def main():
 cases=[]
 for early,err,name in [(True,0,'early-success'),(True,-5,'early-error'),(False,0,'late-success'),(False,-5,'late-error')]:
  m=Model(early=early,cb_err=err);assert m.init()==0;assert 'state=ready'in m.get()and m.api_count==0 and m.reads==0;assert m.submit()==32
  if not early:assert 'state=pending'in m.get()and m.reads==0;m.callback(err)
  s=m.get();assert ('state=error'in s and m.reads==0 and m.cache_count==1)if err else('state=done'in s and('raw='+m.pattern.hex())in s and m.reads==52 and m.cache_count==2)
  before=(m.api_count,m.reads,m.cache_count);assert m.submit()==-114;assert m.get()==s;assert before==(m.api_count,m.reads,m.cache_count);m.callback(-7);assert m.get()==s;cases.append(m.record(name,s))
 m=Model();assert m.init()==0;assert m.submit()==32
 for _ in range(3):assert 'state=pending'in m.get()
 assert m.api_count==1 and m.reads==0 and m.cache_count==1;cases.append(m.record('missing-callback-stays-pending',m.get()))
 m=Model();assert m.init()==0;m.callback(bad=True);assert' state=ready'in m.get();assert m.submit()==32;m.callback(bad=True);assert' state=pending'in m.get()and m.reads==0;m.callback();assert' state=done'in m.get();cases.append(m.record('wrong-cookie-never-dereferenced',m.get()))
 for rc in [-22,-5]:
  m=Model(api_rc=rc);assert m.init()==0;assert m.submit()==rc;assert'state=submit-error'in m.get()and m.reads==0;assert m.submit()==-114;cases.append(m.record('API-error-'+str(rc),m.get()))
 for bad in ['x'*32,'', 'short','NONCEPLUS']:
  m=Model();assert m.init()==0;assert m.submit(bad)<0 and m.api_count==0 and m.cache_count==0;cases.append(m.record('nonce-reject-'+bad,m.get()))
 m=Model();assert m.submit()==-11 and m.api_count==0;assert m.init()==0;assert m.submit(m.nonce+'\n')==33;cases.append(m.record('load-time-reject-and-singleLF-submit',m.get()))
 for kw in [dict(src=0x011e74d4),dict(va=0),dict(va=PAGE+1),dict(va=0x60000000),dict(pa=0),dict(pa=0x500000000),dict(pa=0x480000001)]:
  m=Model(**kw);assert m.init()<0 and m.api_count==0 and m.cache_count==0;assert m.submit()==-11;assert m.reads==0;cases.append(m.record('init-failure-'+str(kw),m.get()))
 m=Model(early=True,api_rc=-5);assert m.init()==0;assert m.submit()==-5;assert 'state=submit-error'in m.get()and m.reads==0;cases.append(m.record('API-error-does-not-enable-read-even-with-early-done',m.get()))
 for pattern in [bytes(52),bytes([255])*52,bytes.fromhex('004005f1')+bytes(range(4,52))]:
  m=Model(early=True,pattern=pattern);assert m.init()==0 and m.submit()==32;s=m.get();assert ('raw='+pattern.hex())in s and 'raw_valid=1'in s and m.reads==52;assert m.get()==s and m.reads==52;cases.append(m.record('raw-byte-encoding-'+pattern[:4].hex(),s))
 o=dict(camera_io=False,module_loads=0,real_DMA_cache_or_kernel_API_calls=0,candidate_sha256=hashlib.sha256((D/'m4btl_cspi52_01.stripped.ko').read_bytes()).hexdigest(),actual_sysfs_wrapper_included=True,actual_wrapper_show='FFFFFF80080BBD48',actual_wrapper_store='FFFFFF80080BBE30',assertions_passed=True,cases=cases,limits=['Synthetic device/page/IRQ schedule; no real PCI address routing, cache coherency or camera result proven.','Kernel mutex and imported APIs mocked; original wrapper instructions execute.','One-shot resources are never freed/reused; host timeout not a DMA cancellation.'])
 out=R/'output/pcidma-OFFLINE_CSPI52_ONCE-01';out.mkdir(exist_ok=True);(out/'offline-model.json').write_text(json.dumps(o,indent=2)+'\n');print(json.dumps(dict(cases=len(cases),assertions_passed=True,actual_wrapper=True,camera_io=False)))
if __name__=='__main__':main()
