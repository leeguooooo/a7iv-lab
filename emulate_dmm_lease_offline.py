"""Offline execution of selected original dmm.ko functions with synthetic state.

No allocator/device/library executes on the host kernel. Extent allocation/free
and slot bookkeeping boundaries are mocked; results do not prove live policy.
"""
from pathlib import Path
from elftools.elf.elffile import ELFFile
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn.arm64_const import *
import hashlib,json,struct
ROOT=Path(__file__).resolve().parent;P=ROOT/'local/analysis/cspi-coldboot/dmm.ko';RAW=P.read_bytes();assert hashlib.sha256(RAW).hexdigest()=='126637b19987552f51a6749e6adac31649dd57193ef2e8bf083bfbe3e71a7579'
ARENA=0x21000000;STACK=0x20000000;STOP=0x22000000

def image():
 u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);addrs={};extern={};nextbase=0x100000;nextstub=0x1800000
 with P.open('rb') as f:
  e=ELFFile(f)
  for idx,s in enumerate(e.iter_sections()):
   if not(s['sh_flags']&2) or not s['sh_size']:continue
   addrs[idx]=nextbase;sz=(s['sh_size']+4095)&~4095;u.mem_map(nextbase,sz)
   if s['sh_type']!='SHT_NOBITS':u.mem_write(nextbase,s.data())
   nextbase+=sz+0x1000
  u.mem_map(nextstub,0x10000)
  def symbol(s):
   nonlocal nextstub
   sh=s['st_shndx']
   if sh=='SHN_UNDEF':
    if s.name not in extern:extern[s.name]=nextstub;u.mem_write(nextstub,b'\xc0\x03\x5f\xd6');nextstub+=16
    return extern[s.name]
   if sh=='SHN_ABS':return s['st_value']
   return addrs[sh]+s['st_value']
  for sec in e.iter_sections():
   if sec['sh_type']!='SHT_RELA' or sec['sh_info'] not in addrs:continue
   st=e.get_section(sec['sh_link'])
   for r in sec.iter_relocations():
    loc=addrs[sec['sh_info']]+r['r_offset'];val=symbol(st.get_symbol(r['r_info_sym']))+r['r_addend']
    if r['r_info_type']==257:u.mem_write(loc,struct.pack('<Q',val))
    elif r['r_info_type']==283:
     w=struct.unpack('<I',u.mem_read(loc,4))[0];delta=val-loc;assert not delta&3 and -(1<<27)<=delta<(1<<27);u.mem_write(loc,struct.pack('<I',(w&0xfc000000)|((delta>>2)&0x3ffffff)))
    else:raise ValueError('unknownrelocation')
  text=addrs[e.get_section_index('.text')]
 for p,s in [(ARENA,0x10000),(STACK,0x10000),(STOP,0x1000)]:u.mem_map(p,s)
 return u,text,extern

def case(name,alloc=False,fail_second=False,refs=1,opens=0,reserves=0,state=1,badgen=False,badslot=False,exclusive=False):
 u,T,extern=image();ctrl=struct.unpack('<Q',u.mem_read(T+0x95c0,8))[0];unit=ARENA;counter=ARENA+0x8000;tbl=ARENA+0x4000;ids=ARENA+0x5000;extent1=ARENA+0x6000;extent2=ARENA+0x6100;out=ARENA+0x7000
 u.mem_write(ctrl+0x20,struct.pack('<QQ',unit,counter));u.mem_write(counter,struct.pack('<I',100));slot=bytearray(0x70);struct.pack_into('<II',slot,0,0x304,100);slot[8]=refs;slot[9]=opens;slot[10]=reserves;slot[11]=4 if alloc else 5;struct.pack_into('<HH',slot,12,state,2);struct.pack_into('<QQ',slot,16,extent1,extent2);u.mem_write(unit,bytes(slot));u.mem_write(tbl,struct.pack('<IIQ',0x304,0,ids)+struct.pack('<IIQ',0xffffffff,0,0));u.mem_write(ids,struct.pack('<III',0x42d,0x430,0xffffffff))
 events=[];stopped=False;returned=[];extcount=0
 def ret(v=0):u.reg_write(UC_ARM64_REG_X0,v&0xffffffffffffffff);u.reg_write(UC_ARM64_REG_PC,u.reg_read(UC_ARM64_REG_LR))
 def hook(_,pc,size,c):
  nonlocal stopped,extcount
  if pc==STOP:stopped=True;u.emu_stop()
  elif pc==T+0xa268:ret(tbl)
  elif pc==T+0x89e8:u.mem_write(u.reg_read(UC_ARM64_REG_X0),struct.pack('<H',0));events.append('slot_allocate_mock');ret()
  elif pc==T+0x8988:events.append('slot_return_mock');ret()
  elif pc==T+0xb5f0:
   ptr=u.reg_read(UC_ARM64_REG_X2);extcount+=1
   if fail_second and extcount==2:events.append('extent_allocate_policy_denial_mock');ret(-0x6501)
   else:u.mem_write(ptr,struct.pack('<Q',extent1 if extcount==1 else extent2));events.append('extent_allocate_mock');ret()
  elif pc==T+0xb768:events.append({'extent_free_mock':hex(u.reg_read(UC_ARM64_REG_X0))});ret()
  elif pc in extern.values():raise RuntimeError('unmodeledexternalcalled')
 u.hook_add(UC_HOOK_CODE,hook)
 def run(off,args):
  nonlocal stopped
  stopped=False;u.reg_write(UC_ARM64_REG_SP,STACK+0x8000);u.reg_write(UC_ARM64_REG_LR,STOP)
  for reg,arg in zip([UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3],args):u.reg_write(reg,arg)
  u.emu_start(T+off,0,count=100000);assert stopped;v=u.reg_read(UC_ARM64_REG_X0)&0xffffffff;v=v-(1<<32) if v&(1<<31) else v;returned.append(v);return v
 if alloc:
  run(0x8b88,[0x304,0,out]);handle=struct.unpack('<I',u.mem_read(out,4))[0]
 else:
  handle=(5<<10)|(0x3ff if badslot else 0)
  if badgen:handle^=1<<10
  if exclusive:
   run(0x91e8,[handle,4,ARENA+0x9000,ARENA+0x9100]);run(0x91e8,[handle,1,ARENA+0x9000,ARENA+0x9100]);run(0x9358,[handle])
  elif opens:run(0x9358,[handle])
  run(0x9460,[handle])
 final=bytes(u.mem_read(unit,0x70));return {'name':name,'synthetic_initial':{'alloc':alloc,'refs':refs,'opens':opens,'reserves':reserves,'state':state,'badgen':badgen,'badslot':badslot},'returns':returned,'handle':hex(handle),'events':events,'final':{'allocation_refs':final[8],'open_refs':final[9],'reserve_refs':final[10],'generation':final[11],'state':struct.unpack_from('<H',final,12)[0]},'hardware':False,'limitation':'Extentpolicy/physicalallocation andslotfree-listboundarymocked; originalunitfunctioninstructionsrun.'}

def policy_case(attr,count):
 u,T,_=image();pool=ARENA;u.mem_write(pool+0x14,bytes([attr]));u.reg_write(UC_ARM64_REG_X6,pool);u.reg_write(UC_ARM64_REG_X5,count);flag={}
 def h(_,pc,size,c):
  if pc in [T+0xb1c0,T+0xadc0]:flag['admitted']=pc==T+0xb1c0;u.emu_stop()
 u.hook_add(UC_HOOK_CODE,h);u.emu_start(T+0xadb4,0,count=20);assert 'admitted'in flag;return {'rule_attribute':attr,'live_counter_synthetic':count,**flag,'scope':'actualADB4..ADBCcomparisononly, notwholeallocator'}

def main():
 cs=[case('new_two_extents',alloc=True),case('partial_extent_denial_rollback',alloc=True,fail_second=True),case('own_unopened_free'),case('wrong_generation',badgen=True),case('invalid_slot',badslot=True),case('shared_allocation_ref',refs=2),case('another_open_ref_remains',opens=2,state=2),case('reserve_reference',reserves=1),case('exclusive_open_close_free',exclusive=True)]
 assert cs[0]['returns']==[0] and cs[0]['handle']=='0x1400'
 assert cs[1]['handle']=='0xffffffff' and any(isinstance(x,dict) for x in cs[1]['events']) and cs[1]['final']['state']==0
 assert cs[2]['returns']==[0] and cs[2]['final']['state']==0
 assert cs[3]['returns']==[-0x205] and not cs[3]['events']
 assert cs[4]['returns']==[-0x105] and not cs[4]['events']
 assert cs[5]['final']['allocation_refs']==1 and not cs[5]['events']
 assert cs[6]['returns']==[0,3] and cs[6]['final']['state']==0
 assert cs[7]['final']['state']==4 and not cs[7]['events']
 assert cs[8]['returns']==[0,-0x3301,0,0]
 ps=[policy_case(1,0),policy_case(1,1),policy_case(0,0),policy_case(2,1)];assert [x['admitted'] for x in ps]==[True,False,False,True]
 out=ROOT/'output/rea-study/normal-dma-lease';out.mkdir(exist_ok=True);(out/'offline-unit-tests.json').write_text(json.dumps({'allocator_execution':False,'device_io':False,'actual_driver_instructions_offline':True,'policy_boundaries_mocked':True,'assertions_passed':True,'unit_cases':cs,'quota_predicate_cases':ps},indent=2)+'\n');print(json.dumps({'unit_cases':len(cs),'quota_cases':len(ps),'assertions_passed':True}))
if __name__=='__main__':main()
