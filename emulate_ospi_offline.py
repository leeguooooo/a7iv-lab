"""Offline AArch64 loader traces. Never opens a device. MMIO/data are synthetic.

Actual loader instructions run; timer and generic controller command/config
boundaries are mocked explicitly. This does not validate electrical behaviour,
register meanings, runtime mappings, concurrency, flash contents or recovery.
"""
from pathlib import Path
import json,struct,hashlib
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
from unicorn.arm64_const import *
ROOT=Path(__file__).resolve().parent
BASE=0xfe049000;STATE=BASE+0x169d0;CTRL=0xf1054000;STACK=0x20000000;DEST=0x21000000;STOP=0x22000000
RAW=(ROOT/'local/analysis/cspi-coldboot/boot-source/loader_nor.bin').read_bytes()
assert hashlib.sha256(RAW).hexdigest()=='0f5b3dc210ef7d00749ec52a847e56bd33cf635e706188c6043dbaa7171aa502', 'Wrong original loader'

def trace_init(jedec,start=0xf9fc,boot_flag=0,ddr=0,mock_config=True):
 u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.mem_map(BASE,0x40000);u.mem_write(BASE,RAW)
 for p,s in [(STACK,0x10000),(DEST,0x10000),(STOP,0x1000),(CTRL,0x1000),(0xf1388000,0x1000),(0xd0000000,0x1000)]:u.mem_map(p,s)
 # Both status-bit values below are model assumptions, not hardware observations.
 u.mem_write(CTRL,struct.pack('<I',0x80000000|(ddr<<24)));u.mem_write(CTRL+0xbc,struct.pack('<I',0x8000));u.mem_write(0xf1388f20,struct.pack('<I',boot_flag))
 u.reg_write(UC_ARM64_REG_SP,STACK+0x8000);u.reg_write(UC_ARM64_REG_LR,STOP);u.reg_write(UC_ARM64_REG_X0,1 if start==0xf9fc else 0);u.reg_write(UC_ARM64_REG_X1,1 if start==0xf9fc else 1000);u.reg_write(UC_ARM64_REG_X2,1000)
 events=[];mmio=[];counts={'timer':0};finished=False
 def ret(value=0):u.reg_write(UC_ARM64_REG_X0,value);u.reg_write(UC_ARM64_REG_PC,u.reg_read(UC_ARM64_REG_LR))
 def code(_,pc,size,ctx):
  nonlocal finished
  off=pc-BASE
  if pc==STOP:finished=True;u.emu_stop();return
  if off==0x11bdc:counts['timer']+=1;ret(counts['timer']);return
  if off==0x11bec:ret();return
  if off==0xb530:ret();return
  if off==0x3d84 and mock_config:
   q=u.reg_read(UC_ARM64_REG_X2);op=u.reg_read(UC_ARM64_REG_X1);events.append({'boundary':'controller_config_mock','op':op,'data':bytes(u.mem_read(q,12)).hex()});ret();return
  if off==0x3844:
   q=u.reg_read(UC_ARM64_REG_X1);d=bytes(u.mem_read(q,32));op=d[8];rd=d[12];wr=d[13];n=struct.unpack_from('<I',d,4)[0];nr=d[10];pr,pw=struct.unpack_from('<QQ',d,16)
   evt={'boundary':'flash_command_mock','opcode':hex(op),'address_present':d[14],'address':struct.unpack_from('<I',d)[0],'read_enable':rd,'read_length':n,'write_enable':wr,'write_length':nr}
   if wr:evt['write_data_hex']=bytes(u.mem_read(pw,nr)).hex()
   events.append(evt)
   if rd:
    if not 0<n<=512:raise RuntimeError('unbounded synthetic command read')
    data=bytes.fromhex(jedec) if op==0x9f else bytes(n)
    u.mem_write(pr,(data+bytes(n))[:n])
   if len(events)>2000:raise RuntimeError('event budget exceeded')
   ret();return
 def mem(_,access,addr,size,value,ctx):
  if CTRL<=addr<CTRL+0x1000 or 0xf1388000<=addr<0xf1389000 or 0xd0000000<=addr<0xd0001000:
   mmio.append({'operation':'write' if access==17 else 'read','address':hex(addr),'size':size,'value':hex(value) if access==17 else None,'pc':hex(u.reg_read(UC_ARM64_REG_PC)-BASE)})
 u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_READ|UC_HOOK_MEM_WRITE,mem)
 error=None
 try:u.emu_start(BASE+start,0,count=1000000)
 except Exception as e:error=str(e)
 return {'controller_config_mocked':mock_config,'entry_raw':hex(start),'boot_flag_synthetic':boot_flag,'ddr_synthetic':ddr,'jedec_synthetic':jedec,'finished':finished,'return':u.reg_read(UC_ARM64_REG_X0),'error':error,'events':events,'mmio':mmio,'timer_calls':counts['timer'],'limitations':'Command/config/timer calls are mocked. No controller command MMIO is emitted by mocked boundaries; unmocked loader direct MMIO instructions are traced. Not a hardware safety test.'}



def trace_read(name,length=32,offset=0,ddr=0,control_flag=0,dma=255,ready_after=0,ready_never=False,reg_pointer=CTRL,dest_delta=0):
 """Actual69d8 CPU path; strict finite-register model, no init executed."""
 u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.mem_map(BASE,0x40000);u.mem_write(BASE,RAW)
 for p,s in [(STACK,0x10000),(DEST,0x10000),(STOP,0x1000),(CTRL,0x1000),(0xd0000000,0x1000)]:u.mem_map(p,s)
 expected=bytes((i*13+7)&255 for i in range(4096));u.mem_write(0xd0000000,expected)
 state=bytearray(64);struct.pack_into('<Q',state,8,reg_pointer);struct.pack_into('<I',state,0x30,2);state[0x3a]=ddr;state[0x3b]=control_flag;state[0x3c]=dma;u.mem_write(STATE,bytes(state))
 u.reg_write(UC_ARM64_REG_SP,STACK+0x8000);u.reg_write(UC_ARM64_REG_LR,STOP);u.reg_write(UC_ARM64_REG_X0,DEST+dest_delta);u.reg_write(UC_ARM64_REG_X1,offset);u.reg_write(UC_ARM64_REG_X2,length)
 events=[];ticks=0;reads=0;finished=False;trap=None
 def code(_,pc,size,ctx):
  nonlocal finished,ticks,trap
  if pc==STOP:finished=True;u.emu_stop();return
  if pc==BASE+0x11bdc:
   ticks+=1;u.reg_write(UC_ARM64_REG_X0,ticks);u.reg_write(UC_ARM64_REG_PC,u.reg_read(UC_ARM64_REG_LR));return
  if pc in [BASE+0xc178,BASE+0xc28c,BASE+0xcdd0]:
   trap='DMA_CONFIGURATION_BOUNDARY';events.append({'operation':'trapped_dma_boundary','raw':hex(pc-BASE)});u.emu_stop()
 def memory(_,access,addr,size,value,ctx):
  nonlocal reads
  if CTRL<=addr<CTRL+4096:
   if addr!=CTRL or size!=4:raise RuntimeError(f'unmodelled controller register {addr:x}/{size}')
   if access==16:
    reads+=1;v=struct.unpack('<I',u.mem_read(CTRL,4))[0]&0x7fffffff
    if not ready_never and reads>ready_after:v|=0x80000000
    u.mem_write(CTRL,struct.pack('<I',v))
   events.append({'operation':'mmio_write' if access==17 else 'mmio_read','address':hex(addr),'value':hex(value) if access==17 else None,'raw':hex(u.reg_read(UC_ARM64_REG_PC)-BASE)})
  elif 0xd0000000<=addr<0xd0001000:
   if access==17:raise RuntimeError('FLASH_APERTURE_WRITE_FORBIDDEN')
   events.append({'operation':'synthetic_flash_aperture_read','address':hex(addr),'size':size,'raw':hex(u.reg_read(UC_ARM64_REG_PC)-BASE)})
 u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_READ|UC_HOOK_MEM_WRITE,memory)
 error=None
 try:u.emu_start(BASE+0x69d8,0,count=100000)
 except Exception as ex:error=str(ex)
 result=u.reg_read(UC_ARM64_REG_X0);got=bytes(u.mem_read(DEST+dest_delta,max(0,min(length,4096))))
 return {'name':name,'input':{'length':length,'offset':offset,'ddr':ddr,'control_flag':control_flag,'dma_channel':dma,'ready_after':ready_after,'ready_never':ready_never,'register_pointer':hex(reg_pointer),'destination_delta':dest_delta},'finished':finished,'return':result,'trap':trap,'error':error,'copied_expected_bytes':got==expected[offset:offset+length] if 0<=offset<4096 and length<=4096 else None,'timer_calls':ticks,'final_controller_value':hex(struct.unpack('<I',u.mem_read(CTRL,4))[0]),'events':events,'limitations':'State, readiness and aperture bytes are synthetic. This explicitly assumes preinitialized controller state; it does not show that state exists on the camera.'}


def main():
 out=ROOT/'output/rea-study/ospi-followup';out.mkdir(exist_ok=True)
 init_cases=[trace_init(x) for x in ['c2803a','2c5b1a']]
 controller_cases=[trace_init('000000',start=0x6750,boot_flag=flag,ddr=ddr,mock_config=False) for flag in [0,1] for ddr in [0,1]]
 for c in controller_cases:assert c['finished'] and c['return']==0 and not any(e['boundary']=='flash_command_mock' for e in c['events'])
 real_config_cases=[trace_init(j,mock_config=False) for j in ['c2803a','2c5b1a']]
 for c in real_config_cases:assert any(e['boundary']=='flash_command_mock' and e['write_enable'] for e in c['events'])
 (out/'init-real-config-traces.json').write_text(json.dumps({'hardware_state':'synthetic; timer and flashcommand mocked; original controllerconfig instructions executed','camera_io':False,'cases':real_config_cases},indent=2)+'\n')
 (out/'controller-init-traces.json').write_text(json.dumps({'camera_io':False,'cases':controller_cases},indent=2)+'\n')
 (out/'init-command-traces.json').write_text(json.dumps({'loader_sha256':hashlib.sha256(RAW).hexdigest(),'camera_io':False,'hardware_state':'synthetic only','cases':init_cases},indent=2)+'\n')
 cases=[trace_read('cpu32'),trace_read('cpu1',length=1),trace_read('cpu3',length=3),trace_read('zero',length=0),trace_read('ddr_even',ddr=1),trace_read('ddr_odd_size',length=3,ddr=1),trace_read('ddr_odd_dest',ddr=1,dest_delta=1),trace_read('ddr_odd_source',ddr=1,offset=1),trace_read('control_flag',control_flag=1),trace_read('timeout',ready_never=True),trace_read('timeout_control_flag',ready_never=True,control_flag=1),trace_read('ready_after2',ready_after=2),trace_read('reject_offset',offset=0x4000000),trace_read('dma_trap',dma=0),trace_read('missing_initialization',reg_pointer=0)]
 for c in cases:
  if c['name'] in ['ddr_odd_size','ddr_odd_dest','ddr_odd_source','reject_offset']:assert c['finished'] and c['return']==3 and not c['events']
  elif c['name'].startswith('timeout'):assert c['finished'] and c['return']==2
  elif c['name']=='dma_trap':assert c['trap']=='DMA_CONFIGURATION_BOUNDARY' and not c['finished']
  elif c['name']=='missing_initialization':assert c['error'] and 'READ_UNMAPPED' in c['error']
  else:assert c['finished'] and c['return']==0 and c['copied_expected_bytes']
 assert int(next(x for x in cases if x['name']=='timeout_control_flag')['final_controller_value'],16)&0x2000000
 assert not next(x for x in cases if x['name']=='zero')['events']
 (out/'read-mmio-traces.json').write_text(json.dumps({'loader_sha256':hashlib.sha256(RAW).hexdigest(),'camera_io':False,'model':'strict finite register trace, original69d8 instructions, timer mock only','assertions_passed':True,'cases':cases},indent=2)+'\n')
 print(json.dumps({'init_traces':len(init_cases),'init_returns':[x['return'] for x in init_cases],'read_cases':len(cases),'assertions_passed':True,'hardware_validation':False}))

if __name__=='__main__':main()
