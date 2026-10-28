"""Offline ARM MP_INIT / MP_SET_MODE traces. No host/device target execution.

Real ARM handler/device/config instructions execute in Unicorn. Flash command,
semaphore, waits, DMA init and MMU boundaries are explicitly synthetic.
"""
from pathlib import Path
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_MEM_READ,UC_HOOK_MEM_WRITE
from unicorn.arm_const import *
import struct,json,hashlib
ROOT=Path(__file__).resolve().parent;RAW=(ROOT/'local/analysis/updater-sdk/bodyfs/cp/udtrcp.bin').read_bytes();assert hashlib.sha256(RAW).hexdigest()=='2c04cf41c63decc8bc9e4ff0441570aaf25a7c50687051716bfdcae69af0ac25'
CTRL=0xf1054000;STATE=0x1b6cc0;ARENA=0x30000000;REQ=0x40000000;RES=0x40001000;STACK=0x41008000;STOP=0x42000000

def trace(jedec,target=None,prepare_ddr=False,initial_ddr=0,command_failure=None,budget=2000000,status05=0,config15=0,direct_hw=False):
 u=Uc(UC_ARCH_ARM,UC_MODE_ARM);u.mem_map(0x108000,0x100000);u.mem_write(0x108000,RAW)
 for p,s in [(CTRL,0x1000),(0xf1388000,0x1000),(0xd0000000,0x1000),(ARENA,0x1000),(0x31800000,0x1000),(REQ,0x3000),(0x41000000,0x10000),(STOP,0x1000)]:u.mem_map(p,s)
 u.mem_write(CTRL,struct.pack('<I',0x80000000|(initial_ddr<<24)));u.mem_write(CTRL+0xbc,struct.pack('<I',0x8000))
 events=[];mmio=[];phase='init';stopped=False;insns=0
 def ret(v=0):u.reg_write(UC_ARM_REG_R0,v&0xffffffff);u.reg_write(UC_ARM_REG_PC,u.reg_read(UC_ARM_REG_LR))
 def code(_,pc,size,c):
  nonlocal stopped,insns
  insns+=1
  if pc==STOP:stopped=True;u.emu_stop()
  elif pc in [0x169c40,0x177914,0x15f288,0x15ee2c,0x17ead4,0x185368]:ret()
  elif pc in [0x131cb4,0x131da0,0x17b5d8]:events.append({'phase':phase,'boundary_mock':hex(pc),'arg0':hex(u.reg_read(UC_ARM_REG_R0))});ret()
  elif pc==0x186310:
   p=u.reg_read(UC_ARM_REG_R1);d=bytes(u.mem_read(p,24));n=struct.unpack_from('<I',d,4)[0];op=d[8];rd=d[12];wr=d[13];wlen=d[10];rbuf,wbuf=struct.unpack_from('<II',d,16)
   x={'phase':phase,'command_boundary':'0x186310','caller_return':hex(u.reg_read(UC_ARM_REG_LR)),'opcode':hex(op),'address_present':d[14],'address_bytes':d[9],'address':hex(struct.unpack_from('<I',d)[0]),'read_enable':rd,'read_length':n,'write_enable':wr,'write_length':wlen}
   if wr:
    assert wlen<=8;x['write_data_hex']=bytes(u.mem_read(wbuf,wlen)).hex()
   events.append(x)
   if command_failure==op:ret(2);return
   if rd:
    assert 0<n<=512
    if op==0x9f:data=bytes.fromhex(jedec)
    elif op==0x05:data=bytes([status05])*n
    elif op==0x15:data=bytes([config15])*n
    elif op in [0x35,0x65,0x85,0x70,0x71,0xea,0xfa]:data=bytes(n)
    else:raise RuntimeError(f'unmodeled flash read opcode{op:x}')
    u.mem_write(rbuf,(data+bytes(n))[:n])
   ret()
 def memory(_,access,a,size,value,c):
  if CTRL<=a<CTRL+0x1000 or 0xf1388000<=a<0xf1389000:
   mmio.append({'phase':phase,'kind':'write' if access==17 else'read','address':hex(a),'size':size,'value':hex(value) if access==17 else None,'pc':hex(u.reg_read(UC_ARM_REG_PC))})
  elif 0xd0000000<=a<0xd0001000:
   if access==17:raise RuntimeError('flashaperturewriteforbidden')
   pc=u.reg_read(UC_ARM_REG_PC)
   # Synthetic valid tap-window, never observed hardware calibration data.
   if 0x183f8c<=pc<0x18443c:
    tap=struct.unpack('<I',u.mem_read(CTRL+0xb4,4))[0]&0x7f;val=0 if tap<16 else 0xffffffff
   else:val=0
   u.mem_write(a,struct.pack('<I',val)[:size]);mmio.append({'phase':phase,'kind':'synthetic_aperture_read','address':hex(a),'pc':hex(pc)})
 u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_MEM_READ|UC_HOOK_MEM_WRITE,memory)
 def run(cmd,payload=b''):
  nonlocal stopped
  u.mem_write(ARENA,struct.pack('<8I',cmd,0,len(payload),0x20,1,0,4096,0x1800000));u.mem_write(ARENA+0x20,payload or bytes(4));u.reg_write(UC_ARM_REG_SP,STACK)
  for entry in [0x177278,0x177344]:
   stopped=False;u.reg_write(UC_ARM_REG_LR,STOP);u.reg_write(UC_ARM_REG_R0,REQ);u.reg_write(UC_ARM_REG_R1,RES);u.emu_start(entry,0,count=budget);assert stopped,'instruction budget exhausted'
  return struct.unpack('<II',u.mem_read(RES,8))
 result={};error=None
 try:
  if direct_hw:
   u.reg_write(UC_ARM_REG_SP,STACK);u.reg_write(UC_ARM_REG_LR,STOP);u.reg_write(UC_ARM_REG_R0,0);u.reg_write(UC_ARM_REG_R1,1000);u.emu_start(0x183c90,0,count=budget);assert stopped,'directhw instruction budget exhausted';result['hw_init_return']=u.reg_read(UC_ARM_REG_R0)
  else:result['init']=run(10)
  if target is not None and result.get('init',(1,0))[0]==0:
   if prepare_ddr:phase='prepare_ddr';result['prepare_ddr']=run(9,struct.pack('<I',1))
   phase='target_mode';result['mode']=run(9,struct.pack('<I',target))
 except Exception as ex:error=str(ex)
 return {'direct_hw_only':direct_hw,'status05_synthetic':status05,'config15_synthetic':config15,'last_PC':hex(u.reg_read(UC_ARM_REG_PC)),'jedec_synthetic':jedec,'target_mode':target,'prepare_ddr_first':prepare_ddr,'initial_controller_ddr_synthetic':initial_ddr,'command_failure_synthetic':hex(command_failure) if command_failure else None,'results':result,'error':error,'instructions':insns,'events':events,'mmio':mmio,'final_state':bytes(u.mem_read(STATE,0x38)).hex(),'limit':'All Flash response/status/calibration values synthetic; command186310 mocked; waits/locks/MMU/DMAinit mocked. No realFlash safety or init-success proof.'}

def main():
 cases=[trace(j) for j in ['c2803a','2c5b1a']]
 cases+=[trace(j,m,warm) for j in ['c2803a','2c5b1a'] for warm in [False,True] for m in [0,1,2]]
 cases+=[trace('c2803a',initial_ddr=1),trace('2c5b1a',command_failure=0x9f),trace('c2803a',status05=2,config15=7),trace('000000'),trace('c2803a',command_failure=0x01),trace('2c5b1a',command_failure=0x81),trace('000000',direct_hw=True)]
 assert cases[0]['results']['init']==(0,4) and cases[1]['results']['init']==(0,4)
 assert any(e.get('write_enable') for e in cases[0]['events']) and any(e.get('write_enable') for e in cases[1]['events'])
 for c in cases:
  if c['target_mode'] is not None:assert not c['error'] and c['results']['mode']==(0,0)
 assert cases[-1]['results']['hw_init_return']==0 and not any('opcode'in e for e in cases[-1]['events'])
 out=ROOT/'output/rea-study/cp-updater-init';out.mkdir(exist_ok=True)
 (out/'command-traces.json').write_text(json.dumps({'camera_io':False,'target_execution':False,'CP_SHA256':hashlib.sha256(RAW).hexdigest(),'assertions_passed':True,'cases':cases},indent=2)+'\n')
 summary=[{k:c[k] for k in ['direct_hw_only','status05_synthetic','config15_synthetic','jedec_synthetic','target_mode','prepare_ddr_first','initial_controller_ddr_synthetic','command_failure_synthetic','results','error','last_PC']}|{'commands':[e for e in c['events'] if 'opcode'in e]} for c in cases]
 (out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps({'cases':len(cases),'assertions_passed':True,'init_results':[cases[0]['results'],cases[1]['results']],'initial_DDR_model_error':cases[14]['error'],'hardware_validation':False}))
if __name__=='__main__':main()
