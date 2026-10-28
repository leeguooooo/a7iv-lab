"""Pure offline parser/READ dispatch and client poll tests. No device APIs.

The NOR primitive is mocked, not executed. This verifies protocol instructions,
never hardware/NOR safety or that a CP updater context exists on the camera.
"""
from pathlib import Path
import hashlib,json,struct
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_ARM,UC_ARCH_ARM64,UC_HOOK_CODE
from unicorn.arm_const import UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_SP,UC_ARM_REG_LR,UC_ARM_REG_PC
from unicorn.arm64_const import UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3,UC_ARM64_REG_SP,UC_ARM64_REG_LR,UC_ARM64_REG_PC
from elftools.elf.elffile import ELFFile
ROOT=Path(__file__).resolve().parent;OUT=ROOT/'output/rea-study/cp-updater-nor'
CP=(ROOT/'local/analysis/updater-sdk/bodyfs/cp/udtrcp.bin').read_bytes();CLIENT=ROOT/'local/analysis/updater-sdk/bodyfs/bin/ud_cp_firmup.elf'
assert hashlib.sha256(CP).hexdigest()=='2c04cf41c63decc8bc9e4ff0441570aaf25a7c50687051716bfdcae69af0ac25'
assert hashlib.sha256(CLIENT.read_bytes()).hexdigest()=='ea896626a2503f9ab8b90c9506176ffbab7d3b8081a378734d93d7dd410f2c95'

def cp_case(name,address=0,length=32,reqsize=8,capacity=0x200000,reqoff=0x20,resoff=0x1800020,driver_status=0):
 u=Uc(UC_ARCH_ARM,UC_MODE_ARM);u.mem_map(0x108000,0x200000-0x108000);u.mem_write(0x108000,CP)
 for p,s in [(0x30000000,0x1000),(0x31800000,0x201000),(0x40000000,0x3000),(0x41000000,0x10000),(0x42000000,0x1000)]:u.mem_map(p,s)
 shared=bytearray(32);struct.pack_into('<8I',shared,0,3,0,reqsize,reqoff,1,0,capacity,resoff);u.mem_write(0x30000000,bytes(shared));u.mem_write(0x30000020,struct.pack('<II',address,length))
 req,res,sp,stop=0x40000000,0x40001000,0x41008000,0x42000000;events=[];stopped=False
 def ret(v=0):u.reg_write(UC_ARM_REG_R0,v);u.reg_write(UC_ARM_REG_PC,u.reg_read(UC_ARM_REG_LR))
 def hook(_,pc,size,c):
  nonlocal stopped
  if pc==stop:stopped=True;u.emu_stop()
  elif pc in [0x169c40,0x177914]:ret()
  elif pc==0x184ca0:
   dst,src,n=[u.reg_read(r) for r in [UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2]];assert src==address and n==length and n<=0x100000
   events.append({'operation':'mock_nor_read','destination':hex(dst),'offset':src,'length':n,'status':driver_status})
   if not driver_status:u.mem_write(dst,bytes((src+i*13+7)&255 for i in range(n)))
   ret(driver_status)
  elif pc==0x1320e4:events.append({'operation':'cache_maintenance_boundary_mock'});ret()
  elif pc in [0x176b78,0x17658c,0x174cac,0x174f74,0x175538,0x17590c,0x175cbc,0x17606c,0x176204,0x176850]:raise RuntimeError('Mutating or unrelated command handler reached')
 u.hook_add(UC_HOOK_CODE,hook);u.reg_write(UC_ARM_REG_SP,sp);u.reg_write(UC_ARM_REG_LR,stop);u.reg_write(UC_ARM_REG_R0,req);u.reg_write(UC_ARM_REG_R1,res);u.emu_start(0x177278,0,count=20000);assert stopped
 stopped=False;u.reg_write(UC_ARM_REG_LR,stop);u.reg_write(UC_ARM_REG_R0,req);u.reg_write(UC_ARM_REG_R1,res);u.emu_start(0x177344,0,count=50000);assert stopped
 result,nbytes=struct.unpack('<II',u.mem_read(res,8));reads=[e for e in events if e['operation']=='mock_nor_read'];expected=bytes((address+i*13+7)&255 for i in range(length)) if length<=0x100000 else b''
 return {'name':name,'input':{'offset':address,'length':length,'request_size':reqsize,'capacity':capacity,'reqoff':reqoff,'resoff':resoff,'driver_status':driver_status},'result':result,'response_bytes':nbytes,'primitive_calls':len(reads),'events':events,'data_matches':bytes(u.mem_read(0x30000000+resoff,length))==expected if result==0 and length<=0x100000 else None}

def poll_case(name,target=1,states=(1,),ioctl_error=False,budget=30000):
 u=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
 with CLIENT.open('rb') as f:
  e=ELFFile(f)
  # One encompassing ELF map, original segment contents only.
  u.mem_map(0x400000,0x16000)
  for s in e.iter_segments():
   if s['p_type']=='PT_LOAD':u.mem_write(s['p_vaddr'],s.data())
 for p,s in [(0x41000000,0x10000),(0x42000000,0x1000),(0x43000000,0x1000)]:u.mem_map(p,s)
 u.mem_write(0x414118,struct.pack('<Q',0x43000000));u.reg_write(UC_ARM64_REG_SP,0x41008000);u.reg_write(UC_ARM64_REG_LR,0x42000000);u.reg_write(UC_ARM64_REG_X0,target);u.reg_write(UC_ARM64_REG_X1,99)
 reads=0;sleeps=0;stopped=False;ioctls=[]
 def ret(v=0):u.reg_write(UC_ARM64_REG_X0,v&0xffffffffffffffff);u.reg_write(UC_ARM64_REG_PC,u.reg_read(UC_ARM64_REG_LR))
 def hook(_,pc,size,c):
  nonlocal stopped,reads,sleeps
  if pc==0x42000000:stopped=True;u.emu_stop()
  elif pc==0x400ae0:
   cmd=u.reg_read(UC_ARM64_REG_X1);ptr=u.reg_read(UC_ARM64_REG_X2);d=bytes(u.mem_read(ptr,24));src,dst=struct.unpack_from('<QQ',d,8)
   assert cmd==0x40185001 and struct.unpack_from('<I',d,4)[0]==32 and src==0x30000000 and dst==0x410524000
   ioctls.append({'cmd':hex(cmd),'size':32,'source':hex(src),'destination':hex(dst),'dir':d[2]});u.mem_write(0x43000010,struct.pack('<I',states[min(reads,len(states)-1)]));reads+=1;ret(-1 if ioctl_error else 0)
  elif pc==0x400b40:sleeps+=1;assert u.reg_read(UC_ARM64_REG_X0)==20000;ret()
  elif pc==0x400bb0:ret()
 u.hook_add(UC_HOOK_CODE,hook);u.emu_start(0x40261c,0,count=budget)
 return {'name':name,'target_state':target,'states_synthetic':states,'stopped':stopped,'return_if_stopped':u.reg_read(UC_ARM64_REG_X0) if stopped else None,'poll_reads':reads,'mock_20ms_sleeps':sleeps,'instruction_budget':budget,'ioctls':ioctls[:2],'limitation':'All remote state/PCI DMA responses synthetic. Instruction-budget stop is not a real client timeout.'}

def main():
 cases=[cp_case('read32'),cp_case('read1MiB',length=0x100000),cp_case('last_even_pair',address=0x3fffffe,length=2),cp_case('zero',length=0),cp_case('odd_length',length=3),cp_case('odd_offset',address=1),cp_case('offset64MiB',address=0x4000000),cp_case('end_above64MiB',address=0x3fffffe,length=4),cp_case('small_request',reqsize=4),cp_case('small_response',capacity=16),cp_case('zero_request_offset',reqoff=0),cp_case('zero_response_offset',resoff=0),cp_case('driver_param_error',driver_status=3),cp_case('driver_timeout',driver_status=2)]
 for c in cases:
  if c['name'] in ['read32','read1MiB','last_even_pair']:assert c['result']==0 and c['data_matches'] and c['primitive_calls']==1
  elif c['name']=='zero':assert c['result']==0 and c['primitive_calls']==0
  else:assert c['result']!=0
 polls=[poll_case('initial_ready'),poll_case('initial_never_ready',states=(0,)),poll_case('response_after3',target=3,states=(2,2,3)),poll_case('response_never_ready',target=3,states=(2,)),poll_case('dma_error',ioctl_error=True)]
 assert polls[0]['stopped'] and polls[0]['return_if_stopped']==1
 assert polls[1]['stopped'] and polls[1]['return_if_stopped']==0
 assert polls[2]['stopped'] and polls[2]['return_if_stopped']==1
 assert not polls[3]['stopped'] and polls[3]['poll_reads']>12
 assert polls[4]['stopped'] and polls[4]['return_if_stopped']==0
 OUT.mkdir(exist_ok=True);(OUT/'offline-protocol-tests.json').write_text(json.dumps({'camera_io':False,'CP_read_primitive':'mocked, actual184ca0 notexecuted','cache_operations':'mocked','assertions_passed':True,'cp_cases':cases,'client_poll_cases':polls},indent=2)+'\n');print(json.dumps({'CP_cases':len(cases),'client_poll_cases':len(polls),'initial_timeout_reads':polls[1]['poll_reads'],'response_never_polls_before_budget':polls[3]['poll_reads'],'assertions_passed':True}))
if __name__=='__main__':main()
