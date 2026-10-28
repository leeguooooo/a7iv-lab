"""Original A64 pcidma lifetime model. No ioctl/device/MMIO is executed.
Synthetic wait returns force timeout; locks/ASPM/init-wait/DMA-start/complete
are explicit mocks. Uses real ioctl, enqueue/start, callback instructions.
"""
from pathlib import Path
import json,hashlib,struct
from elftools.elf.elffile import ELFFile
from unicorn import *
from unicorn.arm64_const import *
R=Path(__file__).resolve().parent;P=R/'local/analysis/normal-kernel-6.02.elf'
K=0xffffff8008080000;SP=0x40008000;STOP=0x40009000;TASK=0x50000000;UDIF=0x50002000;USER=0x50003000
CHANNEL=0xffffff80086aee00+0x378

def model(active=False):
 with P.open('rb')as f:e=ELFFile(f);sg=next(s for s in e.iter_segments()if s['p_type']=='PT_LOAD');raw=sg.data();assert sg['p_vaddr']==K
 assert hashlib.sha256(raw).hexdigest()=='3f30147326233e63b9406f6808122934035b18c7adc55ba1adeb2b8cd1a8e920'
 u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.mem_map(K,0x800000);u.mem_write(K,raw);u.mem_map(0x40000000,0x10000);u.mem_map(TASK,0x10000)
 u.reg_write(UC_ARM64_REG_SP_EL0,TASK);u.mem_write(TASK+8,struct.pack('<Q',0x7fffffffffffffff));u.mem_write(TASK+0x388,struct.pack('<I',123))
 u.mem_write(UDIF,struct.pack('<IIQ',0x40185001,0,USER));u.mem_write(USER,struct.pack('<4BIQQ',0,0,0,0,32,0x30000000,0x4f0000000))
 u.mem_write(CHANNEL+0x14,struct.pack('<II',int(active),1));u.mem_write(CHANNEL+0x20,struct.pack('<QQ',CHANNEL+0x20,CHANNEL+0x20));u.mem_write(CHANNEL+0x30,bytes(8))
 events=[];finished=[False];phase=['ioctl']
 def ret(v=0):u.reg_write(UC_ARM64_REG_X0,v&0xffffffffffffffff);u.reg_write(UC_ARM64_REG_PC,u.reg_read(UC_ARM64_REG_LR))
 def code(uc,pc,size,_):
  if pc==STOP:finished[0]=True;uc.emu_stop();return
  if pc==0xffffff8008270000:
   dst,src,n=[u.reg_read(x)for x in [UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2]];u.mem_write(dst,bytes(u.mem_read(src,n)));events.append(dict(mock='copy_from_user',n=n));ret()
  elif pc==0xffffff80080d7830:
   q=u.reg_read(UC_ARM64_REG_X0);u.mem_write(q,bytes(24));ret()
  elif pc in [0xffffff8008320da0,0xffffff8008323fe8,0xffffff80084a6440,0xffffff80084a66f0]:events.append(dict(mock=hex(pc)));ret()
  elif pc==0xffffff80083227c0:events.append(dict(mock='dma_start_NO_MMIO',channel=hex(u.reg_read(UC_ARM64_REG_X0))));ret()
  elif pc==0xffffff80084a38a8:
   events.append(dict(mock='wait_for_completion_timeout',completion=hex(u.reg_read(UC_ARM64_REG_X0)),jiffies=u.reg_read(UC_ARM64_REG_X1),returned=0));ret()
  elif pc==0xffffff80080d8418:events.append(dict(mock='complete',address=hex(u.reg_read(UC_ARM64_REG_X0)),phase=phase[0]));ret()
 u.hook_add(UC_HOOK_CODE,code)
 u.reg_write(UC_ARM64_REG_SP,SP);u.reg_write(UC_ARM64_REG_LR,STOP);u.reg_write(UC_ARM64_REG_X1,UDIF);u.emu_start(0xffffff8008323818,0,count=100000);assert finished[0]
 fp=SP-0xc0;req=fp+0x80;ctx=fp+0x58
 value=u.reg_read(UC_ARM64_REG_W0);assert value==((-110)&0xffffffff);assert u.reg_read(UC_ARM64_REG_SP)==SP
 queued=struct.unpack('<Q',u.mem_read(CHANNEL+0x20,8))[0];running=struct.unpack('<Q',u.mem_read(CHANNEL+0x30,8))[0]
 assert running==req if active else queued==req+0x28
 cb,cookie=struct.unpack('<QQ',u.mem_read(req+0x18,16));assert cb==0xffffff80083237f8 and cookie==ctx
 before=dict(return_status=-110,returned_SP=hex(SP),expired_frame=[hex(fp),hex(SP)],request=hex(req),cookie=hex(cookie),queue_head_next=hex(queued),active=hex(running),callback=hex(cb),request_in_expired_frame=True,context_in_expired_frame=True)
 # Show late callback's actual write into expired context. This does not
 # emulate IRQ timing or assert real hardware completion; callback arguments
 # come from the preserved real request and all addresses are synthetic.
 u.mem_write(ctx+0x20,struct.pack('<I',0xa5a5a5a5));u.reg_write(UC_ARM64_REG_SP,SP+0x1000);u.reg_write(UC_ARM64_REG_LR,STOP);u.reg_write(UC_ARM64_REG_W0,7);u.reg_write(UC_ARM64_REG_X1,cookie);finished[0]=False;phase[0]='late_callback';u.emu_start(cb,0,count=1000);assert finished[0];after=struct.unpack('<I',u.mem_read(ctx+0x20,4))[0];assert after==7
 return dict(initial_active_enabled=active,timeout_snapshot=before,late_callback=dict(expired_status_before='0xa5a5a5a5',expired_status_after=after,writes_expired_stack=True),events=events,limit='Timeout/late-callback schedule injected, not observed on camera. No hardware/DMA transaction, queue/IRQ timing or full completion implementation emulated.')
def main():
 cases=[model(False),model(True)];out=R/'output/rea-study/pcidma-lifetime';out.mkdir(exist_ok=True);(out/'offline-model.json').write_text(json.dumps(dict(camera_io=False,assertions_passed=True,cases=cases),indent=2)+'\n');print(json.dumps(dict(cases=2,assertions_passed=True,timeout_preserves_expired_stack_references=True,camera_io=False)))
if __name__=='__main__':main()
