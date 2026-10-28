"""Offline CP lock-helper control-flow replay with synthetic RTOS primitives.

No device access. Native ARM code executes, while CP CPU/thread/RTOS context is
modeled. Passing this model is not proof that a live mode3 call is safe.
"""
import hashlib
import json
import struct
from pathlib import Path
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_PC, UC_ARM_REG_LR, UC_ARM_REG_SP, UC_ARM_REG_CPSR

ROOT=Path(__file__).resolve().parent
SOURCE=ROOT/'dumps/20261026-032053-probe3/cp_cpapp-b.bin'
EXPECTED='7b9b137d696e5972d20db7f9119076172ed8e0730805d7f0b4c31b87689e2c2b'


def replay(kind):
    data=SOURCE.read_bytes();assert hashlib.sha256(data).hexdigest()==EXPECTED
    u=Uc(UC_ARCH_ARM,UC_MODE_ARM);u.mem_map(0x100000,0x1700000);u.mem_write(0x108000,data)
    u.mem_map(0x2000000,0x20000);stack=0x2010000;stop=0x201f000
    descriptor=0x1504878;context=0x1700000;thread=0x1234
    u.mem_write(0x1508980,struct.pack('<I',context));u.mem_write(context+0x40,struct.pack('<I',1 if kind=='interrupt_context' else 0))
    u.mem_write(0xd6c8bc,struct.pack('<I',256))
    u.mem_write(descriptor,bytes(0x34));u.mem_write(descriptor+0x20,struct.pack('<II',1,1))
    if kind=='deadlock':u.mem_write(descriptor+0x28,struct.pack('<I',thread))
    calls=[];writes=[];state={'returned':False,'hlt':None}
    def ret(value=0):
        u.reg_write(UC_ARM_REG_R0,value&0xffffffff);u.reg_write(UC_ARM_REG_PC,u.reg_read(UC_ARM_REG_LR))
    def hook(_u,addr,size,ctx):
        if addr==stop:state['returned']=True;u.emu_stop();return
        if addr in [0x55ca0c,0x55cd54]:
            u.reg_write(UC_ARM_REG_R2,0);u.reg_write(UC_ARM_REG_PC,addr+4);return
        if addr in [0x55cab8,0x55cadc,0x55cb14,0x55cb28,0x55cb78,0x55cbd4,0x55cdfc]:
            state['hlt']=hex(addr);u.emu_stop();return
        if addr in [0x552fd0,0x552d08,0x54ac60,0x54ae18,0x54a854,0x5598d4,0x55278c]:
            args=[u.reg_read(r) for r in [UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3]]
            calls.append({'target':hex(addr),'args':args})
            if addr==0x5598d4:u.mem_write(args[0],struct.pack('<I',thread));ret();return
            if addr==0x552fd0:
                ret(-50 if kind=='deadlock' else -1 if kind=='unexpected_rtos_error' else 0);return
            if addr==0x54ac60 and kind=='mutex_error':ret(-7);return
            ret();return
    def mem(_u,access,addr,size,value,ctx):
        if not 0x2000000<=addr<0x2020000:writes.append({'address':hex(addr),'bytes':size,'value':value})
    u.hook_add(UC_HOOK_CODE,hook);u.hook_add(UC_HOOK_MEM_WRITE,mem)
    def call(address,index):
        state['returned']=False;u.reg_write(UC_ARM_REG_CPSR,0x13);u.reg_write(UC_ARM_REG_SP,stack)
        u.reg_write(UC_ARM_REG_LR,stop);u.reg_write(UC_ARM_REG_R0,index)
        u.emu_start(address,0,count=10000)
        assert state['returned'] or state['hlt'],'Instruction bound'
        return u.reg_read(UC_ARM_REG_R0)&0xffffffff
    result=call(0x55c9ec,0 if kind=='invalid_index' else 1)
    count1=struct.unpack('<I',bytes(u.mem_read(descriptor+0x2c,4)))[0]
    if kind=='normal':
        assert result==0 and count1==1
        released=call(0x55cd34,1)
        count2=struct.unpack('<I',bytes(u.mem_read(descriptor+0x2c,4)))[0]
        assert released==0 and count2==0
    else:released=None;count2=None
    expected={'invalid_index':0xffffffef,'interrupt_context':0xffffffe7,'mutex_error':0xfffffff9,'deadlock':0xffffffd7}
    if kind in expected:assert result==expected[kind]
    if kind=='unexpected_rtos_error':assert state['hlt']=='0x55cab8'
    assert all(descriptor<=int(w['address'],16)<descriptor+0x34 for w in writes),'Write escaped synthetic lock descriptor'
    return {'scenario':kind,'return_u32':hex(result),'release_return':released,'reader_count_after_acquire':count1,'reader_count_after_release':count2,'hlt':state['hlt'],'calls':calls,'direct_nonstack_writes':writes,'passed':True}


def main():
    cases=[replay(k) for k in ['normal','invalid_index','interrupt_context','mutex_error','deadlock','unexpected_rtos_error']]
    out=ROOT/'output/rea-study/m4-persistence-followup-01';out.mkdir(mode=0o700,exist_ok=True)
    report={'hardware_io':False,'source_sha256':EXPECTED,'real_code':['ARM0x55c9ec','ARM0x55cd34'],'synthetic':['CP15 CPU id=0','current thread/context','valid-id bound and lock descriptor','all called RTOS primitives'],'all_direct_nonstack_writes_confined_to_synthetic_descriptor':True,'no_storage_operations_in_model':True,'not_proven':'RTOS primitive implementations and real runtime lock contention/scheduling; no live mode3 safety claim','tests':cases,'all_passed':True}
    (out/'cp-lock-emulation.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'all_passed':True,'scenarios':[x['scenario'] for x in cases]}))


if __name__=='__main__':main()
