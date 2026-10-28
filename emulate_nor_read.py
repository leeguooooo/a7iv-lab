"""Run the real 6.02 Thumb NOR dispatcher with mocked DMA/NOR/log primitives.

This tests packet parsing, branch selection and rejection, not real hardware.
"""
import hashlib
import json
import struct
from pathlib import Path

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC
from camera_inventory import ROOT, require, save

SOURCE_SHA = '7b9b137d696e5972d20db7f9119076172ed8e0730805d7f0b4c31b87689e2c2b'
BASE = 0x108000


def emulate(address=0,length=32,phase=1,driver_error=False,return_packet=False):
    raw=(ROOT/'dumps/20261026-032053-probe3/cp_cpapp-b.bin').read_bytes()
    require(hashlib.sha256(raw).hexdigest()==SOURCE_SHA,'Wrong source CP')
    u=Uc(UC_ARCH_ARM,UC_MODE_THUMB);u.mem_map(BASE,0x1800000-BASE);u.mem_write(BASE,raw)
    packet,stack,stop=0x20000000,0x21000000,0x22000000
    u.mem_map(packet,4096);u.mem_map(stack,0x10000);u.mem_map(stop,4096)
    data=bytearray(0x150);data[0]=phase;struct.pack_into('<HHII',data,0x24,0x60b,1,address,length);u.mem_write(packet,bytes(data))
    u.reg_write(UC_ARM_REG_R0,packet);u.reg_write(UC_ARM_REG_SP,stack+0x8000);u.reg_write(UC_ARM_REG_LR,stop|1)
    events=[];state={'stopped':False}
    def returns(value):
        lr=u.reg_read(UC_ARM_REG_LR);u.reg_write(UC_ARM_REG_R0,value);u.reg_write(UC_ARM_REG_PC,lr)
    def hook(_u,pc,size,ctx):
        if pc==stop:state['stopped']=True;u.emu_stop()
        elif pc==0x56c95c:events.append({'operation':'log'});returns(0)
        elif pc==0x4d11e8:events.append({'operation':'dma_open','channel':u.reg_read(UC_ARM_REG_R0)});returns(0)
        elif pc==0x4d1260:events.append({'operation':'dma_close'});returns(0)
        elif pc==0x4d12e4:
            dest=u.reg_read(UC_ARM_REG_R0);addr=u.reg_read(UC_ARM_REG_R1);n=u.reg_read(UC_ARM_REG_R2)
            require(dest==packet+0x1c and 0<n<=0x130,'Unexpected buffer/allocation path')
            events.append({'operation':'nor_read','address':addr,'length':n})
            if driver_error:returns(7)
            else:
                u.mem_write(dest,bytes((addr+i*13)&255 for i in range(n)));returns(0)
        elif pc==0x4d1748:raise RuntimeError('NOR write branch reached')
        elif pc in (0xacf968,0xacfa14):raise RuntimeError('Unexpected large-buffer allocation/free')
    u.hook_add(UC_HOOK_CODE,hook);u.emu_start(0x4d4bf1,0,count=100000)
    require(state['stopped'],'Dispatcher did not return')
    out=bytes(u.mem_read(packet,0x150));reads=[e for e in events if e['operation']=='nor_read']
    if phase==0x10:require(out[0:2]==b'\x20\x01' and not reads,'Preparation unexpectedly read NOR')
    elif address&0xfff:require(out[0:2]==b'\x00\x82' and not reads,'Unaligned address not rejected')
    elif driver_error:require(out[0:2]==b'\x00\x82' and len(reads)==1,'Driver failure not propagated')
    else:
        expected=bytes((address+i*13)&255 for i in range(length))
        require(out[0:2]==b'\x08\x01' and out[0x1c:0x1c+length]==expected,'Response bytes differ')
        require(struct.unpack_from('<I',out,0x18)[0]==length,'Response length differs')
        require(len(reads)==1 and reads[0]['address']==address and reads[0]['length']==length,'Wrong read primitive arguments')
    result={'address':address,'length':length,'phase':phase,'driver_error':driver_error,'response_prefix':out[:2].hex(),'events':events,'passed':True}
    if return_packet:result['packet_hex']=out.hex()
    return result


def main():
    tests=[emulate(),emulate(0x1000,32),emulate(0,256),emulate(1,32),emulate(0,32,phase=0x10),emulate(driver_error=True)]
    save(ROOT/'output/rea-study/nor-dispatch-emulation.json',{'source_sha256':SOURCE_SHA,'dispatcher':'0x4d4bf0 Thumb','read_primitive':'0x4d12e4','write_primitive_not_executed':'0x4d1748','hardware_access':False,'mocked_primitives':['log','dma_open','dma_close','nor_read'],'all_passed':True,'tests':tests})
    print(json.dumps({'all_passed':True,'cases':len(tests),'hardware_access':False}))


if __name__=='__main__':main()
