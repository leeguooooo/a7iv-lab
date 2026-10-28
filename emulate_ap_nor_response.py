"""Feed real CP-dispatcher responses into the original AP response decoder.

Only AP logging is mocked here. OSAL delivery, NOR hardware, DMA and runtime
initialization are not executed and remain unverified.
"""
import hashlib
import json
import struct
from pathlib import Path

from elftools.elf.elffile import ELFFile
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn.arm64_const import UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_LR,UC_ARM64_REG_SP,UC_ARM64_REG_PC
from camera_inventory import ROOT,require,save
from emulate_nor_read import emulate

SOURCE_SHA='f58b97548062b8c5ab819f109e7cd64b57b1724e7885ca066358a0dc4849f742'


def decode_ap(cp_packet):
    path=ROOT/'local/firmware/a7m4-6.02/nor-research/libs/libsencore.so'
    raw=path.read_bytes();require(hashlib.sha256(raw).hexdigest()==SOURCE_SHA,'AP source mismatch')
    u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.mem_map(0,0x80000)
    with path.open('rb') as f:
        elf=ELFFile(f)
        for seg in elf.iter_segments():
            if seg['p_type']=='PT_LOAD':u.mem_write(seg['p_vaddr'],seg.data())
        rel=elf.get_section_by_name('.rela.dyn')
        for item in rel.iter_relocations():
            if item['r_info_type']==1027:u.mem_write(item['r_offset'],struct.pack('<Q',item['r_addend']))
    region=0x20000000;u.mem_map(region,0x10000)
    info=region;packet=region+0x1000;outsize=region+0x2000;stack=region+0x8000;stop=region+0xf000
    u.mem_write(packet,cp_packet);u.mem_write(info+0x160,struct.pack('<Q',packet));u.mem_write(info+0x150,struct.pack('<I',0x928a07eb));u.mem_write(info+1,b'\x01')
    u.reg_write(UC_ARM64_REG_X0,info);u.reg_write(UC_ARM64_REG_X1,outsize);u.reg_write(UC_ARM64_REG_SP,stack);u.reg_write(UC_ARM64_REG_LR,stop)
    state={'returned':False,'log_calls':0};allowed_logs={0xaa80,0xa520}
    def hook(_u,address,size,ctx):
        if address==stop:state['returned']=True;u.emu_stop()
        elif address in allowed_logs:
            state['log_calls']+=1;u.reg_write(UC_ARM64_REG_X0,0);u.reg_write(UC_ARM64_REG_PC,u.reg_read(UC_ARM64_REG_LR))
        elif 0x9fe0<=address<0xafa0:
            raise RuntimeError(f'Unexpected AP external helper: {address:#x}')
    u.hook_add(UC_HOOK_CODE,hook);u.emu_start(0xf1b0,0,count=100000)
    require(state['returned'],'AP decoder did not return')
    result=u.reg_read(UC_ARM64_REG_X0)
    # Inline length is retained in the response header; the auxiliary output
    # parameter is not populated by this branch. The real caller also takes
    # its inline length from packet+0x18.
    length=struct.unpack_from('<I',cp_packet,0x18)[0]
    aux=struct.unpack('<I',bytes(u.mem_read(outsize,4)))[0]
    status=bytes(u.mem_read(info+0x169,1))[0];mode=bytes(u.mem_read(info+0x168,1))[0]
    return {'address':result,'expected_inline_address':packet+0x1c,'length':length,'auxiliary_output':aux,'status':status,'mode':mode,
            'data':bytes(u.mem_read(result,length)).hex() if result and length else '', 'log_calls':state['log_calls']}


def main():
    tests=[]
    for length in [32,256]:
        cp=emulate(length=length,return_packet=True);packet=bytes.fromhex(cp['packet_hex']);ap=decode_ap(packet)
        require(ap['address']==ap['expected_inline_address'] and ap['length']==length and ap['status']==1 and ap['mode']==0,'AP inline response rejected')
        require(ap['data']==packet[0x1c:0x1c+length].hex(),'AP response bytes changed')
        tests.append({'case':f'CP original dispatcher to AP original decoder, {length} bytes','passed':True,'ap':ap})
    cp=emulate(driver_error=True,return_packet=True);ap=decode_ap(bytes.fromhex(cp['packet_hex']))
    require(ap['status']==0x82 and ap['address']==0 and ap['mode']==0,'CP failure not propagated by AP')
    tests.append({'case':'CP driver failure','passed':True,'ap':ap})
    report={'all_passed':True,'source_ap_sha256':SOURCE_SHA,'ap_decoder':'0xf1b0','tests':tests,
            'hardware_access':False,'real_dma_or_nor':False,'osal_delivery_verified':False,
            'conclusion':'Expected inline CP responses decode correctly in the original AP code. This does not identify the real USB failure cause.'}
    save(ROOT/'output/rea-study/ap-cp-inline-response-emulation.json',report)
    print(json.dumps(report,indent=2))


if __name__=='__main__':main()
