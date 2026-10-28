"""Offline M4 CP WRITE41 large-record receiver replay, never a device tool.

Uses the original CP dispatcher, record lookup, length/attribute checks, writer,
and notification builder. Models RTOS locks, DMA/cache primitives, memcpy and
OSAL allocation/send. No USB entry point and no output backup image.
"""
import hashlib
import json
import struct
from pathlib import Path
from a7m4.fl23 import bk4_rows
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_PC, UC_ARM_REG_LR, UC_ARM_REG_SP

ROOT=Path(__file__).resolve().parent
CP=ROOT/'dumps/20261026-032053-probe3/cp_cpapp-b.bin'
CP_SHA='7b9b137d696e5972d20db7f9119076172ed8e0730805d7f0b4c31b87689e2c2b'


def test(key,kind):
    image=CP.read_bytes();assert hashlib.sha256(image).hexdigest()==CP_SHA
    preset=(ROOT/'output/existing-fault-data-01/backup_preset.after.bin').read_bytes()
    row=bk4_rows(preset)[1];raw=preset[row['base']:row['base']+row['extent']]
    groups,items,_=struct.unpack_from('<III',raw,0x10)
    group=key>>16;slot=key&65535;count,first=struct.unpack_from('<HI',raw,0x100+group*6)
    record_offset=0x100+groups*6+(first+slot)*6
    attrs,packed=struct.unpack_from('<HI',raw,record_offset)
    assert attrs==8 and packed>>24==255
    record=row['records'][key];n=record['size'];offset=record['offset']-row['base']
    u=Uc(UC_ARCH_ARM,UC_MODE_ARM);u.mem_map(0x100000,0x1700000);u.mem_write(0x108000,image)
    base=0x20000000;source=0x21000000;message=0x22000000;notice=0x22010000;stack=0x23010000;stop=0x2301f000
    for a,size in [(base,0x200000),(source,0x100000),(message,0x20000),(0x23000000,0x20000)]:u.mem_map(a,size)
    u.mem_write(base,raw);u.mem_write(0x146492c,struct.pack('<III',base,base+0x100,base+0x100+groups*6))
    u.mem_write(0x1012f98+(group&255)*4,struct.pack('<I',1))
    if kind=='protected':
        u.mem_write(base+record_offset,struct.pack('<H',attrs|1));u.mem_write(base+0x28,struct.pack('<I',1))
    initial=bytes(u.mem_read(base,len(raw)))
    length=0 if kind=='native_zero_size' else n-1 if kind=='short' else n+1 if kind=='long' else n
    payload=bytes((i*17+11)&255 for i in range(length));u.mem_write(source,payload)
    packet=bytearray(0x1000);struct.pack_into('<I',packet,0,0x32)
    struct.pack_into('<H',packet,0x20,group+1 if kind=='wrong_group' else group)
    struct.pack_into('<I',packet,0x28,(key&0xffff0000)|0xffff if kind=='missing_id' else key)
    struct.pack_into('<H',packet,0x2c,length);u.mem_write(message,bytes(packet))
    events=[];state={'returned':False}
    def ret(value=0):
        u.reg_write(UC_ARM_REG_R0,value&0xffffffff);u.reg_write(UC_ARM_REG_PC,u.reg_read(UC_ARM_REG_LR))
    def hook(_u,address,size,ctx):
        if address==stop:state['returned']=True;u.emu_stop();return
        args=[u.reg_read(r) for r in [UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3]]
        if address in [0x55cbf8,0x55cd34]:
            events.append({'kind':'lock_primitive','target':hex(address),'id':args[0]});ret(-7 if kind=='lock_error' and address==0x55cbf8 else 0);return
        if address==0x566544:events.append({'kind':'DMA_staging_lookup','requested':hex(args[0])});ret(source);return
        if address in [0x56def0,0x56ded8]:ret();return
        if address==0x5866ac:u.mem_write(args[0],bytes(args[1]));ret(args[0]);return
        if address==0x585fb8:
            dest,src,size,_=args;assert 0<=size<=0x100000
            u.mem_write(dest,bytes(u.mem_read(src,size)));events.append({'kind':'copy','destination':hex(dest),'bytes':size});ret(dest);return
        if address==0xac9a36:events.append({'kind':'log','code':args[0]});ret();return
        if address==0x4cc3ac:
            events.append({'kind':'notification_allocate','message_id':hex(args[0]),'bytes':args[2]})
            if kind=='notify_alloc_error':ret(-1);return
            u.mem_write(args[1],struct.pack('<I',notice));ret();return
        if address==0xacc4d2:ret();return
        if address==0x4cbce0:
            fields=struct.unpack('<III',bytes(u.mem_read(args[1],12)))
            events.append({'kind':'notification_send','message_id':hex(args[0]),'unit':hex(fields[0]),'length':fields[1],'embedded_data_flag':fields[2]});ret(-1 if kind=='notify_send_error' else 0);return
        if address==0x4cc4a8:events.append({'kind':'notification_free'});ret();return
    u.hook_add(UC_HOOK_CODE,hook);u.reg_write(UC_ARM_REG_SP,stack);u.reg_write(UC_ARM_REG_LR,stop);u.reg_write(UC_ARM_REG_R0,message)
    u.emu_start(0x4c516d,0,count=50000);assert state['returned'],'Instruction bound'
    result=struct.unpack('<I',bytes(u.mem_read(message+4,4)))[0]
    after=bytes(u.mem_read(base,len(raw)));changed=[i for i,(a,b) in enumerate(zip(initial,after)) if a!=b]
    success=kind in ['same','notify_alloc_error','notify_send_error','lock_error','native_zero_size']
    if success:
        assert result==n and after[offset:offset+n]==(bytes(n) if kind=='native_zero_size' else payload)
        assert all(offset<=i<offset+n for i in changed),'Write touched other record or metadata'
    else:
        assert result&0x80000000 and not changed
    return {'unit':f'{key:08x}','scenario':kind,'fixed_extended_record_tag':255,'original_attributes':attrs,'original_length':n,'supplied_length':length,'cp_result_u32':hex(result),'record_modified':bool(changed),'changed_bytes':len(changed),'other_record_and_metadata_unchanged':True,'events':events,'passed':True}


def main():
    cases=[test(k,s) for k in [0x02a40001,0x02a4000d] for s in ['same','short','long','wrong_group','missing_id','protected','notify_alloc_error','notify_send_error','lock_error','native_zero_size']]
    out=ROOT/'output/rea-study/m4-write41-review-01'
    report={'hardware_io':False,'cp_sha256':CP_SHA,'real_code':['CP interchip op32 dispatcher0x4c516c','write_vsize4c31d0','BK4 record lookup/accessors','notification builderaca19a'],'mocked':['RTOS writer lock/release','DMA staging pointer/cache operations','memcpy/memset','OSAL notification allocate/send/free','logging'],'not_proven':['live OSAL/DMA transport','notification consumer side effects/completion','actual lock acquisition','actual memcpy atomicity','power interruption or saved flash persistence'],'all_passed':True,'tests':cases}
    (out/'cp-op32-emulation.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'all_passed':True,'tests':len(cases),'rows':[{'unit':x['unit'],'case':x['scenario'],'result':x['cp_result_u32'],'changed':x['record_modified']} for x in cases]}))


if __name__=='__main__':main()
