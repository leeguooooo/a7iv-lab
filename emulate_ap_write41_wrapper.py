"""Offline replay of the A7M4 large-WRITE41 AP continuation/wrapper.

The actual AArch64 code executes; DMA, OSAL request/reply, address conversion,
logging and USB response publication are modeled. No device entry point.
"""
import hashlib
import json
import struct
from pathlib import Path
from elftools.elf.elffile import ELFFile
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn.arm64_const import UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3,UC_ARM64_REG_X4,UC_ARM64_REG_X5,UC_ARM64_REG_X6,UC_ARM64_REG_X7,UC_ARM64_REG_SP,UC_ARM64_REG_LR,UC_ARM64_REG_PC

ROOT=Path(__file__).resolve().parent
ELF=ROOT/'local/analysis/m4-persistence/linked/backup.analysis.elf'
EXPECTED='f0e083703a6ff669574dfad39ef4b0495e20a87b93f202d420bdc931ce3b5c3a'


def test(kind,staging=False):
    assert hashlib.sha256(ELF.read_bytes()).hexdigest()==EXPECTED
    u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.mem_map(0x100000,0x500000)
    with ELF.open('rb') as f:
        e=ELFFile(f);sy={s.name:s['st_value'] for s in e.get_section_by_name('.symtab').iter_symbols() if s.name}
        for seg in e.iter_segments():
            if seg['p_type']=='PT_LOAD' and seg['p_filesz']:u.mem_write(seg['p_vaddr'],seg.data())
    u.mem_map(0x20000000,0x100000);packet=0x20000000;payload=0x20001000;stack=0x200e0000;stop=0x200f0000
    size=8192;key=0x02a40001
    state=struct.unpack('<Q',bytes(u.mem_read(0x109b30,8)))[0]
    b=bytearray(0x200);b[0]=4;struct.pack_into('<H',b,0x26,0x41);struct.pack_into('<Q',b,0x18,payload);struct.pack_into('<I',b,0x20,size);struct.pack_into('<I',b,0x2c,1);u.mem_write(packet,bytes(b))
    u.mem_write(state,struct.pack('<I',0 if kind=='wrong_phase' else 4));u.mem_write(state+0x48,struct.pack('<I',key))
    events=[];st={'returned':False}
    def ret(v=0):u.reg_write(UC_ARM64_REG_X0,v&((1<<64)-1));u.reg_write(UC_ARM64_REG_PC,u.reg_read(UC_ARM64_REG_LR))
    def hook(_u,a,n,c):
        if a==stop:st['returned']=True;u.emu_stop();return
        args=[u.reg_read(x) for x in [UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3,UC_ARM64_REG_X4,UC_ARM64_REG_X5,UC_ARM64_REG_X6,UC_ARM64_REG_X7]]
        if a==sy['arch_phys_to_noncache']:ret(args[0]);return
        if a==sy['backup_put_cp_wt_data'] and not staging:
            events.append({'kind':'DMA_staging','bytes':args[1]});ret(-5 if kind=='dma_error' else 0);return
        if a==sy['arch_va_to_phys']:ret(args[0]);return
        if a==sy['pcidma_transfer_async']:
            descriptor=bytes(u.mem_read(args[0],0x28))
            events.append({'kind':'DMA_submit','bytes':struct.unpack_from('<I',descriptor,4)[0],
                           'source':hex(struct.unpack_from('<Q',descriptor,8)[0]),'destination':hex(struct.unpack_from('<Q',descriptor,16)[0])})
            ret(-5 if kind=='staging_dma_error' else 0);return
        if a==sy['osal_wai_sem_tmo']:events.append({'kind':'wait_completion','timeout_argument':args[1]});ret(-110 if kind=='staging_wait_error' else 0);return
        if a==0x1011c0:
            value=-3 if kind=='cp_error' else 0 if kind=='cp_zero' else size-1 if kind=='cp_short_positive' else size
            events.append({'kind':'OSAL_request','message_id':hex(args[1]),'operation':hex(args[2]),'argument_count':args[3],'group':hex(args[4]),'unit':hex(args[5]),'length':args[7],'response':value})
            u.mem_write(args[0],struct.pack('<I',value&0xffffffff));ret();return
        if a in [sy['backup_senser_set_process_end'],sy['backup_senser_set_error']]:
            events.append({'kind':'process_end' if a==sy['backup_senser_set_process_end'] else 'process_error','status':hex(args[1]&0xffffffff)});ret();return
        if a in [sy['backup_senser_free'],sy['backup_logrec']]:ret();return
        if a==sy['memset']:u.mem_write(args[0],bytes([args[1]&255])*args[2]);ret(args[0]);return
    u.hook_add(UC_HOOK_CODE,hook);u.reg_write(UC_ARM64_REG_X0,packet);u.reg_write(UC_ARM64_REG_SP,stack);u.reg_write(UC_ARM64_REG_LR,stop)
    if staging:
        u.reg_write(UC_ARM64_REG_X0,0 if kind=='staging_null' else payload+1 if kind=='staging_unaligned' else payload)
        u.reg_write(UC_ARM64_REG_X1,0 if kind=='staging_zero' else 0xffffffff if kind=='staging_negative' else size)
    u.emu_start(sy['backup_put_cp_wt_data'] if staging else sy['backup_senser_cmd_write'],0,count=10000);assert st['returned']
    code=u.reg_read(UC_ARM64_REG_X0)&0xffffffff
    if staging:
        expected=-7 if kind in ['staging_null','staging_unaligned','staging_zero','staging_negative'] else -5 if kind=='staging_dma_error' else -110 if kind=='staging_wait_error' else 0
        assert code==(expected&0xffffffff),(kind,hex(code),events)
        assert any(x['kind']=='DMA_submit' for x in events)==(expected!=-7)
        return {'scenario':kind,'staging_return_u32':hex(code),'events':events,'passed':True}
    success=kind in ['normal','cp_short_positive','cp_zero']
    assert code==(0 if success else 0xffffffff),(kind,hex(code),events)
    assert any(x['kind']=='process_end' for x in events)==success
    if kind in ['dma_error','wrong_phase']:assert not any(x['kind']=='OSAL_request' for x in events)
    return {'scenario':kind,'handler_return_u32':hex(code),'events':events,'passed':True}


def main():
    rows=[test(k) for k in ['normal','dma_error','cp_error','cp_short_positive','cp_zero','wrong_phase']]
    rows += [test(k,True) for k in ['staging_normal','staging_unaligned','staging_null','staging_zero','staging_negative','staging_dma_error','staging_wait_error']]
    out=ROOT/'output/rea-study/m4-write41-review-01/ap-wrapper-emulation.json'
    out.write_text(json.dumps({'hardware_io':False,'elf_sha256':EXPECTED,'real_code':['large WRITE41 continuation backup_senser_cmd_write','Backup_write_vsize_ic_for_senser','backup_put_cp_wt_data in staging cases'],'mocked':['DMA transport primitives (whole staging helper in continuation cases)','OSAL request/reply','address conversion','logging/free','USB response publication'],'does_not_test':['real DMA data arrival/completeness','CP execution in this model','normal USB mode1-to-mode4 transport transitions'],'all_passed':True,'tests':rows},indent=2)+'\n')
    print(json.dumps({'all_passed':True,'tests':len(rows),'outcomes':[{'scenario':x['scenario'],'return':x.get('handler_return_u32',x.get('staging_return_u32'))} for x in rows]}))


if __name__=='__main__':main()
