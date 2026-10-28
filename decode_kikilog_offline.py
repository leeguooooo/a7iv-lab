"""Replay the firmware's error-selection reader against a captured log file.

The analysis-linked kernel module has synthetic import stubs. Only file reads,
memory allocation/copy and mutex bookkeeping are modeled; no driver runs on
the host or camera. Linked addresses are NOT runtime camera addresses.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

from elftools.elf.elffile import ELFFile
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn.arm64_const import UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3,UC_ARM64_REG_LR,UC_ARM64_REG_SP,UC_ARM64_REG_PC
from camera_inventory import ROOT,require,save


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--input',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    require(not a.output.exists(),'Use a new evidence path');log=a.input.read_bytes();require(len(log)==0x408000,'Unexpected log extent')
    elfpath=ROOT/'local/analysis/kikilog-linked/kikilog.analysis.elf';u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.mem_map(0x100000,0x500000)
    with elfpath.open('rb') as f:
        e=ELFFile(f);sy=e.get_section_by_name('.symtab');symbols={s.name:s for s in sy.iter_symbols() if s.name}
        for seg in e.iter_segments():
            if seg['p_type']=='PT_LOAD' and seg['p_filesz']:u.mem_write(seg['p_vaddr'],seg.data())
    heap=0x10000000;u.mem_map(heap,0x4000000);control=0x20000000;u.mem_map(control,0x20000)
    stack=control+0x10000;stop=control+0x1f000
    other=heap;u.mem_write(other,log[0x200000:0x204000]);cursor=heap+0x10000
    u.mem_write(symbols['p_other_buf']['st_value'],struct.pack('<Q',other));u.mem_write(symbols['kikilog_filp']['st_value'],struct.pack('<Q',1))
    table=symbols['selected_info_table']['st_value'];count=struct.unpack('<I',bytes(u.mem_read(table,4)))[0]
    require(0<count<=1000,'Implausible compiled selector count');length=4+count*16;dest=control+0x1000
    imports=json.loads((elfpath.parent/'manifest.json').read_text())['synthetic_imports'];byaddr={symbols[x['name']]['st_value']:x['name'] for x in imports if x['kind']=='function'}
    file_reads=[];allocations=[];calls=[];state={'returned':False,'cursor':cursor}
    def ret(value=0):u.reg_write(UC_ARM64_REG_X0,value&((1<<64)-1));u.reg_write(UC_ARM64_REG_PC,u.reg_read(UC_ARM64_REG_LR))
    def hook(_u,addr,size,ctx):
        if addr==stop:state['returned']=True;u.emu_stop();return
        args=[u.reg_read(r) for r in [UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3]]
        if addr==symbols['kikilog_dat_read']['st_value']:
            out,n,off,_=args;require(off+n<=len(log),'Parser read outside captured log');u.mem_write(out,log[off:off+n]);file_reads.append({'offset':off,'bytes':n});ret(0);return
        if addr==symbols['kikilog_dat_write']['st_value']:raise RuntimeError('Error reader attempted to write log storage')
        name=byaddr.get(addr)
        if name is None:return
        calls.append(name)
        if name in ('__kmalloc','kmalloc_order_trace'):
            n=args[0];require(0<n<=0x800000,'Unexpected allocation');pos=(state['cursor']+63)&~63;state['cursor']=pos+n;require(state['cursor']<heap+0x4000000,'Heap budget');allocations.append(n);ret(pos)
        elif name.startswith('kmem_cache_alloc'):
            n=0x300000;pos=(state['cursor']+63)&~63;state['cursor']=pos+n;allocations.append(n);ret(pos)
        elif name in ('memcpy','__memcpy','memmove'):
            out,src,n,_=args;require(n<=0x800000,'Copy budget');u.mem_write(out,bytes(u.mem_read(src,n)));ret(out)
        elif name in ('memset','__memset'):
            out,v,n,_=args;require(n<=0x800000,'Clear budget');u.mem_write(out,bytes([v&255])*n);ret(out)
        elif name in ('kfree','mutex_lock','mutex_unlock','kmalloc_add_trace'):ret(0)
        else:raise RuntimeError('Unmodeled reader import: '+name)
    u.hook_add(UC_HOOK_CODE,hook);u.reg_write(UC_ARM64_REG_SP,stack);u.reg_write(UC_ARM64_REG_LR,stop)
    u.reg_write(UC_ARM64_REG_X0,0x80084a26);u.reg_write(UC_ARM64_REG_X1,0);u.reg_write(UC_ARM64_REG_X2,length);u.reg_write(UC_ARM64_REG_X3,dest)
    u.emu_start(symbols['get_log']['st_value'],0,count=30000000);require(state['returned'],'Instruction budget exceeded')
    returned=u.reg_read(UC_ARM64_REG_X0);require(returned<=length,'Reader returned error or oversized result');raw=bytes(u.mem_read(dest,returned))
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_bytes(raw);a.output.chmod(0o600)
    report={'input_sha256':hashlib.sha256(log).hexdigest(),'analysis_elf_sha256':hashlib.sha256(elfpath.read_bytes()).hexdigest(),'hardware_access':False,'linked_analysis_only':True,'selector_capacity':count,'requested_bytes':length,'returned_bytes':returned,'file_reads':file_reads,'allocation_sizes':allocations,'imports':sorted(set(calls)),'result_file':str(a.output),'result_sha256':hashlib.sha256(raw).hexdigest(),'fields_not_yet_named':True}
    save(a.output.with_suffix('.json'),report);a.output.with_suffix('.json').chmod(0o600)
    print(json.dumps({k:report[k] for k in ['selector_capacity','requested_bytes','returned_bytes','file_reads','imports']},indent=2))


if __name__=='__main__':main()
