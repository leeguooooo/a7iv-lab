"""Exact SD condition-dispatch CPU models; current-device info retrieval is mocked.

No OS calls, device, file transfer or firmware installation. Region zero is an
ordinary compared value here, not an inferred wildcard.
"""
import hashlib
import io
import json
import os
from pathlib import Path
import struct
import subprocess

from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_INTR
from unicorn.arm64_const import UC_ARM64_REG_SP, UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_LR, UC_ARM64_REG_PC

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'output/rea-study/sd-conditions-exact-01'
NAME = 'usr/lib/libsdfileinputupdaterapi.so'


def run(raw, target, current):
    u = Uc(UC_ARCH_ARM64, UC_MODE_ARM);base = 0x40000000
    elf = ELFFile(io.BytesIO(raw));pages = set()
    for s in elf.iter_segments():
        if s['p_type'] == 'PT_LOAD':
            pages.update(range((base+s['p_vaddr']) & ~4095,
                               (base+s['p_vaddr']+s['p_memsz']+4095) & ~4095,4096))
    for page in sorted(pages):u.mem_map(page,4096)
    for s in elf.iter_segments():
        if s['p_type'] == 'PT_LOAD':u.mem_write(base+s['p_vaddr'],s.data())
    obj, table, info, stack, stop, prepare = 0x81000000,0x81001000,0x81002000,0x82000000,0x90000000,0x90001000
    u.mem_map(obj,0x4000);u.mem_map(stack,0x10000);u.mem_map(stop,0x2000)
    u.mem_write(obj,struct.pack('<Q',table))
    for slot,address in ((0x30,base+0x9fd4),(0x38,base+0xa004),(0x40,base+0xa018),(0x48,prepare)):
        u.mem_write(table+slot,struct.pack('<Q',address))
    # getFirmwareInformation@a054 calls GetCurrentFirmwareInfo into offset0,
    # then getUpdateFirmwareInfo into offset0x18 (confirmed via actual BL/ADD).
    def pack(values):return struct.pack('<6I',1,*values,0)
    u.mem_write(info,pack(current)+pack(target))
    u.reg_write(UC_ARM64_REG_X0,obj);u.reg_write(UC_ARM64_REG_X1,obj+128)
    u.reg_write(UC_ARM64_REG_X2,info);u.reg_write(UC_ARM64_REG_SP,stack+32768)
    u.reg_write(UC_ARM64_REG_LR,stop)
    state={'prepare_calls':0,'version_calls':0,'model_calls':0,'region_calls':0}
    def code(machine,address,size,unused):
        if address == stop:
            state['return']=machine.reg_read(UC_ARM64_REG_X0);machine.emu_stop()
        elif address == prepare:
            state['prepare_calls']+=1
            machine.reg_write(UC_ARM64_REG_X0,0)
            machine.reg_write(UC_ARM64_REG_PC,machine.reg_read(UC_ARM64_REG_LR))
        else:
            field={base+0x9fd4:'version_calls',base+0xa004:'model_calls',base+0xa018:'region_calls'}.get(address)
            if field:state[field]+=1
    def syscall(*args):raise ValueError('No OS/syscall admitted')
    u.hook_add(UC_HOOK_CODE,code);u.hook_add(UC_HOOK_INTR,syscall)
    u.emu_start(base+0xa360,0,count=10000)
    if 'return' not in state:raise ValueError('Condition model did not return')
    return state


def main():
    profile=json.loads((ROOT/'ref/sony-a7m4-custom-firmware/no-fastboot-install/software/app/profiles/profile.json').read_text())
    images={}
    for label,image in (('stock','source.img'),('actual_P1_candidate','candidate.img')):
        raw=subprocess.run(['/opt/homebrew/bin/unsquashfs','-cat',str(ROOT/'output/stock-key-preserving-receiver-01'/image),NAME],check=True,capture_output=True).stdout
        images[label]=raw
    expected=profile['libraries']['libsdfileinputupdaterapi.so']['original_sha256']
    if hashlib.sha256(images['stock']).hexdigest()!=expected:raise ValueError('Stock library changed')
    if hashlib.sha256(images['actual_P1_candidate']).hexdigest()!='f6c68faca339cadff1c1bda5aca9971fb4fcf3af5ac5150ccb6e59f489b65c75':raise ValueError('Actual P1 library changed')
    with (ROOT/'output/fl23-stock-receiver-plain-01/plain.DO_NOT_INSTALL.bin').open('rb') as f:h=f.read(512)
    target=(h[0x21],h[0x20],*struct.unpack_from('<II',h,0x24))
    cases=(('same_version_same_model_region',target,0,1),
           ('higher_current_version_same_model_region',(7,0,target[2],target[3]),0,1),
           ('lower_current_version_same_model_region',(5,0,target[2],target[3]),1,1),
           ('wrong_model',(5,0,target[2]+1,target[3]),0,0),
           ('wrong_region',(5,0,target[2],target[3]+1),0,0))
    tests=[]
    for name,current,stock_expected,patched_expected in cases:
        for label,raw in images.items():
            result=run(raw,target,current)
            expected=stock_expected if label=='stock' else patched_expected
            if result['return']!=expected:raise ValueError(f'Unexpected condition result: {name}/{label}')
            tests.append(dict(case=name,library=label,expected=expected,**result))
    result=dict(all_passed=True,original_A64_dispatch_and_gates_executed=True,tests=tests,
        candidate_header_information=dict(major=target[0],minor=target[1],model_hex=f'{target[2]:08x}',region_hex=f'{target[3]:08x}'),
        modeled_external_operation='vtable+0x48 prepares caller-supplied fixture info; no actual device info retrieval',
        information_pair_layout='current at offset0; update/package at offset0x18; native a054/7040/a080 binding checked',
        region_zero_is_not_a_wildcard_in_checked_function=True,
        live_current_model_and_region_match_proven=False,normal_AP_frontend_acceptance_proven=False,
        whole_installation_acceptance_proven=False,OS_calls=0,camera_operations=0,
        script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    with (OUT/'conditions-cpu-model.json').open('x') as f:
        os.fchmod(f.fileno(),0o600);json.dump(result,f,indent=2);f.write('\n')
    print(json.dumps(result))


if __name__ == '__main__':main()
