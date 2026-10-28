"""Offline CP Backup notification routing, exact-match and fanout replay.

Original CP send/dispatch/filter/listener code runs against saved record data.
All queue tables, object registrations, RTOS primitives, allocators and memcpy
are explicit host models; no camera, IPC socket or storage writes exist.
"""
import hashlib
import json
import struct
from pathlib import Path
from a7m4.fl23 import bk4_rows
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_ARM,UC_HOOK_CODE
from unicorn.arm_const import UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3,UC_ARM_REG_PC,UC_ARM_REG_LR,UC_ARM_REG_SP

ROOT=Path(__file__).resolve().parent
CP=ROOT/'dumps/20261026-032053-probe3/cp_cpapp-b.bin'
EXPECTED='7b9b137d696e5972d20db7f9119076172ed8e0730805d7f0b4c31b87689e2c2b'


class Model:
    def __init__(self,fail=None):
        b=CP.read_bytes();assert hashlib.sha256(b).hexdigest()==EXPECTED
        u=self.u=Uc(UC_ARCH_ARM,UC_MODE_ARM);u.mem_map(0x100000,0x1700000);u.mem_write(0x108000,b)
        u.mem_map(0x20000000,0x3000000);self.stack=0x22e00000;self.stop=0x22f00000
        raw=(ROOT/'output/color-snapshots-01/preset-memory-before.bin').read_bytes();row=bk4_rows(raw)[1]
        self.bank=0x20000000;self.raw=raw[row['base']:row['base']+row['extent']];u.mem_write(self.bank,self.raw)
        groups=struct.unpack_from('<I',self.raw,0x10)[0]
        u.mem_write(0x146492c,struct.pack('<III',self.bank,self.bank+0x100,self.bank+0x100+groups*6))
        self.record={k:{**v,'relative':v['offset']-row['base']} for k,v in row['records'].items()}
        u.mem_write(0x1012f98+0xa4*4,struct.pack('<I',1))
        self.events=[];self.heap=0x21000000;self.returned=False;self.fail=fail
        self.queue=0x1700000;self.proxy=0x1700800;self.proxy_fn=0x22008000
        u.mem_write(self.proxy,struct.pack('<I',self.proxy_fn|1));u.mem_write(0x1464a40,struct.pack('<I',self.proxy))
        self.registration=[];u.hook_add(UC_HOOK_CODE,self.hook)

    def ret(self,v=0):self.u.reg_write(UC_ARM_REG_R0,v&0xffffffff);self.u.reg_write(UC_ARM_REG_PC,self.u.reg_read(UC_ARM_REG_LR))

    def hook(self,_u,a,size,c):
        u=self.u;v=[u.reg_read(r) for r in [UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3]]
        if a==self.stop:self.returned=True;u.emu_stop();return
        if a==self.proxy_fn:self.events.append({'kind':'cross_chip_proxy','id':hex(v[0])});self.ret();return
        if a==0xacbe48:self.events.append({'kind':'local_queue_lookup','id':hex(v[0])});self.ret(self.queue);return
        if a in [0xacbc8a,0xacbce6,0x55c9ec,0x55cd34]:self.ret();return
        if a==0x55a02c:self.ret(0);return
        if a==0x5598d4:u.mem_write(v[0],struct.pack('<I',0x1234));self.ret();return
        if a==0x585fb8:
            assert 0<=v[2]<=0x100000;u.mem_write(v[0],bytes(u.mem_read(v[1],v[2])));self.events.append({'kind':'memcpy','destination':hex(v[0]),'bytes':v[2]});self.ret(v[0]);return
        if a==0xac9cb2:
            self.events.append({'kind':'allocate_current_data','bytes':v[0]})
            if self.fail=='allocation':self.ret(0);return
            p=self.heap;self.heap+=0x10000;self.ret(p);return
        if a==0x4c4eb0:self.events.append({'kind':'free_current_data'});self.ret();return
        if a==0x4cc4a8:
            self.events.append({'kind':'free_message'})
            p=v[1]-0x18+0xa;n=struct.unpack('<H',bytes(u.mem_read(p,2)))[0]
            if n:u.mem_write(p,struct.pack('<H',n-1))
            self.ret();return
        if a==0x4cb7f4:self.events.append({'kind':'free_queue_block'});self.ret();return
        if a==0xaca246:
            key,fn,arg=struct.unpack('<III',bytes(u.mem_read(v[1],12)))
            self.registration.append({'unit':hex(key),'function':hex(fn),'userdata':hex(arg)});u.mem_write(v[0],struct.pack('<I',1));self.ret();return
        if a==0xac94ca:self.ret(0);return
        if a in [0xa32386,0x56d5e8]:raise RuntimeError('Unexpected firmware error/log path')

    def call(self,entry,*args):
        u=self.u;self.returned=False;u.reg_write(UC_ARM_REG_SP,self.stack);u.reg_write(UC_ARM_REG_LR,self.stop)
        for r,v in zip([UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3],args):u.reg_write(r,v)
        u.emu_start(entry|1,0,count=100000);assert self.returned,'Instruction bound'
        return u.reg_read(UC_ARM_REG_R0)&0xffffffff

    def message(self,key,embedded=False):
        p=0x22000018;n=self.record.get(key,{'size':32})['size'];b=bytearray(0x10000)
        struct.pack_into('<III',b,0,key,n,1 if embedded else 0)
        if embedded:b[12:12+n]=bytes([0x5a])*n
        self.u.mem_write(p-0x18,bytes(0x18));self.u.mem_write(p,bytes(b));self.u.mem_write(p-0x18+0xa,struct.pack('<H',1));return p,n

    def context(self,key,dest=0x122a418):
        p=0x22020000;self.u.mem_write(p,struct.pack('<IIIII',p,0,key,0x69da47,dest));return p


def main():
    results=[]
    # Real declaration loop, no registration API execution.
    r=Model();assert r.call(0x222a8c)==0;assert len(r.registration)==19
    assert [x['unit'] for x in r.registration]==[hex(0x2a40000+i) for i in range(19)]
    assert all(x['function']=='0x69da47' for x in r.registration)
    results.append({'case':'19_colour_listener_declarations','registrations':r.registration,'passed':True})
    for msgid,local in [(0x003e414e,True),(0x903e414e,True),(0x803e414e,False)]:
        r=Model();r.u.mem_write(r.queue,struct.pack('<I',3));r.u.mem_write(r.queue+0x1c,struct.pack('<I',1));p,_=r.message(0x2a40001)
        assert r.call(0x4cbce0,msgid,p)==0
        assert any(x['kind']=='local_queue_lookup' for x in r.events)==local
        assert any(x['kind']=='cross_chip_proxy' for x in r.events)==(not local)
        results.append({'case':'route','message_id':hex(msgid),'local':local,'events':r.events,'passed':True})
    for case,key,registered,embedded,fail in [('match_large',0x2a40001,0x2a40001,False,None),('wrong_id',0x2a40001,0x2a4000d,False,None),('group_base_is_not_wildcard',0x2a40001,0x2a40000,False,None),('small_embedded',0x2a40003,0x2a40003,True,None),('allocation_failure',0x2a40001,0x2a40001,False,'allocation')]:
        r=Model(fail);dest=0x122a418 if key!=0x2a40003 else 0x14853ee;p,n=r.message(key,embedded);ctx=r.context(registered,dest);before=bytes(r.u.mem_read(dest,n));r.call(0xaca2ba,p,ctx);after=bytes(r.u.mem_read(dest,n))
        expected=embedded or (key==registered and fail is None)
        assert any(x['kind']=='memcpy' and x['destination']==hex(dest) for x in r.events)==expected
        if expected:
            payload=bytes([0x5a])*n if embedded else r.raw[r.record[key]['relative']:r.record[key]['relative']+n]
            assert after==payload
        else:assert before==after
        results.append({'case':case,'events':r.events,'listener_called':expected,'passed':True})
    # Original shared-queue fanout + wrapper + exact Backup callback.
    r=Model();p,n=r.message(0x2a40001);q=r.queue;r.u.mem_write(q,bytes(0x40));r.u.mem_write(q,bytes([1]));r.u.mem_write(q+2,struct.pack('<H',1));r.u.mem_write(q+8,struct.pack('<II',p-0x18,p-0x18));r.u.mem_write(q+0x1c,struct.pack('<I',1))
    nodebase=0x22100000;destinations=[0x122a418,0x122c918,0x1248000]
    for i,key in enumerate([0x2a40001,0x2a4000d,0x2a40001]):
        node=nodebase+i*0x100;ctx=node+0x40;r.u.mem_write(ctx,struct.pack('<IIIII',ctx,0,key,0x69da47,destinations[i]));r.u.mem_write(node,bytes(0x20));r.u.mem_write(node,struct.pack('<I',node+0x100 if i<2 else 0));r.u.mem_write(node+8,struct.pack('<I',0xacc0e3));r.u.mem_write(node+0x14,struct.pack('<II',0xaca2bb,ctx))
    r.u.mem_write(q+4,struct.pack('<I',nodebase));r.call(0xacc140,q)
    writes=[x['destination'] for x in r.events if x['kind']=='memcpy']
    assert hex(destinations[0]) in writes and hex(destinations[2]) in writes and hex(destinations[1]) not in writes
    results.append({'case':'shared_fanout_two_matching_one_nonmatching','events':r.events,'matching_listeners':2,'nonmatching_invocations':0,'passed':True})
    out=ROOT/'output/rea-study/m4-notify-route-review-01'
    report={'hardware_io':False,'source_sha256':EXPECTED,'real_functions':['CP send4cbce0','colour listener declaration222a8c','CP shared fanoutacc140 and wrapperacc0e2','Backup callbackaca2ba','colour callback69da46 and ARM memcpy thunk521f78','CP BK4 read lookup'],'mocked':['queue registry/current runtime state','RTOS primitives','allocator/free','memcpy leaf','cross-chip proxy','registration API and initial bulk read'],'does_not_prove':['actual runtime registered listener list','all other/dynamic listener behavior','hardware cross-chip transport','all consumers lack persistent effects'],'all_passed':True,'tests':results}
    (out/'notification-emulation.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'all_passed':True,'tests':len(results),'cases':[x['case'] for x in results]}))


if __name__=='__main__':main()
