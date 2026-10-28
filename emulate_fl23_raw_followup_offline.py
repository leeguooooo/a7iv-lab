"""Offline v7 cave mapping + full matrix consumer evidence. No CP/DAT output.
Real original ARM mapper and real Thumb consumer/helper/tail instructions run
only in synthetic Unicorn RAM. No camera transports or vendor ELF execution.
"""
from pathlib import Path
import struct,json,hashlib
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_ARM,UC_MODE_THUMB,UC_HOOK_CODE
from unicorn.arm_const import *
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM
R=Path(__file__).resolve().parent;BASE=0x108000
V=(R/'output/fl23-offline/CPAPP-B.BIN').read_bytes();S=(R/'dumps/20261026-032053-probe3/cp_cpapp-b.bin').read_bytes()
assert hashlib.sha256(V).hexdigest()=='4551c73386c27a0a9b247fd3e05c3bd5e3425bdb9fe9f8374c201c96533b3479'
RECIPE=json.loads((R/'ref/sony-a7m4-custom-firmware/a7m4/profiles/fl23/cp-raw-lossless-recipe.json').read_text())
ID=[1024,0,0,0,1024,0,0,0,1024];M=[960,17,47,46,1091,-113,-406,-184,1614];G=[2754,7084,6318,3606]

def mappings(raw,flag):
 u=Uc(UC_ARCH_ARM,UC_MODE_ARM);u.mem_map(BASE,0x1500000);u.mem_write(BASE,raw);u.mem_map(0x30000000,0x20000);u.mem_map(0x40000000,0x4000);u.mem_map(0x03e42000,0x1000)
 u.mem_write(0x108f1c,struct.pack('<I',0x30000000));u.mem_write(0x108d98,struct.pack('<I',0x30004000));u.mem_write(0x108d9c,bytes(4));u.mem_write(0x30000000,b''.join(struct.pack('<I',(n<<20)|0xc12)for n in range(4096)))
 sp=0x40002000;u.mem_write(sp+12,struct.pack('<II',0x128000,0x128000));u.mem_write(0x03e42000,bytes([flag]))
 u.reg_write(UC_ARM_REG_SP,sp);u.reg_write(UC_ARM_REG_R0,sp+16);u.reg_write(UC_ARM_REG_LR,0x40003000);u.emu_start(0x1089e4,0x40003000,count=100);assert u.reg_read(UC_ARM_REG_PC)==0x40003000
 for a,z in [(0x1084bc,0x1084d8),(0x1084d8,0x1084f4)]:
  u.reg_write(UC_ARM_REG_R4,0x128000);u.reg_write(UC_ARM_REG_SP,sp);u.emu_start(a,z,count=1000000);assert u.reg_read(UC_ARM_REG_PC)==z
 out=[]
 for va in [0x6b10d2,0xb10f00,0xb11000,0xba4da0,0xba4e74]:
  l1=struct.unpack('<I',u.mem_read(0x30000000+4*(va>>20),4))[0]
  if l1&3==1:
   pte=struct.unpack('<I',u.mem_read((l1&~0x3ff)+4*((va>>12)&255),4))[0];xn=pte&1;typ='4K smallpage';pa=(pte&~0xfff)|(va&0xfff)
  else:pte=l1;xn=(l1>>4)&1;typ='1M section';pa=(pte&~0xfffff)|(va&0xfffff)
  out.append(dict(CP_VA=hex(va),descriptor=hex(pte),descriptor_type=typ,XN=xn,CP_physical=hex(pa)))
 return dict(source_sha256=hashlib.sha256(raw).hexdigest(),synthetic_boot_flag=flag,text_base=hex(struct.unpack('<I',u.mem_read(sp+16,4))[0]),rodata_call_instruction=raw[0x4ec:0x4f0].hex(),translations=out)

def consumer(patched=True,color=19,selector=54,gains=None,root=True,bit3=0,bit11=0,cap=0,aux_bad=False,extra=False,mode9=0,matrix=None,tail_reference=False,actual_image=None):
 u=Uc(UC_ARCH_ARM,UC_MODE_THUMB);u.mem_map(BASE,0x1500000);u.mem_write(BASE,V if actual_image is None else actual_image);u.mem_map(0x30000000,0x4000);u.mem_map(0x40000000,0x4000)
 if patched and actual_image is None:
  for p in RECIPE['patches']:u.mem_write(BASE+p['offset'],bytes.fromhex(p['new_hex']))
 ctx,meta,buf,out=0x30000000,0x30001000,0x30002000,0x30003000;sp=0x40002000;active=sp-0xa8
 u.mem_write(ctx,struct.pack('<II',meta,buf));u.mem_write(meta+0x2e,bytes([color]));u.mem_write(buf+0x25,bytes([selector]));u.mem_write(buf+0x80,struct.pack('<9h',*(matrix or M)));u.mem_write(buf+0x4ec,struct.pack('<4H',*(gains or G)))
 aux=ID.copy()
 if aux_bad:aux[1]=1
 u.mem_write(0x148515e,struct.pack('<9h',*aux));u.mem_write(0x122921b,bytes([bit3]));u.mem_write(0x1229223,bytes([bit11]));u.mem_write(0x1229f18,struct.pack('<H',cap))
 if extra:u.mem_write(meta+0xa2,bytes([1]));u.mem_write(meta+0x90,struct.pack('<9h',2048,0,0,0,2048,0,0,0,2048))
 if mode9:u.mem_write(buf+5,bytes([9]));u.mem_write(0x122a598,struct.pack('<H',mode9))
 for reg,val in [(UC_ARM_REG_R0,out),(UC_ARM_REG_R1,ctx),(UC_ARM_REG_R2,buf+(0x80 if root else 0x82)),(UC_ARM_REG_SP,sp),(UC_ARM_REG_LR,0x40003001)]:u.reg_write(reg,val)
 marks=[];done=[False];count=[0]
 def hook(uc,pc,size,_):
  count[0]+=1
  if pc in [0x6b105e,0xba4da0,0xba4e70,0x6b10d6,0x6b11e4,0x6b11f6,0x6b1214,0x6b1218,0x6b125a]:marks.append(hex(pc))
  if pc==0x40003000 or(tail_reference and pc==0x6b125a):done[0]=True;uc.emu_stop()
 u.hook_add(UC_HOOK_CODE,hook)
 if tail_reference:
  u.mem_write(active+0x60,struct.pack('<9i',*(matrix or M)));u.reg_write(UC_ARM_REG_SP,active);u.reg_write(UC_ARM_REG_R9,ctx);u.reg_write(UC_ARM_REG_R11,out);entry=0x6b11e5
 else:entry=0x6b105f
 u.emu_start(entry,0,count=200000);assert done[0],'consumer model budget/unexpected flow'
 return dict(output9=list(struct.unpack('<9h',u.mem_read(out,18))),marks=marks,instructions=count[0])

def main():
 maps=[dict(kind=k,**mappings(raw,f))for k,raw in [('stock',S),('v7',V)]for f in [0,1]]
 for x in maps:
  cave=next(y for y in x['translations']if y['CP_VA']=='0xba4da0');assert cave['XN']==(1 if x['kind']=='stock'else 0)
 base=[]
 for c,s in [(19,54),(19,56),(20,55),(20,57)]:
  a=consumer(False,color=c,selector=s);b=consumer(True,color=c,selector=s);assert b['output9']==M;base.append(dict(color=c,selector=s,original=a,patched=b))
 options=[dict(root=False),dict(color=0),dict(color=19,selector=55),dict(color=20,selector=54),dict(bit3=16),dict(bit11=2),dict(cap=1),dict(aux_bad=True)]
 for k in range(4):g=G.copy();g[k]=1024;options.append(dict(gains=g))
 fall=[]
 for kw in options:
  a=consumer(False,**kw);b=consumer(True,**kw);assert a['output9']==b['output9']and'0xba4e70'in b['marks'];fall.append(dict(inputs=kw,original=a,patched=b))
 tails=[]
 for kw in [dict(extra=True),dict(mode9=16384),dict(mode9=32768),dict(extra=True,mode9=32768,matrix=[30000,17,47,46,30000,-113,-406,-184,30000])]:
  a=consumer(True,**kw);b=consumer(True,tail_reference=True,**kw);assert a['output9']==b['output9'];tails.append(dict(inputs=kw,full_patched=a,common_tail_reference=b))
 chunks=[];cs=Cs(CS_ARCH_ARM,CS_MODE_ARM)
 for a,z in [(0x1084bc,0x1084f4),(0x108768,0x108974),(0x108324,0x10836c),(0x108728,0x10875c)]:
  d=V[a-BASE:z-BASE];chunks.append(dict(start=hex(a),end_exclusive=hex(z),raw_sha256=hashlib.sha256(d).hexdigest(),instructions=[dict(address=hex(i.address),mnemonic=i.mnemonic,operands=i.op_str,bytes=i.bytes.hex())for i in cs.disasm(d,a)]))
 o=dict(camera_io=False,formal_candidate_written=False,original_v7_sha256=hashlib.sha256(V).hexdigest(),mapping_cases=maps,consumer_cases=base,fallback_full_consumer_cases=fall,common_tail_cases=tails,original_bootstrap_instructions=chunks,DACR_literal_108394=hex(struct.unpack_from('<I',V,0x394)[0]),rodata=dict(start='0xb11000',end_exclusive='0xf31e40',file_offset='0xa09000',cave_file_offset='0xa9cda0',cave_bytes=216,within_file=True),assertions_passed=True,limits=['Original ARM arithmetic generates tables, but Unicorn is not running hardware MMU enforcement. Descriptor XN is decoded per ARMv7 architecture.','Page tables/controller flags are synthetic initial inputs, not current body state. Actual call instructions from each hashed image select permissions.','Thumb consumer frame and calibration are synthetic; no photographed RAW, full SR2 serializer or pixels tested.','Additional-transform/mode9/saturation outputs match isolated original common tail; this is bounded path evidence, not all combinations.'])
 out=R/'output/rea-study/fl23-raw-lossless';(out/'cave-and-consumer.json').write_text(json.dumps(o,indent=2)+'\n');print(json.dumps(dict(mapping_cases=len(maps),consumer_cases=len(base),fallback_cases=len(fall),tail_cases=len(tails),v7_cave_XN=0,stock_cave_XN=1,camera_io=False)))
if __name__=='__main__':main()
