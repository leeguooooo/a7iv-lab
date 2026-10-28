"""Offline Thumb proof of RAW rounding and recipe guards. Never writes CP/DAT.
Only isolated Unicorn RAM receives the published 216-byte code body; original
images are hash checked and read-only. No camera libraries or transports used.
"""
from pathlib import Path
import json,hashlib,struct
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_THUMB,UC_HOOK_CODE
from unicorn.arm_const import *
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB
ROOT=Path(__file__).resolve().parent
SRC=ROOT/'output/fl23-offline/CPAPP-B.BIN'
RECIPE=ROOT/'ref/sony-a7m4-custom-firmware/a7m4/profiles/fl23/cp-raw-lossless-recipe.json'
b=SRC.read_bytes();recipe=json.loads(RECIPE.read_text())
assert hashlib.sha256(b).hexdigest()=='4551c73386c27a0a9b247fd3e05c3bd5e3425bdb9fe9f8374c201c96533b3479'
MATRIX=[960,17,47,46,1091,-113,-406,-184,1614]
GAIN=[2754,7084,6318,3606]
BASE=0x108000;CTX=0x30000000;META=0x30001000;BUF=0x30002000;SP=0x40001000

def run(patched=True,color=19,selector=54,gains=None,root=True,bit3=0,bit11=0,cap=0,aux_bad=False,actual_image=None):
 u=Uc(UC_ARCH_ARM,UC_MODE_THUMB);u.mem_map(BASE,0x1500000);u.mem_write(BASE,b if actual_image is None else actual_image);u.mem_map(CTX,0x4000);u.mem_map(0x40000000,0x4000)
 # Published new body only in synthetic emulator RAM. No patched CP output.
 if patched and actual_image is None:u.mem_write(0xba4da0,bytes.fromhex(recipe['patches'][1]['new_hex']))
 u.mem_write(CTX,struct.pack('<II',META,BUF));u.mem_write(META+0x2e,bytes([color]));u.mem_write(BUF+0x25,bytes([selector]));u.mem_write(BUF+0x80,struct.pack('<9h',*MATRIX));u.mem_write(BUF+0x4ec,struct.pack('<4H',*(gains or GAIN)))
 aux=[1024,0,0,0,1024,0,0,0,1024]
 if aux_bad:aux[1]=1
 u.mem_write(SP+0x2a,struct.pack('<9h',*aux));u.mem_write(0x122921b,bytes([bit3]));u.mem_write(0x1229223,bytes([bit11]));u.mem_write(0x1229f18,struct.pack('<H',cap))
 for reg,val in [(UC_ARM_REG_SP,SP),(UC_ARM_REG_R7,SP+0xa0),(UC_ARM_REG_R8,BUF+(0x80 if root else 0x82)),(UC_ARM_REG_R9,CTX)]:u.reg_write(reg,val)
 stop=[];count=[0]
 def hook(uc,pc,size,_):
  count[0]+=1
  if pc==0x6b11e4 or (patched and pc==0x6b10d6):stop.append(pc);uc.emu_stop()
 u.hook_add(UC_HOOK_CODE,hook);u.emu_start((0xba4da0 if patched else 0x6b10d2)|1,0,count=100000)
 assert len(stop)==1,'instruction budget or unexpected flow'
 return dict(patched=patched,color=color,selector=selector,gains=gains or GAIN,root=root,bit3=bit3,bit11=bit11,cap=cap,aux_bad=aux_bad,stop=hex(stop[0]),instructions=count[0],output9=list(struct.unpack('<9i',u.mem_read(SP+0x60,36))))

def main():
 original=run(False);assert original['output9'][-1]==1615 and original['output9']!=MATRIX
 positives=[run(color=c,selector=s,gains=g,cap=cap)for c,s in [(19,54),(19,56),(20,55),(20,57)]for g,cap in [(GAIN,0),([4096]*4,65535)]]
 assert all(x['stop']=='0x6b11e4'and x['output9']==MATRIX for x in positives)
 options=[dict(root=False),dict(color=0),dict(color=19,selector=55),dict(color=20,selector=54),dict(bit3=16),dict(bit11=2),dict(cap=1),dict(aux_bad=True)]
 for k in range(4):g=GAIN.copy();g[k]=1024;options.append(dict(gains=g))
 negatives=[run(**kw)for kw in options];assert all(x['stop']=='0x6b10d6'for x in negatives)
 windows=[];cs=Cs(CS_ARCH_ARM,CS_MODE_THUMB)
 for x in recipe['patches']:
  a=x['offset'];new=bytes.fromhex(x['new_hex']);old=b[a:a+len(new)];assert hashlib.sha256(old).hexdigest()==x['old_sha256']
  windows.append(dict(offset=hex(a),CP_VA=hex(a+BASE),bytes=len(new),old_sha256=hashlib.sha256(old).hexdigest(),old_matches=True,new_hex=new.hex(),instructions=[dict(address=hex(i.address),mnemonic=i.mnemonic,operands=i.op_str,bytes=i.bytes.hex())for i in cs.disasm(new,a+BASE)]))
 stock=(ROOT/'dumps/20261026-032053-probe3/cp_cpapp-b.bin').read_bytes();a,z=0x6b089e-BASE,0x6b1300-BASE;assert b[a:z]==stock[a:z]
 o=dict(camera_io=False,patched_CP_or_DAT_written=False,original_source_sha256=hashlib.sha256(b).hexdigest(),original_source_matches_published_recipe=False,published_recipe_source_sha256=recipe['source_sha256'],published_recipe_target_sha256=recipe['target_sha256'],published_exact_source_bytes_available=False,published_target_bytes_available=False,recipe_sha256=hashlib.sha256(RECIPE.read_bytes()).hexdigest(),windows=windows,stock_equal_WB_code_range=dict(start='0x6b089e',end_exclusive='0x6b1300',sha256=hashlib.sha256(b[a:z]).hexdigest()),synthetic_original=original,synthetic_target_cases=positives,synthetic_fallback_cases=negatives,assertions_passed=True,limits=['Only Thumb block and helper instructions execute in synthetic RAM. InputWB/calibration/frame are not observations from current camera.','Patched guard positives stop before common postprocessing tail; fallback cases stop before original route. Not full RAW/JPEG pipeline proof.','Whole recipe source/target identities differ from v7; local preimage match does not authorize ignoring whole-source check.','No fixed-A1 custom source or deployed upstream target bytes supplied, so their whole hashes remain published claims, not independent reproduction.'])
 out=ROOT/'output/rea-study/fl23-raw-lossless';out.mkdir(exist_ok=True);(out/'review.json').write_text(json.dumps(o,indent=2)+'\n');print(json.dumps(dict(original_output=original['output9'],direct_cases=len(positives),fallback_cases=len(negatives),camera_io=False,patched_artifact_written=False)))
if __name__=='__main__':main()
