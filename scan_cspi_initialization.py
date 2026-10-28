import struct,json
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_ARM
r=Path(__file__).resolve().parent;b=(r/'dumps/20261026-032053-probe3/cp_cpapp-b.bin').read_bytes();base=0x108000
out=[]
for mode,step in [('thumb',2),('arm',4)]:
 ops=[]
 for p in range(0,len(b)-4,step):
  a,c=struct.unpack_from('<HH',b,p);word=a|(c<<16)
  if mode=='thumb':
   op={0xf240:'w',0xf2c0:'t'}.get(a&0xfbf0)
   if not op or c&0x8000:continue
   imm=((a&15)<<12)|(((a>>10)&1)<<11)|(((c>>12)&7)<<8)|(c&255);reg=(c>>8)&15
  else:
   op={0x03000000:'w',0x03400000:'t'}.get(word&0x0ff00000)
   if not op:continue
   imm=((word>>16)&15)<<12|(word&4095);reg=(word>>12)&15
  ops.append((p,op,reg,imm))
 for n,(p,op,reg,imm) in enumerate(ops):
  if op=='t' and imm==0x11e:
   prev=[x for x in ops[max(0,n-30):n] if x[0]>=p-100 and x[1]=='w' and x[2]==reg]
   for q,_,_,low in prev[-1:]:
    if 0x7000<=low<=0x7800:out.append({'mode':mode,'movw':hex(q+base),'movt':hex(p+base),'reg':reg,'value':hex((imm<<16)|low)})
print(json.dumps(out,indent=2));(r/'output/rea-study/cspi-all-base-refs.json').write_text(json.dumps(out,indent=2)+'\n')
