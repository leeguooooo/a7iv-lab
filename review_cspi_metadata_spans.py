"""Offline exact-normal CSPI metadata audit. No device/MMIO/NOR execution."""
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_THUMB
import struct,json,hashlib
R=Path(__file__).resolve().parent;P=R/'dumps/20261026-032053-probe3/cp_cpapp-b.bin';B=P.read_bytes();BASE=0x108000;S=0x11e74d0;T=0x14f99e0
assert hashlib.sha256(B).hexdigest()=='7b9b137d696e5972d20db7f9119076172ed8e0730805d7f0b4c31b87689e2c2b'
# Bounded immediate-pair inventory, retaining aliases and nearby object bases.
pairs=[]
for mode,step in [('thumb',2),('arm',4)]:
 ops=[]
 for p in range(0,len(B)-4,step):
  a,c=struct.unpack_from('<HH',B,p);w=a|(c<<16)
  if mode=='thumb':
   k={0xf240:'w',0xf2c0:'t'}.get(a&0xfbf0)
   if not k or c&0x8000:continue
   imm=((a&15)<<12)|(((a>>10)&1)<<11)|(((c>>12)&7)<<8)|(c&255);reg=(c>>8)&15
  else:
   k={0x03000000:'w',0x03400000:'t'}.get(w&0x0ff00000)
   if not k:continue
   imm=((w>>16)&15)<<12|(w&4095);reg=(w>>12)&15
  ops.append((p,k,reg,imm))
 for n,(p,k,reg,imm)in enumerate(ops):
  if k!='t'or imm not in [0x11e,0x14f]:continue
  prev=[x for x in ops[max(0,n-30):n]if x[0]>=p-100 and x[1]=='w'and x[2]==reg]
  if not prev:continue
  q,_,_,lo=prev[-1];v=(imm<<16)|lo
  if (0x11e7400<=v<0x11e7520)or(0x14f9900<=v<0x14f9a10):pairs.append(dict(mode=mode,movw=hex(q+BASE),movt=hex(p+BASE),register=reg,value=hex(v),in_declared_text=0x128000<=p+BASE<0xb10f08))
literals={}
for value in list(range(S,S+0x3c))+list(range(T,T+0x30)):
 q=struct.pack('<I',value);at=0;hits=[]
 while (at:=B.find(q,at))>=0:hits.append(dict(file_offset=hex(at),image_VA=hex(at+BASE),word_aligned=not(at&3)));at+=1
 if hits:literals[hex(value)]=hits
ranges=[('DMA channel claim',0x4d11e8,0x4d1230,CS_MODE_THUMB),('DMA channel release',0x4d1260,0x4d12b2,CS_MODE_THUMB),('read',0x4d12e4,0x4d14a6,CS_MODE_THUMB),('DMA copy flash-type timeout selection',0x4d1630,0x4d16ec,CS_MODE_THUMB),('write',0x4d1748,0x4d18f8,CS_MODE_THUMB),('sector erase callback',0x4d1954,0x4d1a10,CS_MODE_THUMB),('controller ready helper',0xace516,0xace5da,CS_MODE_THUMB),('DMA channel underlyingclaim/release',0xad636a,0xad63cc,CS_MODE_THUMB),('next independent object',0x4d2284,0x4d22bc,CS_MODE_THUMB),('BSS mapping call',0x10850c,0x108534,CS_MODE_ARM)]
chunks=[]
for name,a,z,mode in ranges:
 raw=B[a-BASE:z-BASE];c=Cs(CS_ARCH_ARM,mode);chunks.append(dict(name=name,start=hex(a),end_exclusive=hex(z),raw_sha256=hashlib.sha256(raw).hexdigest(),instructions=[dict(address=hex(i.address),mnemonic=i.mnemonic,operands=i.op_str,bytes=i.bytes.hex())for i in c.disasm(raw,a)]))
field=[dict(offset='0x4',width=4,type='u32 pointer',address=hex(S+4),meaning='register block pointer used by read/write/ready helper',readers=['4D139E','4D1778','ACE554'],producer='not identified among exact/near immediate users'),dict(offset='0x28',width=4,type='u32',address=hex(S+0x28),meaning='ready-poll loop limit, unit not independently established',readers=['ACE556'],producer='not identified'),dict(offset='0x30',width=1,type='u8',address=hex(S+0x30),meaning='flash-type selector used as wait-timeout branch,0/1 handled',readers=['4D1414','4D1874','4D1674..16B4'],producer='not identified'),dict(offset='0x31',width=1,type='unknown',address=hex(S+0x31),meaning='no direct exact-global meaning established',readers=[],producer='not identified'),dict(offset='0x32',width=1,type='u8 boolean-like',address=hex(S+0x32),meaning='nonzero requests even offset/dst/length; DDR-mode error string supports cache interpretation',readers=['4D1312','4D1784'],producer='not identified'),dict(offset='0x33',width=1,type='u8 boolean-like',address=hex(S+0x33),meaning='nonzero read routine sets/clears controller bit25; NOT observed livehardware bit or init flag',readers=['4D1398','4D1464'],producer='not identified'),dict(offset='0x34',width=1,type='u8 channel',address=hex(S+0x34),meaning='FF CPUcopy; otherwiseDMA channel argument. Wrapper can claim0..7 and release toFF',readers=['4D126E','4D13AA','4D1810','4D1418','4D1878'],writers=['4D1226:provided channel afterAD636A success','4D12A8:FF afterAD6396 success']),dict(offset='table+0x8',width=4,type='function pointer',address=hex(T+8),meaning='sector-erase callback invoked withstate/startsector/count; not a read/init proof',readers=['4D19AC..19B6'],producer='not identified')]
seg=struct.unpack_from('<III',B,0x20000+0x148);bss=0x128000+seg[0];end=bss+seg[1];assert seg[2]==bss and S>=bss+0x418 and T+12<=end
for f in field:assert bss<=int(f['address'],16)and int(f['address'],16)+f['width']<=end
spans=[dict(name='register_pointer',p32=hex(S+4),bytes=4,interpret='raw pointer only, never follow'),dict(name='cached_modes_and_channel',p32=hex(S+0x30),bytes=8,interpret='+30flash_type/+31unknown/+32DDRbool/+33bit25-controlflag/+34channel/+35..37uninterpreted'),dict(name='sector_erase_callback_pointer',p32=hex(T+8),bytes=4,interpret='raw callback slot only, never invoke/follow')]
proofs=['output/rea-study/cp-bss4-source-review/review.json','output/rea-study/ddr4-root-review/bss-prefix-root-model.json']
o=dict(camera_io=False,new_kernel_candidate_built=False,NOR_or_MMIO_executed=False,source=dict(path=str(P.relative_to(R)),bytes=len(B),sha256=hashlib.sha256(B).hexdigest()),BSS=dict(start=hex(bss),end_exclusive=hex(end),bulkclear_start=hex(bss+0x418),bytes=seg[1],state_and_table_in_bulkcleared_BSS=True,interpretation='RAM ownership/layout evidence, not current initialized state or zero snapshot'),fields=field,instruction_chunks=chunks,immediate_scan=dict(method='Fullraw every2B Thumb/every4B ARM MOVW/MOVT nearestsame-reg within100B; bounded inventory not complete dataflow; embedded data can false-positive',matches=pairs),literal_scan=dict(method='Fullraw every-byte exact32bit literal values overstate0..3B andtable0..2F',matches=literals),minimal_naturally_aligned_spans=spans,natural_total_bytes=16,optional_poll_limit=dict(p32=hex(S+0x28),bytes=4),layout_limits=dict(state_minimum_accessed_bytes=0x35,next_independent_base=hex(S+0x38),state_exact_size_not_proven=True,callback_minimum_bytes=12,callback_exact_table_size_not_proven=True,unknown_state_offsets='0..3,8..27,2c..2f,31,35..37'),source_proof_hashes={x:hashlib.sha256((R/x).read_bytes()).hexdigest()for x in proofs},correction='Previous generic-config interpretation ofT+8 was wrong:4D1954 sector range check+linkedsector erase strings identify sector-erase callbackslot',limits=['No explicit initialized/ready softwareflag established. Zero/nonzero fields cannot prove initialized or safeMMIO/NOR.','Direct global fields may be set throughaliases/anotherbootstage; failure tofindproducer is boundednegative, not absenceproof.','No CP lock/generation/sequencecounter snapshot contract identified;3separate spans can tear/changeepochs.','Field+34 changes onnormalDMA claim/release;FF doesnot mean uninitialized and0 is a valid channel value.','Register pointer and cachedmode do not establish actual controller power/protocol/ready bits.','Callback table state is independent of read path, whichdoesnot useT+8.','Current full CP executedimage identity and remote route fornew spans still need separate binding;BSS4 prefixreceipt alone isnot allBSS readback.'])
out=R/'output/rea-study/cspi-fixed-metadata-review-01';out.mkdir(exist_ok=True);(out/'review.json').write_text(json.dumps(o,indent=2)+'\n');print(json.dumps(dict(immediate_matches=len(pairs),literal_values_with_hits=len(literals),natural_spans=3,natural_total_bytes=16,source_sha256=o['source']['sha256'],camera_io=False)))
if __name__=='__main__':pass
