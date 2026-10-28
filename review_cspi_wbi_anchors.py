from a7m4.firmware import tar_index
from pathlib import Path
import struct,json,hashlib
r=Path(__file__).resolve().parent;p=r/'local/firmware/a7m4-6.02/plaintext.bin';o,s=tar_index(p)['0700_part_image/dev/nflasha5'];cp=(r/'dumps/20261026-032053-probe3/cp_cpapp-b.bin').read_bytes();report={'source':'official 6.02 plaintext','nfa5_offset':o,'nfa5_size':s,'physical_mapping':'only infer from exact CP anchors; none guessed','anchors':[]}
with p.open('rb') as f:f.seek(o);image=f.read(s)
v=struct.unpack('<4sI11Q',image[:96]);metaoff=512+v[7];rows=[struct.unpack_from('<8Q',image,metaoff+i*64) for i in range(v[2])];pos=512;ranges=[]
for i,row in enumerate(rows):
 if row[1]:ranges.append((pos,pos+row[1],row[0],i))
 pos+=(row[1]+511)//512*512
report['wbi']={'version':v[0].decode(),'sections':v[2],'flag':v[3],'sector_size':v[6],'real_data_size':v[7],'original_data_size':v[11],'metadata_offset':metaoff,'sum_rlen':sum(x[1] for x in rows),'sum_olen':sum(x[4] for x in rows),'ranges_phys_min':min(x[0] for x in rows),'ranges_phys_max':max(x[0]+x[4] for x in rows)}
blobs={'wbi_real_data':image[512:metaoff], 'bootB0':(r/'output/backup-01/execution/nflashaB0.bin').read_bytes(),'bootB1':(r/'output/backup-01/execution/nflashaB1.bin').read_bytes(),'CPIMG.DAT':(r/'local/analysis/cspi-coldboot/CPIMG.DAT').read_bytes(),'LOADER~1.BIN':(r/'local/analysis/cspi-coldboot/LOADER~1.BIN').read_bytes()}
for addr in [0x128000,0x4d12e4]:
 for n in [32,64]:
  needle=cp[addr-0x108000:addr-0x108000+n];record={'cp_va':hex(addr),'length':n,'sha256':hashlib.sha256(needle).hexdigest(),'matches':[]}
  for name,b in blobs.items():
   start=0
   while (q:=b.find(needle,start))>=0:
    start=q+1;hit={'source':name,'file_offset':hex(q+(512 if name=='wbi_real_data' else 0))}
    if name=='wbi_real_data':
     absolute=q+512
     for begin,end,phys,idx in ranges:
      if begin<=absolute and absolute+n<=end:hit.update({'section':idx,'physical_address':hex(phys+absolute-begin)})
    record['matches'].append(hit)
  report['anchors'].append(record)
report['limitations']=['GPL 5.00 structures corroborated by 6.02 WBI sums but not exact version source','No known validated CP-to-AP physical mapping','No device read or memory dump beyond original saved/official artifacts']
(r/'output/rea-study/cspi-wbi-anchor-review.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
