"""Exact offline final BSS module -> relocated analysis ELF binding proof."""
from pathlib import Path
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
import re,struct,json,hashlib
R=Path(__file__).resolve().parent;D=R/'local/build/pcidma-bss4-once-01/build/bss4-once';O=R/'output/pcidma-OFFLINE_BSS4_ONCE-01';NAME='m4btl_bss4_01';sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 bases={};pending=None
 for line in (D/(NAME+'.analysis.map')).read_text().splitlines():
  m=re.match(r'^\s+(\S+)\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+'+NAME+r'\.stripped\.ko$',line)
  if m:bases[m[1]]=int(m[2],16);pending=None;continue
  m=re.match(r'^\s+(\S+)\s*$',line)
  if m:pending=m[1];continue
  m=re.match(r'^\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+'+NAME+r'\.stripped\.ko$',line)
  if m and pending:bases[pending]=int(m[1],16);pending=None
 with (D/(NAME+'.stripped.ko')).open('rb')as f,(D/(NAME+'.analysis.elf')).open('rb')as g:
  e,a=ELFFile(f),ELFFile(g);ans={s.name:s['st_value']for s in a.get_section_by_name('.symtab').iter_symbols()};rels={}
  for s in e.iter_sections():
   if isinstance(s,RelocationSection):rels.setdefault(s['sh_info'],[]).extend((x,e.get_section(s['sh_link']).get_symbol(x['r_info_sym']))for x in s.iter_relocations())
  rows=[]
  for idx,s in enumerate(e.iter_sections()):
   if s.name not in ['.text','.init.text','.rodata','.rodata.str1.8','.data','__param','.gnu.linkonce.this_module','.bss','.modinfo']:continue
   start=bases[s.name];expected=bytearray(s.data());count=0
   for rel,sym in rels.get(idx,[]):
    v=ans[sym.name]if sym['st_shndx']=='SHN_UNDEF'else sym['st_value']if sym['st_shndx']=='SHN_ABS'else bases[e.get_section(sym['st_shndx']).name]+sym['st_value'];off=rel['r_offset'];t=rel['r_info_type'];target=v+rel['r_addend'];P=start+off
    if t==257:struct.pack_into('<Q',expected,off,target&0xffffffffffffffff)
    elif t==261:struct.pack_into('<I',expected,off,(target-P)&0xffffffff)
    elif t==283:
     delta=target-P;assert not(delta&3)and -(1<<27)<=delta<(1<<27);word=struct.unpack_from('<I',expected,off)[0];assert word&0xfc000000==0x94000000;struct.pack_into('<I',expected,off,(word&0xfc000000)|((delta>>2)&0x3ffffff))
    else:raise AssertionError(t)
    count+=1
   seg=next(v for v in a.iter_segments()if v['p_type']=='PT_LOAD'and v['p_vaddr']<=start and start+len(expected)<=v['p_vaddr']+v['p_memsz']);raw=seg.data()+bytes(seg['p_memsz']-seg['p_filesz']);assert expected==raw[start-seg['p_vaddr']:start-seg['p_vaddr']+len(expected)],s.name
   rows.append(dict(section=s.name,analysis_base=hex(start),bytes=len(expected),applied_relocations=count,relocated_bytes_equal=True,expected_sha256=hashlib.sha256(expected).hexdigest()))
 O.mkdir(exist_ok=True);x=dict(candidate_sha256=sha(D/(NAME+'.stripped.ko')),analysis_sha256=sha(D/(NAME+'.analysis.elf')),all_retained_runtime_sections_equal_after_exact_relocations=True,sections=rows,camera_io=False);(O/'analysis-binding.json').write_text(json.dumps(x,indent=2)+'\n');print(json.dumps({'sections':len(rows),'relocations':sum(v['applied_relocations']for v in rows),'candidate_sha256':x['candidate_sha256']}))
if __name__=='__main__':main()
