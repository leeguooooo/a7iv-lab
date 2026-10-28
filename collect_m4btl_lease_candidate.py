"""Seal offline-only lease candidate and audit actual exports/ELF/ABI.
No module loader or device transport is implemented or called.
"""
from pathlib import Path
import json,hashlib,struct,shutil
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM as UMODE
from unicorn.arm64_const import *
R=Path(__file__).resolve().parent;STAGE=R/'local/build/pcidma-lease-only-01';D=STAGE/'build/lease-only';OUT=R/'output/pcidma-OFFLINE_LEASE_ONLY-01';ALLOWED={'__get_free_pages','arch_va_to_phys','free_pages','scnprintf'}
def sha(b):return hashlib.sha256(b).hexdigest()
def save(p,x):p.write_text(json.dumps(x,indent=2)+'\n')
def main():
 ko=D/'m4btl_lease_01.stripped.ko';full=D/'m4btl_lease_01.ko';data=ko.read_bytes();assert len(data)<=65520
 with ko.open('rb')as f:
  e=ELFFile(f);assert e['e_type']=='ET_REL'and e['e_machine']=='EM_AARCH64'and e.elfclass==64 and e.little_endian
  sy=e.get_section_by_name('.symtab');symbols={s.name:s for s in sy.iter_symbols()if s.name};undefined=sorted(s.name for s in symbols.values()if s['st_shndx']=='SHN_UNDEF');assert set(undefined)==ALLOWED
  assert 'init_module'in symbols and 'cleanup_module'not in symbols and e.get_section_by_name('__versions')is None
  tm=e.get_section_by_name('.gnu.linkonce.this_module');assert tm['sh_size']==768;tb=tm.data();assert tb[24:].split(b'\0')[0]==b'm4btl_lease_01';assert struct.unpack_from('<Q',tb,0x2b8)[0]==0
  assert e.get_section_by_name('__param')['sh_size']==7*40
  required=['.symtab','.strtab','.modinfo','.gnu.linkonce.this_module','__param','.rela.text','.rela.init.text','.rela__param','.rela.gnu.linkonce.this_module'];assert all(e.get_section_by_name(n)is not None for n in required)
  relocs=[]
  for sec in e.iter_sections():
   if isinstance(sec,RelocationSection):
    target=e.get_section(sec['sh_info']);st=e.get_section(sec['sh_link'])
    for r in sec.iter_relocations():
     s=st.get_symbol(r['r_info_sym']);relocs.append(dict(section=target.name,offset=hex(r['r_offset']),type=r['r_info_type'],symbol=s.name,symbol_section=e.get_section(s['st_shndx']).name if isinstance(s['st_shndx'],int)else s['st_shndx'],addend=hex(r['r_addend'])))
  tmrel=[x for x in relocs if x['section']=='.gnu.linkonce.this_module'];assert len(tmrel)==1 and tmrel[0]['offset']=='0x158'and tmrel[0]['symbol']=='init_module'
  ops=symbols['metadata_ops'];
  params=[];pb=e.get_section_by_name('__param').data();prel={int(x['offset'],16):x for x in relocs if x['section']=='__param'};rd=e.get_section_by_name('.rodata').data()
  for off in range(0,len(pb),40):
   nr=prel[off];name=rd[int(nr['addend'],16):].split(b'\0')[0].decode();perm,level,flags=struct.unpack_from('<HbB',pb,off+24);assert perm==0o400 and level==-1 and flags==0;assert prel[off+8]['symbol']=='__this_module';assert prel[off+16]['symbol_section']==e.get_section(ops['st_shndx']).name and int(prel[off+16]['addend'],16)==ops['st_value']
   ar=prel[off+32]; expected_id={'nonce':0,'state':1,'bytes':2,'phys':3,'profile':4,'version':5,'status':6}[name]; assert ar['symbol_section']=='.rodata' and struct.unpack_from('<I',rd,int(ar['addend'],16))[0]==expected_id
   params.append(dict(name=name,selector=expected_id,record_offset=hex(off),permissions=oct(perm),level=level,ops=prel[off+16],arg=ar))
  # metadata_ops offset can move with constant strings; derive from symbol.
  ops=symbols['metadata_ops'];opssec=e.get_section(ops['st_shndx']);opoff=ops['st_value'];oraw=opssec.data()[opoff:opoff+32];assert len(oraw)==32 and struct.unpack_from('<I',oraw)[0]==0 and struct.unpack_from('<Q',oraw,24)[0]==0
  opsrel=[x for x in relocs if x['section']==opssec.name and int(x['offset'],16)in [opoff+8,opoff+16]];assert len(opsrel)==2
  for off,n in [(opoff+8,'reject_set'),(opoff+16,'metadata_get')]:
   rr=next(x for x in opsrel if int(x['offset'],16)==off); ss=symbols[n]; assert rr['symbol_section']==e.get_section(ss['st_shndx']).name and int(rr['addend'],16)==ss['st_value']
  assert not any(x['section']==opssec.name and int(x['offset'],16)==opoff+24 for x in relocs)
  modinfo=e.get_section_by_name('.modinfo').data().decode().replace('\0','\n');code=[];cs=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
  for secname in ['.text','.init.text']:
   sec=e.get_section_by_name(secname);code.append(dict(section=secname,raw_sha256=sha(sec.data()),instructions=[dict(offset=hex(i.address),bytes=i.bytes.hex(),mnemonic=i.mnemonic,operands=i.op_str)for i in cs.disasm(sec.data(),0)]))
 # Reopen both streams for payload comparison (ELFFile sections are lazy).
 with full.open('rb')as f,ko.open('rb')as g:
  a,z=ELFFile(f),ELFFile(g)
  retained={n:dict(bytes=z.get_section_by_name(n)['sh_size'],sha256=sha(z.get_section_by_name(n).data()),byte_identical_to_debug=a.get_section_by_name(n).data()==z.get_section_by_name(n).data())for n in ['.text','.init.text','.rodata','.bss','__param','.modinfo','.gnu.linkonce.this_module']};assert all(x['byte_identical_to_debug']for x in retained.values())
 with (R/'local/analysis/normal-kernel-6.02.elf').open('rb')as f:
  ek=ELFFile(f);ks={s.name:s['st_value']for s in ek.get_section_by_name('.symtab').iter_symbols()};sg=next(s for s in ek.iter_segments()if s['p_type']=='PT_LOAD');raw=sg.data();base=sg['p_vaddr'];exports={}
  for n in undefined:
   a=ks['__ksymtab_'+n];v,st=struct.unpack_from('<QQ',raw,a-base);nm=raw[st-base:].split(b'\0')[0].decode();assert nm==n;exports[n]=dict(normal_export_entry=hex(a),function=hex(v))
  deletion=raw[0xffffff8008112900-base:0xffffff8008112918-base]+raw[0xffffff80081129d8-base:0xffffff80081129e0-base]
  # Actual delete_module branch slice, synthetic module state with init/noexit.
  u=Uc(UC_ARCH_ARM64,UMODE);u.mem_map(base,0x800000);u.mem_write(base,raw);u.mem_map(0x50000000,0x1000);u.mem_write(0x50000158,struct.pack('<Q',1));u.reg_write(UC_ARM64_REG_X20,0x50000000);u.emu_start(0xffffff8008112900,0xffffff80081128e0,count=30);assert u.reg_read(UC_ARM64_REG_X21)==((1<<64)-16)
 audit=dict(camera_io=False,ELF='AArch64 ELF64 little-endian ET_REL',candidate_bytes=len(data),candidate_sha256=sha(data),undefined_symbols=undefined,undefined_all_match_actual_normal_exports=True,exports=exports,zero_DMA_cache_CP_NOR_imports=True,required_sections_preserved=required,retained_payloads=retained,module_struct=dict(bytes=768,name_offset='0x18',name='m4btl_lease_01',init_relocation='0x158->init_module',exit_offset='0x2b8',exit=0,no_cleanup_symbol=True),parameters=params,parameter_ops=dict(bytes=32,set_offset=8,get_offset=16,free_offset=24,free=0,relocations=opsrel),relocations=relocs,modinfo=modinfo,code=code,delete_module_noexit=dict(actual_init_check='FFFFFF8008112908',actual_exit_check='FFFFFF8008112910',noexit_branch='FFFFFF8008112914',return_EBUSY='FFFFFF80081129D8',synthetic_original_instruction_result=-16,raw_sha256=sha(deletion)),no_CRC_forged=True,no_version_check_bypassed=True,modpost_warning='Only missing Module.symvers; explicit actual normal exports allowlist supplies independent symbol audit, not fake symbol versions')
 OUT.mkdir(exist_ok=True);srcout=OUT/'source';srcout.mkdir(exist_ok=True)
 for n in ['m4btl_lease_01.c','identity.h','Makefile']:shutil.copyfile(D/n,srcout/n)
 shutil.copyfile(ko,OUT/'m4btl_lease_01.ko');shutil.copyfile(STAGE/'module-build-final.log',OUT/'build.log');shutil.copyfile(STAGE/'model-link.log',OUT/'model-link.log');shutil.copyfile(D/'model.ld',srcout/'analysis-model.ld');shutil.copyfile(D/'m4btl_lease_01.analysis.elf',OUT/'analysis-model.elf');save(OUT/'elf-audit.json',audit)
 identity=json.loads((STAGE/'identity.json').read_text());nonce=identity['nonce'];assert len(nonce)==32 and all(c in '0123456789abcdef'for c in nonce)and int(nonce,16)!=0
 model=json.loads((OUT/'offline-model.json').read_text());assert model['candidate_sha256']==sha(data)and model['assertions_passed'];status=model['cases'][0]['getters']['status'];assert 'nonce='+nonce+' 'in status
 sourcehashes={str(p.relative_to(OUT)):sha(p.read_bytes())for p in srcout.iterdir()if p.is_file()};files={p.name:dict(bytes=p.stat().st_size,sha256=sha(p.read_bytes()))for p in OUT.iterdir()if p.is_file()and p.name!='manifest.json'}
 manifest=dict(schema='m4btl-offline-lease-only/1',status='OFFLINE_REVIEW_ONLY_NOT_AUTHORIZED_TO_LOAD',module_name='m4btl_lease_01',module_nonce=nonce,nonce_encoding='32 lowercase hexadecimal ASCII characters encoding16 random bytes; compile-time fixed, no load-time input',module_file='m4btl_lease_01.ko',module_bytes=len(data),module_sha256=sha(data),status_path='/sys/module/m4btl_lease_01/parameters/status',status_permissions='0400',status_schema='schema=1 profile=lease-only nonce=<32hex> state=ready page_bytes=4096 page_phys=0x<lowercasehex> resident=boot dma=0\n',synthetic_success_status=status,page=dict(bytes=4096,order=0,physical_min='0x400000000',physical_max='0x4fffff000',alignment=4096,content_exposed=False),allowed_undefined_imports=undefined,source_hashes=sourcehashes,files=files,retained_until='reboot on successful init; no exit/unload routine',init_failure_cleanup='Only address returned by this init allocator; no asynchronous work exists',DMA=0,cache_API_imports=0,CP_NOR_access=0,generic_memory_interface=False,module_loads_performed=0,camera_io=False,modpost_succeeded=True,missing_symvers_warning=True,independent_actual_normal_export_audit=True,model_cases=len(model['cases']),model_assertions_passed=True,host_policy_evidence=dict(path='output/module-policy-01/completion.json',sha256=sha((R/'output/module-policy-01/completion.json').read_bytes()),extension_admitted=False),kernel_ABI_evidence='local/build/pcidma-abi-01/evidence/prepared-headers-and-abi.json',build_image='camera-use-kbuild:ubuntu22-arm64-01',compiler_limit='UbuntuGCC11 selected ABI checked, not identical SonyGCC6.4 build',GPL600_compare_points=['Makefile/.config, generated autoconf and utsrelease','include/linux/module.h moduleparam.h mm.h gfp.h','drivers/udif/mach-cxd900xx/include/mach/noncache.h arch_va_to_phys ABI','kernel/module.c params.c and arm64 relocation loader','Actual kernel exports/raw instructions and existing normal .ko layout; do not infer whole-kernel identity from selected matches'],requires_new_user_scope_before_load=True,run_entry_created=False)
 save(OUT/'manifest.json',manifest);print(json.dumps(dict(bundle=str(OUT.relative_to(R)),module_name=manifest['module_name'],nonce=nonce,bytes=len(data),sha256=sha(data),model_cases=manifest['model_cases'],camera_io=False)))
if __name__=='__main__':main()
