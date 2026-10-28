"""Offline typed-DMM allocator/config inspection. Never calls an allocator/device."""
from pathlib import Path
from elftools.elf.elffile import ELFFile
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
import json,hashlib,struct
ROOT=Path(__file__).resolve().parent;OUT=ROOT/'output/rea-study/normal-dma-buffer'
paths={'odl':ROOT/'output/runtime-cp-load-20261026/libOnDemandLoader.so','jiritsu':ROOT/'local/firmware/a7m4-6.02/nor-research/libs/libJiritsu.so','getlog':ROOT/'local/firmware/a7m4-6.02/nor-research/libs/libGetLog.so','uipc':OUT/'libosal_uipc.so','dmm':ROOT/'local/analysis/cspi-coldboot/dmm.ko'}
r={'device_io':False,'allocator_execution':False,'mapping_execution':False,'kind':'ordinaryELF/Capstone, notREA','artifacts':{},'functions':{}}
for name,p in paths.items():r['artifacts'][name]={'path':str(p.relative_to(ROOT)),'size':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}
cfg=(OUT/'DmmCfg.bin').read_bytes();assert hashlib.sha256(cfg).hexdigest()=='f1aec54cdb7bb5741408e9636c3c333926983806ba2e339a63c71d40b1cdcfb3';assert cfg==(OUT/'personal-DMMCFG.BIN').read_bytes();off=0

def tables(maxn):
 global off
 vals=[]
 for _ in range(maxn):
  assert off+80<=len(cfg);pos=off;h=cfg[off:off+80];off+=80
  if struct.unpack_from('<I',h,8)[0]==0xffffffff:return vals
  entries=[]
  for _ in range(3073):
   assert off+20<=len(cfg);p=off;words=struct.unpack_from('<5I',cfg,p);off+=20
   if words[2]==0xffffffff:break
   assert words[2]<=0x8ff
   entries.append({'offset':hex(p),'address_low_or_relative':words[0],'alignment_exponent':words[1]&65535,'address_high16':words[1]>>16,'extent_type':words[2],'length':words[3],'attributes_unresolved':hex(words[4])})
  else:raise ValueError('noentryterminator')
  vals.append({'offset':hex(pos),'header_first4words':struct.unpack_from('<4I',h),'entries':entries})
 raise ValueError('notableterminator')
roots=tables(3);pools=tables(1025);units=[]
for _ in range(1025):
 assert off+8<=len(cfg);p=off;uid,flags=struct.unpack_from('<II',cfg,off);off+=8
 if uid==0xffffffff:break
 ids=[]
 for _ in range(3073):
  val=struct.unpack_from('<I',cfg,off)[0];off+=4
  if val==0xffffffff:break
  ids.append(val)
 units.append({'offset':hex(p),'unit_type':uid,'flags_unresolved':flags,'extent_types':ids})
assert len(cfg)-off==44
selected=[]
for u in units:
 if u['unit_type'] in [0x192,0x288,0x304,0x307,0x3c8,0x400,0x630,0x65b]:
  found=[{'pool':p['offset'],'pool_header_words':p['header_first4words'],**e} for p in pools for e in p['entries'] if e['extent_type'] in u['extent_types']];selected.append({**u,'extent_candidates':found})
r['config']={'SHA256':hashlib.sha256(cfg).hexdigest(),'matches_personal_backup_cfg':True,'roots':len(roots),'pools':len(pools),'units':len(units),'version_offset':hex(off),'version_bytes':44,'selected_units':selected,'namespace':'unit_type andextent_typearedifferent; unitmappingisexplicitconfigtable','not_runtime':'Currentloadedrule/availability/ownersnotreadfromkernel'}
range_map={'odl':[(0x7e98,0x7f8c),(0xd1b0,0xd358),(0xd3dc,0xd6f0),(0xa09c,0xa1b0)],'jiritsu':[(0xcdd8,0xd128),(0xcce0,0xcdd8),(0xcb10,0xccac)],'getlog':[(0x51e8,0x53bc)],'uipc':[(0x67b0,0x6870),(0x3e98,0x3f28)],'dmm':[(0x8420,0x8448),(0x8b88,0x8df0),(0xb858,0xb8f0),(0xafa0,0xafd8),(0xb018,0xb034),(0x9ff8,0xa0cc)]}
for name,p in paths.items():
 with p.open('rb') as f:
  e=ELFFile(f);s=e.get_section_by_name('.text');d=s.data();v=s['sh_addr'];annotations={};plt=e.get_section_by_name('.plt');rs=e.get_section_by_name('.rela.plt')
  if plt and rs:
   st=e.get_section(rs['sh_link']);annotations={plt['sh_addr']+32+i*16:st.get_symbol(x['r_info_sym']).name for i,x in enumerate(rs.iter_relocations())}
  kr=e.get_section_by_name('.rela.text');kst=e.get_section(kr['sh_link']) if kr else None;relocs={x['r_offset']:kst.get_symbol(x['r_info_sym']).name for x in kr.iter_relocations()} if kr else {};m=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
  for a,z in range_map[name]:
   rows=[]
   for i in m.disasm(d[a-v:z-v],a):
    x={'address':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}
    if i.address in relocs:x['relocation_symbol']=relocs[i.address]
    elif i.mnemonic=='bl':x['PLT_callee']=annotations.get(int(i.op_str[1:],16),'')
    rows.append(x)
   r['functions'][name+':'+hex(a)]=rows
r['findings']=['NormaltypedDMM NEW+openmessagecmd20 via0061003c returnshandleandphysicalextentlist; cmd23 closes/freesallocatedunit. Notordinarymalloc(size).','ODLallocInterchipBuffer sendsNEW/openforfixedunit400 (8MiB128Balign). OverloadsendOpen(handle)cmd24 isdifferent; donotmistakeno-handlecmd20foropeningexistingglobalbuffer.','Jiritsuwhitelistsunittypes, smallestreviewedconfiguredtype304 has5MiB/4KiBalign. FreshgrantcouldprovideasmallDMA slice,butleaf5MiBbutparentreservationmay105/210MiB pernormal_dma_lease_review andnormalresourcepolicy/queueidentitynotvalidated.','JiritsuPhysToLogi mapsauthoritativeresponsephysicalextent withO_RDWR|O_SYNC, pageoffsettracked; cleanupmunmap/close thenhandlecmd23 andawaitreply. NoPagemap/addressguessing.','KernelAlloc generates slot+generationhandle, bindsallocatedextentbacklinks; thisislogicalallocationownership, notprovedprocess/SIDsecurityACL orautomaticprocessdeathcleanup.','GetLogfixedunit192 grants20MiB; firsthelperparameterisnotprovedtobeabackingsizeconstructor.','UIPCmessageallocatorrejectssize>4096; noauthoritativeexportedDMAphysical/lifetimecontractidentified. NotageneralDMAallocatorreplacement.']
r['unresolved']=['Dedicated4KiB..1MiBunitselectionwithnormalowner/policy','Whether5MiBtemporaryunit304 maybeusedwithoutnormalresource/ruleinterference','Independentreplyqueue/tokenregistrationratherthanborrowingODL/Jiritsu singletonorSID','Runtimeavailabilityandcontiguousextentreturnvalidation','CachealiascoherencyforDMA; O_SYNCintentdoesnotproveallkernelaliases','OutstandingDMAquiescencebeforeunmap/free; nofree-on-timeout assumption','Cleanupacktimeout/processdeathsemantics']
r['decision']='Legitimateallocatorbuildingblocks existandavoidfixedstaging, butnotyetarunnable/safeplan. Noexactsmallgenericallocatororapprovedunit/ownercontextproven. Do notpickunrelatedsmallunitsbyconfigsize,initwholeODL/GetLog,modifyDmmCfg,insertkernelhookorcallallocator.'
OUT.mkdir(exist_ok=True);(OUT/'review.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({'config_roots':len(roots),'pools':len(pools),'units':len(units),'remaining_version_bytes':44,'allocator_execution':False}))
