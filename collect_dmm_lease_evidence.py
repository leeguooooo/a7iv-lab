"""Offline lease admission evidence. Does not allocate, map or access devices."""
from pathlib import Path
from elftools.elf.elffile import ELFFile
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
import hashlib,json,struct
ROOT=Path(__file__).resolve().parent;OUT=ROOT/'output/rea-study/normal-dma-lease';cfg=(ROOT/'output/rea-study/normal-dma-buffer/DmmCfg.bin').read_bytes();tables=json.loads((ROOT/'output/rea-study/normal-dma-buffer/config-extent-tables.json').read_text());r={'device_io':False,'allocator_execution':False,'mapping':False,'DMA':False,'scope':'normalRAMresources only','config_sha256':hashlib.sha256(cfg).hexdigest(),'policy_chain':[],'functions':{}}
for pool in tables['pools']:
 items=[e for e in pool['entries'] if int(e['words'][2],16) in [0x42d,0x33,0x2f]]
 if not items:continue
 off=int(pool['header_offset'],16);attrs=list(cfg[off+16:off+80]);r['policy_chain'].append({'pool_header':pool['header_offset'],'parent_extent_type':pool['header_words'][2],'pool_counter_id':pool['header_words'][3],'rule_attributes64':attrs,'relevant_extents':items})
paths={'dmm':ROOT/'local/analysis/cspi-coldboot/dmm.ko','getlog':ROOT/'local/firmware/a7m4-6.02/nor-research/libs/libGetLog.so','odl':ROOT/'output/runtime-cp-load-20261026/libOnDemandLoader.so'}
rsmap={'dmm':[(0x5148,0x51fc),(0x5280,0x52d8),(0x5548,0x5688),(0x5df0,0x5e48),(0x8b88,0x8df0),(0x91e8,0x95c0),(0xadb4,0xadf0),(0xb5f0,0xb674),(0xb7a0,0xb850)],'getlog':[(0x51e8,0x53bc)],'odl':[(0xd1b0,0xd2b0),(0xd3dc,0xd440),(0xd510,0xd588),(0xd5e0,0xd6d0)]}
r['artifacts']={}
for name,p in paths.items():
 r['artifacts'][name]={'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'path':str(p.relative_to(ROOT))}
 with p.open('rb') as f:
  e=ELFFile(f);sec=e.get_section_by_name('.text');d=sec.data();v=sec['sh_addr'];m=Cs(CS_ARCH_ARM64,CS_MODE_ARM);plt=e.get_section_by_name('.plt');pr=e.get_section_by_name('.rela.plt');links={}
  if plt and pr:
   st=e.get_section(pr['sh_link']);links={plt['sh_addr']+32+i*16:st.get_symbol(x['r_info_sym']).name for i,x in enumerate(pr.iter_relocations())}
  kr=e.get_section_by_name('.rela.text');st=e.get_section(kr['sh_link']) if kr else None;rels={x['r_offset']:st.get_symbol(x['r_info_sym']).name for x in kr.iter_relocations()} if kr else {}
  for a,z in rsmap[name]:
   rows=[]
   for i in m.disasm(d[a-v:z-v],a):
    x={'address':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}
    if i.address in rels:x['relocation_symbol']=rels[i.address]
    elif i.mnemonic=='bl':x['PLT_callee']=links.get(int(i.op_str[1:],16),'')
    rows.append(x)
   r['functions'][name+':'+hex(a)]=rows
r['answers']={'rule_switch':'ReviewedNEW path usescurrentrule viaAllocExtentB5F0. OnlySetAllocRulecall relocation5E1C isaseparatecommandhandler; no implicitSetAllocRulecallfoundintheNEWchain. Parentreservationcanstillgrow, notclaimofzerootherRAMeffect.','owner_skip':'AB08 existingextent branchADC8..ADE8 skipsnonNULLownerat+38; backendUnitAllocbindsowneronlyafterextentgrant. QuotaADB4..ADBC admitsifcurrentruleattribute>livepoolcounter.','unit304':'leaf42D5MiB4KiBalign; all64leafrulebytes1. Parent33(105MiB) andoptional2F(210MiB), ancestorquota1/2 forall64rules. Notstaticallyfactory-only, butcapacityandactiveparentstateunknown. Logical5MiB isnotwholepoolreservationfootprint.','dynamic_reply':'GetLognormalpatternallocatesdynamicreplyIDusingosal_dynamic_id2A/ownerSID3D, sendscmd20to0061003C, freesIDwith4A. ODLusestokenincrementandmatchesreplytoken@6/cmd8020/status. PatternnotnewdiagnosticSIDregistrationproof.','nonce':'16-bitrequesttoken/echo+dynamicrecipientand15-bithandle(slot+generation)aredifferentroles. No cryptographicownerorperprocessACLproved.','late_reply':'ExistinghelpercanfreereplyIDafterlocaltimeoutwhileallocatorresponseisunknown; no cancellation/automaticlease-reclamation proof. Futuretimeoutcannotdiscardqueue/retry/guesshandle.','close_free':'Cmd23flags2callsClose thenFree. Wronggeneration/slotdenied. Sharedallocrefs>1decrementwithoutphysicalfree; reserve_refs can deferfreeinstate4. Otheropenrefs mayremainafteroneClose; UnitFreemayfreeandreturnpositive3. Cannotassumeanerrorleftresourceunchangedorfreeisaliassafe.','exclusive':'Provider5280 acceptsopenmodes0(noOpen),1(shared),4(exclusive). UnitOpen4requiresnoopen/reserverefs; setsstate3 andrejectsordinarymode1aliases. Exactpacketcomboforexperimentnotlivevalidated.','nonwait':'NEWhandler55EC..5600 checksflagbit4; timeout0takesimmediatefailurepathforresourceunavailability. Removesresourcewait, nottransportlate-response race.'}
r['offline_models']={'file':'offline-unit-tests.json','unit_cases':9,'quota_predicate_cases':4,'status':'assertionspassed','limits':'Allstateandextentpolicyfixtures synthetic. Twoextentfixtureusedonlytorollbacktest, nottheactualunit304singleextentconfig. Private-slot/extent-allocation/free boundariesmocked; noconcurrencyorparentreservationmodel.'}
r['candidate_not_execution_plan']={'allocation_only':'Kernelacceptsmode0(noOpen); formalNEWrequestcouldavoidmapping/DMA. RequiresvalidatedAPIwrapperandresourceidentity, notdeployed.','exclusive_new_open':'Mode4plusnonwaitflagcanpreventordinaryaliasesintheprovider. No actualrequestconstructedorsent.','free':'Onlyfreshreturnedownhandlewithknowncounts; do notfreeforeign/default/guessedhandle orforceanyrule/owner.','current_verdict':'Sourcebuildingblocksexist, butnotadmittedforasmalllivealloc/freeexperimentuntilparentreservationbaseline/quotas,independentreplyidentity,lategrantandclose/freepostconditionsarecovered.'}
r['live_observable_conditions']=['DMMcurrentrule0..63 andstablebaseline','Relevantparent33/2F alreadyactiveorreservationbudgetexplicitlyaccepted','PoolF7countbelow1 andancestorquotas; noforeignownerreclamation','Dedicatedreplyrecipientvalidandretainedthroughterminalack','Freshhandle/generation andknownallocation/open/reservecounts','Post-freehandleinvalidplusparent/quota baseline restored','Noautomaticrulechange,reuse/steal, retryorqueue-discardontimeout']
OUT.mkdir(exist_ok=True);(OUT/'review.json').write_text(json.dumps(r,indent=2)+'\n');print('saved lease evidence')
