"""Pure local artifact inspection. Does not execute ELF, map memory or open devices."""
from pathlib import Path
from elftools.elf.elffile import ELFFile
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
import hashlib,json,struct
ROOT=Path(__file__).resolve().parent;OUT=ROOT/'output/rea-study/cp-ram-transport';r={'camera_io':False,'target_execution':False,'mapping_execution':False,'kind':'ordinaryELF/Capstone, notREA','artifacts':{},'assembly':{}}
paths={'client':ROOT/'local/analysis/updater-sdk/bodyfs/bin/ud_cp_firmup.elf','kernel':ROOT/'local/analysis/normal-kernel-6.02.elf','backup_original':ROOT/'local/analysis/m4-persistence/backup.ko','backup_analysis':ROOT/'local/analysis/m4-persistence/linked/backup.analysis.elf'}
for name,p in paths.items():r['artifacts'][name]={'path':str(p.relative_to(ROOT)),'size':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}
assert r['artifacts']['client']['sha256']=='ea896626a2503f9ab8b90c9506176ffbab7d3b8081a378734d93d7dd410f2c95'
assert r['artifacts']['backup_original']['sha256']=='697da39f1c39266651f62dd0f7804d683311f507902e75d593628a13395afea8'

def capture(name,ranges):
 with paths[name].open('rb') as f:
  e=ELFFile(f);symbols=[]
  for sec in e.iter_sections():
   if sec['sh_type'] in ['SHT_SYMTAB','SHT_DYNSYM']:symbols.extend(sec.iter_symbols())
  names={s['st_value']:s.name for s in symbols if s.name};m=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
  for a,z in ranges:
   seg=next(s for s in e.iter_segments() if s['p_type']=='PT_LOAD' and s['p_vaddr']<=a<s['p_vaddr']+s['p_filesz']);d=seg.data()[a-seg['p_vaddr']:z-seg['p_vaddr']];rows=[]
   for i in m.disasm(d,a):
    row={'address':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}
    if i.mnemonic=='bl':row['symbol']=names.get(int(i.op_str[1:],16),'unknown')
    rows.append(row)
   r['assembly'][name+':'+hex(a)]=rows
capture('client',[(0x400c14,0x400c58),(0x400e14,0x400e24),(0x400e44,0x400ec4),(0x4017bc,0x40188c)])
capture('kernel',[(0xffffff8008323818,0xffffff8008323968),(0xffffff80083237f8,0xffffff8008323818),(0xffffff8008322a08,0xffffff8008322b70)])
capture('backup_analysis',[(0x107030,0x10718c)])
with paths['kernel'].open('rb') as f:
 e=ELFFile(f);seg=next(x for x in e.iter_segments() if x['p_type']=='PT_LOAD');data=seg.data();addr=0xffffff80086aedc0
 r['UDIF_CDEV_OPS']={n:hex(struct.unpack_from('<Q',data,addr-seg['p_vaddr']+i*8)[0]) for i,n in enumerate(['open','close','ioctl','read','write','lseek','mmap','poll'])}
r['client_t']={'CLI':'-t path setsinternalcmd13→4017bc','source':'-a strtolresultstored32bit; movw0,w0 zeroextendto64; nodomainconversion, no +4G','size':'-s lower32bits, no clientboundsagainst26MiB/no even ornonzero constraintinthisbranch','destination':'APphysical410524000','staging_mapping':'26MiB readwrite mmap physical410524000 usedbeforebranch, cacheduserpointer414108','transfer':'pcie0, dmac0,dir0/read,size32@4,src64@8,dst64@10,ioctl40185001','handshake':'NoMPWAIT/RESPONSE, noMPcommandword, noNORinit/mode/registerDMA inthisbranch','output':'fopen(-t path,wb),fwrite(staging,size,1),fclose; doesnotcheckfwritereturn','meaning':'PCIe read-addressdomain, notCPvirtualaddressresolver; sourcehardwareclassunknownuntilmappedindependently'}
r['kernel_ioctl']={'function':'FFFFFF8008323818','only_command':'40185001','payload_size':24,'validation':'pcie_ch<=4,dmac_ch<=7,usercopy; rawphysicalsrc/dstcopiedunchanged','zero_size':'returns0 withoutqueueingDMA; notlinkedlistmodeofdirectkernelAPI','buffer_API':'No allocation/userpagepin/virtualtophysicalconversion inthisioctl. UDIFopsread/write/mmapnull. Openreturns0. Itrequirescaller-ownedstableDMAphysicaldestination.','nonzero':'pcidma_transfer_async, wait_for_completion_timeout(3000jiffies), callbackresult0success/nonzero-EIO; timeout-ETIMEDOUT; no explicitcancelinthisfunction','risk':'No claimthatioctltimeoutcancelsDMAorprovescallback/requestlifetimeclean; nohardwarecallmade'}
r['PDT_comparison']={'function':'backupfile_get_cp_data, originalbackup.ko text7030; analysis107030 isrelocatedsyntheticaddress, importstubsneverexecuted','source':'firstu32ofpreparedmanagerbuffer→arch_p32_to_p64','destination':'arch_va_to_phys(existingkernelmanagedmanagerbuffer)','transport':'pcie0,dmac4,dir0,pcidma_transfer_async; cachemaintenancebefore/after; completionsemwait','domain':'arch_p32_to_p64 DDRp32→4G|p32; eSRAMFE000000..FEFFFFFF remainsunchanged. ThisnumericconversiondoesnotmeanAPlocalmemoryread; requestsrcisremotePCIedomain. CPVA→CPphysicaltranslationstillrequiresitsMMU/context.','caller_limit':'PDTbuffer/sourcepreparationcomesfromexistingBackupCPprotocol; functionhasnoarbitrarysourceparameter. NotanindependentuserDMAallocatororrawmetadataAPI.'}
r['decision']='-t is directPCI DMAread withnoMPupdaterhandshake, butexistingclientisupdater-contextspecificandwrites hardcodedreservedAPstaging. SamekerneltransportasPDTdoesnotmakeaddresses/destinationownershipinterchangeable. No reviewedindependentnormal-contextstableuserDMAallocationAPIisprovidedby/dev/pcidma. Stopbeforedeployment; do notborrowPDTglobals,overwrite26MiB,addkernelhook/patchor scansourceaddresses.'
OUT.mkdir(exist_ok=True);(OUT/'review.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({'UDIFops':r['UDIF_CDEV_OPS'],'camera_io':False}))
if __name__=='__main__':pass
