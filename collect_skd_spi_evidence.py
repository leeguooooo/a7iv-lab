"""Offline ELF/Capstone evidence only. Never opens SPI or runs target code."""
from pathlib import Path
from elftools.elf.elffile import ELFFile
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
import hashlib,io,json
ROOT=Path(__file__).resolve().parent
OUT=ROOT/'output/rea-study/skd-spi'
SOURCES={'updater':ROOT/'local/firmware/a7m4-6.02/nor-research/updater-nor/usr/lib/libInfraSKD.so','normal':ROOT/'local/firmware/a7m4-6.02/nor-research/libs/libInfraSKD.so'}
EXPECTED={'updater':'8052390d5d043db47dd0aa83b3f65be7ec980288c5c72c01f46229b597b12f20','normal':'7d1fbd9a53794def916ca3ff2fc3a00f295268bb0f4ea7c07d0e8356d2840f9b'}
report={'camera_io':False,'target_execution':False,'kind':'ordinaryELF/Capstone originalartifacts, notREA','sources':{},'embedded':{},'functions':{},'ioctl_abi':{'0x40016b01':'SPI_IOC_WR_MODE','0x40016b03':'SPI_IOC_WR_BITS_PER_WORD','0x40046b04':'SPI_IOC_WR_MAX_SPEED_HZ','0x40016b02':'SPI_IOC_WR_LSB_FIRST','message':'0x40006b00 | (n<<21), n<=511; 32-byte struct spi_ioc_transfer'},'scope_limit':'Runtimeenvironment,actualpeeridentity,electricalstate,andprotectedSonyfunctionbodiesnotexecuted/unpacked; noinferenceofactiveSPIpeerfromstringalone.'}
for label,p in SOURCES.items():
 raw=p.read_bytes();assert hashlib.sha256(raw).hexdigest()==EXPECTED[label];report['sources'][label]={'path':str(p.relative_to(ROOT)),'size':len(raw),'sha256':EXPECTED[label]}
 off=0x298438 if label=='updater' else 0x350438;e=ELFFile(io.BytesIO(raw[off:]));size=max([s['p_offset']+s['p_filesz'] for s in e.iter_segments()]+[s['sh_offset']+(s['sh_size'] if s['sh_type']!='SHT_NOBITS' else 0) for s in e.iter_sections()]+[e['e_shoff']+e['e_shnum']*e['e_shentsize']]);b=raw[off:off+size]
 report['embedded'][label]={'outerfileoffset':hex(off),'size':size,'sha256':hashlib.sha256(b).hexdigest(),'machine':e['e_machine'],'exported_entry':'MainCPS','DT_NEEDED':[x.needed for x in e.get_section_by_name('.dynamic').iter_tags() if x.entry.d_tag=='DT_NEEDED']}
 sec=e.get_section_by_name('.text');text=sec.data();va=sec['sh_addr'];plt=e.get_section_by_name('.plt');rs=e.get_section_by_name('.rela.plt');st=e.get_section(rs['sh_link']);links={plt['sh_addr']+32+i*16:st.get_symbol(x['r_info_sym']).name for i,x in enumerate(rs.iter_relocations())};m=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
 ranges=[(0xf7fcc,0xf806c),(0xf80a8,0xf82dc),(0xf832c,0xf84c8),(0xf84c8,0xf872c),(0xc1f84,0xc20dc),(0xc20dc,0xc21f8),(0xc21f8,0xc2318),(0xc28e4,0xc2ad8),(0xc2fa0,0xc306c),(0xc306c,0xc33e0)] if label=='updater' else [(0xe9d00,0xe9eb0),(0xe9f30,0xea0d0),(0xea0fc,0xea180)]
 for a,z in ranges:
  rows=[]
  for i in m.disasm(text[a-va:z-va],a):
   row={'address':hex(i.address),'mnemonic':i.mnemonic,'operands':i.op_str}
   if i.mnemonic=='bl':row['PLT_callee']=links.get(int(i.op_str[1:],16),'')
   rows.append(row)
  report['functions'][label+':'+hex(a)]=rows
report['observations']=[{'entry':'updaterembedded f84c8','finding':'ReturnsNULLunless getenv(SPI_ENABLE) startsASCII1. Copiesdefault/dev/spidev0.0; optionalSPI_PARAM_DEV_PATH/DEV_PATH2 overrideiflength<=14. Thisiscodecondition, notruntimeenvobservation.'},{'entry':'f80a8','finding':'open(path,0x8002) read/write; defaultmode3,bits8,LSB0,speedfromcontext+18. Configioctlsmustallreturnnonnegative, elseclose/return0. ENOENT/ENODEVgeterrorstate; nofallbacktoNORinterface.'},{'entry':'f832c','finding':'ABI(ctx,tx,rx,nbytes). Buildsone32Btransferperbyte: tx64@0,rx64@8,len32@10=1,cs_change@1b default1,otherfieldszero. Dispatches<=511entriesperioctl, successwhenaccumulatedreturnequalsnbytes. Thisisfull-duplexwiretransfer, notpassivefileread.'},{'entry':'c1f84/c20dc','finding':'Commandsendlimitsctx.maxfragment+2, requiresallreceivedbytesFF. ReceiveclocksallFFTXandpermitsctx.maxfragment+4. Bothusef832c.'},{'entry':'c28e4','finding':'Sends3bytesforprotocolversion<=1 or4for>1: commandbyte,ctx+2e LE16maxfragment,optionalFF. c21f8 pollsnonFFstatus. Onstatus0length/headercheckuseslow9bitsandflagsC000; privateprotocolnotfixedNORaddressABI.'},{'entry':'c306c..c33e0','finding':'Enumerationissuesinternalcommand0x0b with448Bresponsebuffer, checksreplyprotocolversion1/2, derivesfrequencyfromcapabilityindices, validates/configurestimeoutandmaxfragment; maysendinternalcmd3/4. Theseareendpointcapabilitynegotiationcalls, notJEDECarrayread.'},{'entry':'normalembedded e9e50/e9e68/e9e80/e9e98/ea070','finding':'SeparatelyconfirmedfourconfigioctlconstantsandMESSAGEconstruction. Do notreuseupdateroffsetsin normalELF.'}]
report['assessment']='The SPIpathisafragmentedpeerprotocolbackendinsidetheembeddedMainCPS/CodeMetercomponent, conditionallyenabledbySPI_ENABLE. NoCPNORreadprimitive,flashoffset/EXBLhandlingorOSPIregisterpathisidentifiedinthisboundedcallchain. Exactphysicalpeeridentityandwhetherenabledonthebodyremainunobserved; do notlabelactualSonysecuritychiporclaimthatspidevreadsNOR.'
OUT.mkdir(exist_ok=True);(OUT/'review.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'source_shas':EXPECTED,'functions_recorded':len(report['functions']),'camera_io':False}))
