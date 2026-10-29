"""Independent metadata ELF, embedding, ABI, fixed paths and source checks."""
import argparse,hashlib,io,json,re,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from elftools.elf.elffile import ELFFile
from install_runtime_metadata_profile import *
from verify_menu_window_offline import inspect_elf,check_compact
def verify(directory):
 d=jobpath(directory);raw=read_regular(d/'manifest.json');m=json.loads(raw);require(m['schema']==SCHEMA and m['profile']==PROFILE,'Wrong metadata profile');require(m['sources']==input_evidence() and m['compiler_sha256']==COMPILER_SHA,'Current source closure differs')
 require(re.fullmatch('[0-9a-f]{32}',m['nonce']) and any(bytes.fromhex(m['nonce'])) and m['job_dir']=='/tmp_wbshd/m4irm_'+m['nonce'],'Nonce/job differs')
 require(m['hardware_operations']==0 and m['hardware_acceptance'] is False and m['block_opens']==0 and m['process_memory_writes']==0 and m['installation_authorized'] is False,'Offline boundary differs')
 names={'job.h','worker.debug.elf','worker.elf','worker_blob.h','symbols.json','libJit.so','worker.debug.elf.compile.log','libJit.so.compile.log'};require(set(m['artifacts'])==names,'Artifact closure differs');assets={n:read_regular(d/n) for n in names}
 for n,b in assets.items():require(m['artifacts'][n]==dict(sha256=hashlib.sha256(b).hexdigest(),bytes=len(b)),'Artifact changed: '+n)
 require(assets['job.h']==header(bytes.fromhex(m['nonce'])),'Compiled nonce header differs')
 flags=['-target','aarch64-linux-gnu','-mcpu=generic','-Os','-g','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-unwind-tables','-fno-asynchronous-unwind-tables','-nostdlib','-ffunction-sections','-fdata-sections','-Wl,--gc-sections','-Wl,--no-undefined','-Wl,--build-id=none','-Wl,-z,noexecstack','-Wl,-z,max-page-size=4096','-Wl,-z,common-page-size=4096','-I',str(d),'-I',str(APP/'native'),'-I',str(APP/'writer')]
 expected=[[str(COMPILER),'cc',*flags,'-static','-fno-pic','-Wl,-e,_start',str(ROOT/'native/install_runtime_metadata.c'),'-o',str(d/'worker.debug.elf')],[str(COMPILER),'cc',*flags,'-shared','-fPIC','-Wl,-Bsymbolic','-s',str(BOOTSTRAP),'-o',str(d/'libJit.so')]]
 require(m['compile_commands']==expected,'Compile inputs/flags differ')
 debug,compact,module=[assets[n] for n in ('worker.debug.elf','worker.elf','libJit.so')];inspected=dict(debug=inspect_elf(debug,True),compact=inspect_elf(compact,True,compact=True),bootstrap=inspect_elf(module,False));check_compact(debug,compact)
 elf=ELFFile(io.BytesIO(debug));symbols={s.name:s for s in elf.get_section_by_name('.symtab').iter_symbols() if s.name};require(symbols['wr']['st_size']==176 and symbols['aliases']['st_size']==1728,'Native wire sizes differ');require(json.loads(assets['symbols.json'])=={n:s['st_value'] for n,s in symbols.items()},'Symbols differ')
 at=mapped(elf,symbols['job_nonce']['st_value'],16);require(debug[at:at+16]==bytes.fromhex(m['nonce']),'ELF nonce differs');require(module.count(compact)==1 and len(module)<=65520,'Embedding/upload bound differs')
 module_elf=ELFFile(io.BytesIO(module));offset=module.index(compact);segments=[s for s in module_elf.iter_segments() if s['p_type']=='PT_LOAD' and s['p_offset']<=offset and offset+len(compact)<=s['p_offset']+s['p_filesz']];require(len(segments)==1 and not segments[0]['p_flags']&2,'Worker embedding must be readonly')
 blob=re.fullmatch(r'static const unsigned char worker_blob\[\]=\{([0-9,]+)\};\n',assets['worker_blob.h'].decode());require(blob and bytes(map(int,blob.group(1).split(',')))==compact,'Header embedding differs')
 structs={die.attributes['DW_AT_name'].value:die for cu in elf.get_dwarf_info().iter_CUs() for die in cu.iter_DIEs() if die.tag=='DW_TAG_structure_type' and 'DW_AT_name' in die.attributes};st=structs[b'A64Stat'];members={x.attributes['DW_AT_name'].value.decode():x.attributes['DW_AT_data_member_location'].value for x in st.iter_children() if x.tag=='DW_TAG_member'};require(st.attributes['DW_AT_byte_size'].value==128 and members['mode']==16 and members['rdev']==32,'Stat DWARF differs')
 for name,size,offsets in ((b'Wire',176,{'magic':0,'nonce':8,'version':24,'proc_sha':112,'alias_sha':144}),(b'Alias',288,{'number':0,'length':8,'mode':16,'rdev':24,'target':32,'stat_raw':160})):
  die=structs[name];found={x.attributes['DW_AT_name'].value.decode():x.attributes['DW_AT_data_member_location'].value for x in die.iter_children() if x.tag=='DW_TAG_member'};require(die.attributes['DW_AT_byte_size'].value==size and all(found.get(k)==v for k,v in offsets.items()),'Metadata DWARF ABI differs')
 return dict(schema='camera-install-runtime-metadata-verification/1',all_passed=True,manifest_sha256=hashlib.sha256(raw).hexdigest(),nonce=m['nonce'],source_bindings=m['sources'],artifact_bindings=m['artifacts'],elf=inspected,hardware_operations=0,hardware_acceptance=False)
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--job',required=True);a=p.parse_args();print(json.dumps(verify(a.job),sort_keys=True))
