"""Compile the fixed metadata collector and bootstrap offline."""
import argparse,io,json,os,secrets,struct,subprocess
from pathlib import Path
from elftools.elf.elffile import ELFFile
from install_runtime_metadata_profile import *
def build(output):
 sources=input_evidence();out=jobpath(output,True);out.mkdir(parents=True,mode=0o700)
 nonce=secrets.token_bytes(16);(out/'job.h').write_bytes(header(nonce))
 flags=['-target','aarch64-linux-gnu','-mcpu=generic','-Os','-g','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-unwind-tables','-fno-asynchronous-unwind-tables','-nostdlib','-ffunction-sections','-fdata-sections','-Wl,--gc-sections','-Wl,--no-undefined','-Wl,--build-id=none','-Wl,-z,noexecstack','-Wl,-z,max-page-size=4096','-Wl,-z,common-page-size=4096','-I',str(out),'-I',str(APP/'native'),'-I',str(APP/'writer')]
 env=dict(os.environ,ZIG_GLOBAL_CACHE_DIR=str(out/'zig-global-cache'),ZIG_LOCAL_CACHE_DIR=str(out/'zig-local-cache'));commands=[]
 def compile(source,name,extra):
  command=[str(COMPILER),'cc',*flags,*extra,str(source),'-o',str(out/name)];commands.append(command)
  result=subprocess.run(command,capture_output=True,text=True,timeout=120,env=env);(out/(name+'.compile.log')).write_text(result.stdout+result.stderr);require(result.returncode==0,result.stderr[-3000:])
 compile(ROOT/'native/install_runtime_metadata.c','worker.debug.elf',['-static','-fno-pic','-Wl,-e,_start'])
 debug=(out/'worker.debug.elf').read_bytes();elf=ELFFile(io.BytesIO(debug));limit=max(s['p_offset']+s['p_filesz'] for s in elf.iter_segments() if s['p_type']=='PT_LOAD');compact=bytearray(debug[:limit]);struct.pack_into('<Q',compact,40,0);struct.pack_into('<3H',compact,58,0,0,0)
 (out/'worker.elf').write_bytes(compact);(out/'worker_blob.h').write_text('static const unsigned char worker_blob[]={'+','.join(map(str,compact))+'};\n')
 (out/'symbols.json').write_text(json.dumps({s.name:s['st_value'] for s in elf.get_section_by_name('.symtab').iter_symbols() if s.name},sort_keys=True))
 compile(BOOTSTRAP,'libJit.so',['-shared','-fPIC','-Wl,-Bsymbolic','-s']);require(input_evidence()==sources,'Sources changed during build')
 names=('job.h','worker.debug.elf','worker.elf','worker_blob.h','symbols.json','libJit.so','worker.debug.elf.compile.log','libJit.so.compile.log')
 manifest=dict(schema=SCHEMA,profile=PROFILE,nonce=nonce.hex(),job_dir='/tmp_wbshd/m4irm_'+nonce.hex(),sources=sources,compiler_sha256=COMPILER_SHA,compile_commands=commands,artifacts={n:dict(sha256=sha(out/n),bytes=(out/n).stat().st_size) for n in names},hardware_operations=0,hardware_acceptance=False,block_opens=0,process_memory_writes=0,installation_authorized=False)
 (out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');return out
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',required=True);a=p.parse_args();print(build(a.output))
