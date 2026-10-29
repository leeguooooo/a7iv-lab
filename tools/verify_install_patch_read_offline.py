"""Independent fixed-receipt reader ELF and binding inspection; no execution."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from elftools.elf.elffile import ELFFile
from install_patch_read_profile import (ROOT, APP, COMPILER, COMPILER_SHA, SCHEMA, PROFILE, contract,
    input_evidence, derive, header, read_regular, require, sha, mapped)
from verify_menu_window_offline import inspect_elf, check_compact


def verify(directory):
    directory = Path(directory).absolute()
    require('..' not in directory.parts and directory.is_relative_to(ROOT/'output'), 'Workspace output required')
    raw_manifest = read_regular(directory/'manifest.json')
    m = json.loads(raw_manifest)
    require(m['schema']==SCHEMA and m['profile']==PROFILE and m['admission']=='OFFLINE_NOT_BODY_BOUND', 'Reader profile differs')
    sources,libraries=input_evidence()
    require(m['sources']==sources and m['libraries']==libraries,'Reader source/library closure changed')
    original=m['original_pending']
    pending,spec=derive(original['path'],original['body_sha256'],original['plan_sha256'])
    require(hashlib.sha256(pending).hexdigest()==original['sha256']==spec['pending_receipt_sha256'], 'Prior raw pending changed')
    require(m['original_patch_nonce']==spec['original_patch_nonce'] and m['target_spec_sha256']==contract.spec_sha256(spec)
            and m['original_source_is_hardware'] is spec['original_source_is_hardware'], 'Target derivation differs')
    nonce=m['nonce']
    old_nonces={spec['original_patch_nonce'], *(spec['original_asset_reference']['captures'][name]['nonce']
                                               for name in ('pre_app','pre_ufp'))}
    require(isinstance(nonce,str) and re.fullmatch('[0-9a-f]{32}',nonce) and any(bytes.fromhex(nonce))
            and nonce not in old_nonces and m['job_dir']=='/tmp_wbshd/m4ipr_'+nonce,'Reader nonce binding differs')
    for key in ('live_controller_sealed','hardware_acceptance','native_fault_model_executed','worker_executed',
                'bootstrap_executed','automatic_retry','original_hardware_origin_proven','original_mm_continuity_proven',
                'restoration_proven','installation_authorized','firmware_readiness_proven'):
        require(m[key] is False,'Unsupported observation/authority claim')
    require(type(m['hardware_operations']) is int and m['hardware_operations']==0
            and type(m['process_memory_writes']) is int and m['process_memory_writes']==0
            and m['readonly_process_memory'] is True and m['body_binding'] is None and m['target_package_sha256'] is None,
            'Offline readonly boundary differs')
    require(m['compiler']==dict(path=str(COMPILER.relative_to(ROOT)),sha256=COMPILER_SHA,version='0.15.2',host='aarch64-macos',target='aarch64-linux-gnu'), 'Compiler differs')
    flags=['-target','aarch64-linux-gnu','-mcpu=generic','-Os','-g','-ffreestanding','-fno-builtin',
        '-fno-stack-protector','-fno-unwind-tables','-fno-asynchronous-unwind-tables','-nostdlib',
        '-ffunction-sections','-fdata-sections','-Wl,--gc-sections','-Wl,--no-undefined',
        '-Wl,--build-id=none','-Wl,-z,noexecstack','-Wl,-z,max-page-size=4096','-Wl,-z,common-page-size=4096',
        '-I',str(directory),'-I',str(APP/'native')]
    expected_commands=[[str(COMPILER),'cc',*flags,'-static','-fno-pic','-Wl,-e,_start',
                        str(ROOT/'native/install_patch_read.c'),'-o',str(directory/'worker.debug.elf')],
                       [str(COMPILER),'cc',*flags,'-shared','-fPIC','-Wl,-Bsymbolic','-s',
                        str(APP/'native/bootstrap.c'),'-o',str(directory/'libJit.so')]]
    require(m['compile_commands']==expected_commands,'Recorded compile inputs/flags differ')
    require(m['result']==dict(magic=contract.MAGIC.decode(),version=1,start_magic=contract.START_MAGIC.decode(),
            start_format='<8s16s16sQ',format=contract.FRAME.format,bytes=424,fields=list(contract.FIELDS)), 'Reader ABI differs')
    require(m['terminal_publication']==dict(pending='result.pending',published='result',syscall='renameat2',flags=1), 'Publication contract differs')
    names={'prior-pending.json','target-spec.json','job.h','worker.debug.elf','worker.elf','worker_blob.h',
           'symbols.json','libJit.so','worker.debug.elf.compile.log','libJit.so.compile.log'}
    require(set(m['artifacts'])==names,'Artifact closure differs')
    artifacts={name:read_regular(directory/name) for name in names}
    for name,raw in artifacts.items():
        require(m['artifacts'][name]==dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()),'Artifact changed: '+name)
    require(artifacts['prior-pending.json']==pending and json.loads(artifacts['target-spec.json'])==spec, 'Saved target proof differs')
    require(artifacts['job.h']==header(bytes.fromhex(nonce),spec),'Compiled target header differs')
    debug,compact,module=(artifacts[n] for n in ('worker.debug.elf','worker.elf','libJit.so'))
    inspected=dict(worker_debug=inspect_elf(debug,True),worker_compact=inspect_elf(compact,True,compact=True),bootstrap=inspect_elf(module,False))
    loaded=check_compact(debug,compact)
    elf=ELFFile(io.BytesIO(debug));symbols=elf.get_section_by_name('.symtab')
    require(symbols is not None and elf.has_dwarf_info(),'Debug ABI proof missing')
    values={s.name:s['st_value'] for s in symbols.iter_symbols() if s.name}
    require(json.loads(artifacts['symbols.json'])==values and values.get('_start')==elf['e_entry'] and 'read_main' in values,'Entry/symbols differ')
    result=[s for s in symbols.iter_symbols() if s.name=='wr']
    require(len(result)==1 and result[0]['st_size']==424,'Native result size differs')
    for name,expected in (('job_nonce',bytes.fromhex(nonce)),('patch_nonce',bytes.fromhex(spec['original_patch_nonce'])),
                          ('target_spec_sha256',bytes.fromhex(contract.spec_sha256(spec)))):
        require(name in values,'Compiled identity symbol missing')
        offset=mapped(elf,values[name],len(expected));require(debug[offset:offset+len(expected)]==expected,'Compiled identity bytes differ')
    structs=[die for cu in elf.get_dwarf_info().iter_CUs() for die in cu.iter_DIEs()
             if die.tag=='DW_TAG_structure_type' and die.attributes.get('DW_AT_name')
             and die.attributes['DW_AT_name'].value==b'CurrentReadResult']
    require(len(structs)==1 and structs[0].attributes['DW_AT_byte_size'].value==424,'DWARF result ABI differs')
    members=[(d.attributes['DW_AT_name'].value.decode(),d.attributes['DW_AT_data_member_location'].value)
             for d in structs[0].iter_children() if d.tag=='DW_TAG_member']
    require(members==[('magic',0),('nonce',8),('patch_nonce',24),('spec_sha256',40),('values',72)],'DWARF field offsets differ')
    blob=re.fullmatch(r'static const unsigned char worker_blob\[\]=\{([0-9,]+)\};\n',artifacts['worker_blob.h'].decode())
    require(blob and bytes(map(int,blob.group(1).split(',')))==compact,'Worker header differs')
    require(len(module)<=65520 and module.count(compact)==1,'Embedded worker/upload bound differs')
    module_elf=ELFFile(io.BytesIO(module));offset=module.index(compact)
    containing=[s for s in module_elf.iter_segments() if s['p_type']=='PT_LOAD' and s['p_offset']<=offset
                and offset+len(compact)<=s['p_offset']+s['p_filesz']]
    require(len(containing)==1 and not containing[0]['p_flags']&2,'Embedded worker must be readonly')
    return dict(schema='camera-install-patch-read-offline-verification/1',all_passed=True,
        manifest_sha256=hashlib.sha256(raw_manifest).hexdigest(),nonce=nonce,target_spec_sha256=contract.spec_sha256(spec),
        source_count=len(sources),elf=inspected,compact_loaded_bytes=loaded,result_abi=dict(bytes=424,dwarf_members=members),
        embedded_worker_count=1,module_upload_bound=65520,hardware_operations=0,hardware_acceptance=False,
        native_fault_model_executed=False,worker_executed=False,bootstrap_executed=False,
        original_mm_continuity_proven=False,restoration_proven=False,installation_authorized=False,
        verifier_sha256=sha(Path(__file__)))


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    result=verify(a.output)
    with (a.output/'verification.json').open('x') as f:json.dump(result,f,indent=2);f.write('\n')
    print(json.dumps(dict(all_passed=True,hardware_operations=0,manifest_sha256=result['manifest_sha256'])))


if __name__=='__main__':main()
