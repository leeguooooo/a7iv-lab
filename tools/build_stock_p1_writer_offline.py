"""Offline fixed-P1 writer artifacts only. No USB imports or device executor."""
import hashlib
import io
import json
import os
from pathlib import Path
import secrets
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from camera_inventory import NATIVE, UPSTREAM, COMMIT, inspect

OUT = ROOT / 'output/stock-p1-writer-offline-01'
RECEIVER = ROOT / 'output/stock-key-preserving-receiver-01'
SOURCE = ROOT / 'output/backup-01/execution/cnflasha1.bin'
SOURCE_SHA = 'd415c4766c62b5b63bf106306e67b6a0512c4f97db834378e47ef79c40cf580b'
TARGET_SHA = 'e3ac140c49bd81b74799da9051b47a12ed201931380df87f7c35bc122345275e'
P1_SIZE, TEST_SIZE = 25100288, 32768
WRITER = NATIVE.parent / 'writer'
PINS = {'writer.c': 'e2ce0a4132c579d1597e0260f8119de942e31c67bed40881cb800480e65572f3',
        'sha256.h': '92a12379679d481d512e55a6928bf71825651a346d39b2ad15b9bafdea851ae5',
        'linux_a64.h': '827bfa50c9d5e2a1ee8eacc032303844cd3c0a8a9b4f5ea1bfa640a987eedd88',
        'bootstrap.c': '4e4dcb37eceab654a25b4a7f0d16626d1764f2a9708a48b3275da10c173b19a1'}
COMPILER = ROOT / 'local/zig-aarch64-macos-0.15.2/zig'
COMPILER_SHA = 'c65cd34917923f575448cc0603dd7c2326da0af0e5c323043d090662dcdf351c'
ROW = struct.Struct('<QQ32s32s')
RESULT = struct.Struct('<8s16s15q32s32s')
FIELDS = ('version','phase','error','euid','pid','ppid','loader_pid','cleanup','mode','rows',
          'write_calls','write_bytes','rollback','flags','io_status')


def require(ok, message):
    if not ok: raise ValueError(message)


def sha(data): return hashlib.sha256(data).hexdigest()


def file_sha(path):
    with Path(path).open('rb') as f: return hashlib.file_digest(f, 'sha256').hexdigest()


def write(path, data):
    path = Path(path)
    with path.open('xb') as f:
        os.fchmod(f.fileno(), 0o600); f.write(data); f.flush(); os.fsync(f.fileno())


def save(path, value): write(path, (json.dumps(value, indent=2)+'\n').encode())


def derived_source(original, test_only):
    if not test_only: return original
    old = b'#define P1_BYTES 25100288UL'
    old_size = b'if(r!=6 || !same(small,(const u8*)"49024\\n",6))return -22;'
    require(original.count(old)==original.count(old_size)==1, 'Unreviewed geometry substitutions')
    return original.replace(old, b'#define P1_BYTES 32768UL').replace(old_size,
        b'if(r!=3 || !same(small,(const u8*)"64\\n",3))return -22;')


def fixed_windows(before, after, spans):
    rows=[]; table=bytearray(); cursor=0
    for start,length in spans:
        require(cursor<=start<start+length<=len(before), 'Invalid source spans')
        require(before[cursor:start]==after[cursor:start], 'Change outside admitted spans')
        for offset in range(start,start+length,16384):
            n=min(16384,start+length-offset); a,b=before[offset:offset+n],after[offset:offset+n]
            if a==b: continue
            rows.append({'name':f'w{len(rows):04d}','offset':offset,'length':n,
                         'before_sha256':sha(a),'after_sha256':sha(b),'packet_sha256':sha(a+b)})
            table.extend(ROW.pack(offset,n,hashlib.sha256(a).digest(),hashlib.sha256(b).digest()))
        cursor=start+length
    require(before[cursor:]==after[cursor:] and len(before)==len(after), 'Unlisted image change')
    require(0<len(rows)<=768 and len(table)<=61440 and sum(2*r['length'] for r in rows)<=24*1024*1024,
            'Reviewed table/staging bounds exceeded')
    return rows,bytes(table)


def job_header(meta):
    def array(name,data): return 'static const unsigned char '+name+'[]={'+','.join(map(str,data))+'};\n'
    return ('#define JOB_DIR "'+meta['job_dir']+'"\n#define JOB_MODE 1\n#define NROWS '+str(len(meta['windows']))+
        '\n#define STAGE_BYTES '+str(meta['stage_bytes'])+'\n#define REQUIRED_TMPFS '+str(meta['required_tmpfs'])+'UL\n'+
        array('job_nonce',bytes.fromhex(meta['nonce']))+array('expected_table_digest',bytes.fromhex(meta['table_sha256']))+
        array('expected_before_digest',bytes.fromhex(meta['source_sha256']))+
        array('expected_after_digest',bytes.fromhex(meta['target_sha256'])))


def validate_job(job, *, allow_test=False):
    job=Path(job).resolve(); m=json.loads((job/'job.json').read_text())
    require(type(m['test_only']) is bool and (allow_test or not m['test_only']), 'TEST_ONLY writer cannot be production')
    require(m['schema']==('camera-stock-p1-writer-test/1' if m['test_only'] else 'camera-stock-p1-writer-production/1'),
            'Writer schema/test admission mismatch')
    require(m['bytes']==(TEST_SIZE if m['test_only'] else P1_SIZE) and m['direction']=='apply'
            and m['target']=={'path':'/dev/cnflasha1','rdev':'252:129','bytes':m['bytes'],
                             'sysfs_sectors':m['bytes']//512,'exclusive_required':True}, 'Writer fixed identity mismatch')
    if not m['test_only']:
        require(m['source_sha256']==SOURCE_SHA and m['target_sha256']==TARGET_SHA and len(m['windows'])==550,
                'Only reviewed personal P1 transition admitted')
    require(m['admission']=='OFFLINE_NATIVE_GUARDS_VALIDATED_NO_EXECUTOR'
            and m['production_execution_enabled'] is False, 'No execution admission exists')
    for name,digest in m['sources'].items(): require(file_sha(ROOT/name)==digest, 'Writer source changed')
    require(file_sha(COMPILER)==m['compiler_sha256']==COMPILER_SHA, 'Compiler changed')
    original=(WRITER/'writer.c').read_bytes()
    require(sha(original)==PINS['writer.c'] and (job/'source/writer/writer.c').read_bytes()==derived_source(original,m['test_only']),
            'Native writer body changed')
    require((job/'job.h').read_text()==job_header(m), 'Compiled job bindings changed')
    before=(ROOT/m['source_image']).read_bytes();after=(ROOT/m['target_image']).read_bytes()
    require(len(before)==len(after)==m['bytes'] and sha(before)==m['source_sha256'] and sha(after)==m['target_sha256'],
            'Source/target image changed')
    rows,table=fixed_windows(before,after,[(r['offset'],r['length']) for r in m['windows']])
    require(rows==m['windows'] and sha(table)==m['table_sha256'] and (job/'assets/table').read_bytes()==table,
            'Window table/image binding changed')
    for row in rows:
        n,off=row['length'],row['offset'];packet=(job/'assets'/row['name']).read_bytes()
        require(packet==before[off:off+n]+after[off:off+n] and sha(packet)==row['packet_sha256'], 'Staged bytes changed')
    require(m['stage_bytes']==sum(2*r['length'] for r in rows)
            and m['required_tmpfs']==m['stage_bytes']*2+m['stage_bytes']//2+4*1024*1024, 'Staging bound changed')
    require(file_sha(job/'worker.debug.elf')==m['debug_sha256'] and inspect(job/'worker.debug.elf',True)==m['debug_elf'],
            'Debug ELF changed')
    raw=(job/'worker.debug.elf').read_bytes();compact=compact_elf(raw)
    require((job/'worker.elf').read_bytes()==compact and sha(compact)==m['compact_worker_sha256'], 'Compact worker changed')
    require(inspect(job/'libJit.so',False)==m['module'] and (job/'libJit.so').read_bytes().count(compact)==1,
            'Module/embedded worker changed')
    return m


def compact_elf(raw):
    from elftools.elf.elffile import ELFFile
    elf=ELFFile(io.BytesIO(raw));limit=max(s['p_offset']+s['p_filesz'] for s in elf.iter_segments() if s['p_type']=='PT_LOAD')
    output=bytearray(raw[:limit]);struct.pack_into('<Q',output,40,0);struct.pack_into('<3H',output,58,0,0,0)
    ce=ELFFile(io.BytesIO(output));old=[s for s in elf.iter_segments() if s['p_type']=='PT_LOAD'];new=[s for s in ce.iter_segments() if s['p_type']=='PT_LOAD']
    require(len(old)==len(new) and elf['e_entry']==ce['e_entry'],'Compact mappings changed')
    for a,b in zip(old,new):
        require(dict(a.header)==dict(b.header),'Program headers changed');expected=bytearray(a.data())
        if a['p_offset']==0: struct.pack_into('<Q',expected,40,0);struct.pack_into('<3H',expected,58,0,0,0)
        require(bytes(expected)==b.data(),'Loaded native bytes changed')
    return bytes(output)


def build():
    os.umask(0o077);require(not OUT.exists(),'Fresh output required')
    require(subprocess.check_output(['git','-C',str(UPSTREAM),'rev-parse','HEAD'],text=True).strip()==COMMIT,
            'Reference revision changed')
    require(not subprocess.check_output(['git','-C',str(UPSTREAM),'status','--porcelain']),'Reference checkout changed')
    originals=[WRITER/'writer.c',WRITER/'sha256.h',NATIVE/'linux_a64.h',NATIVE/'lifecycle_worker.c',NATIVE/'bootstrap.c']
    for path in originals:
        if path.name in PINS: require(file_sha(path)==PINS[path.name],'Original native guard source changed')
    require(file_sha(COMPILER)==COMPILER_SHA,'Compiler changed')
    raw=SOURCE.read_bytes();candidate=(RECEIVER/'p1_candidate.bin').read_bytes()
    require(len(raw)==len(candidate)==P1_SIZE and sha(raw)==SOURCE_SHA and sha(candidate)==TARGET_SHA,'Personal P1 differs')
    receiver=json.loads((RECEIVER/'manifest.json').read_text())
    require(receiver['source_sha256']==SOURCE_SHA and receiver['candidate_sha256']==TARGET_SHA
            and receiver['stock_public_key_bytes_unchanged'] is True
            and receiver['all_four_original_verifyKey_entries_unchanged'] is True,'Receiver provenance differs')
    OUT.mkdir(mode=0o700)
    for test_only in (True,False):
        job=OUT/('test' if test_only else 'prod');job.mkdir(mode=0o700);(job/'assets').mkdir(mode=0o700)
        if test_only:
            before=bytes((i*7+3)&255 for i in range(TEST_SIZE));target=bytearray(before)
            spans=[(512,1024),(8192,4096),(30000,2000)]
            for off,n in spans:
                for i in range(off,off+n): target[i]^=0x5a
            after=bytes(target);write(job/'source.bin',before);write(job/'target.bin',after)
            before_path,after_path=job/'source.bin',job/'target.bin'
        else:
            before,after=raw,candidate;spans=[(s['offset'],s['length']) for s in receiver['allowed_spans']]
            before_path,after_path=SOURCE,RECEIVER/'p1_candidate.bin'
        rows,table=fixed_windows(before,after,spans)
        if not test_only: require(len(rows)==550,'Reviewed production window count changed')
        nonce=secrets.token_bytes(16);stage=sum(2*r['length'] for r in rows)
        meta={'schema':'camera-stock-p1-writer-test/1' if test_only else 'camera-stock-p1-writer-production/1',
              'test_only':test_only,'production_execution_enabled':False,
              'admission':'OFFLINE_NATIVE_GUARDS_VALIDATED_NO_EXECUTOR','direction':'apply','nonce':nonce.hex(),
              'job_dir':'/tmp_wbshd/m4p1_'+nonce.hex(),'bytes':len(before),'source_sha256':sha(before),'target_sha256':sha(after),
              'source_image':str(before_path.relative_to(ROOT)),'target_image':str(after_path.relative_to(ROOT)),
              'target':{'path':'/dev/cnflasha1','rdev':'252:129','bytes':len(before),'sysfs_sectors':len(before)//512,'exclusive_required':True},
              'table_sha256':sha(table),'windows':rows,'stage_bytes':stage,'required_tmpfs':stage*2+stage//2+4*1024*1024,
              'documented_test_substitutions':{'P1_BYTES':[25100288,32768],'sysfs_size_literal':['49024\\n','64\\n'],
                  'sysfs_size_literal_length':[6,3]} if test_only else {},
              'automatic_retry':False,'host_unknown_after_COMMIT_reconciliation_proven':False,'installable':False,
              'physical_restore_tested':False,'normal_boot_verified':False,'camera_io':False,'hardware_operations':0,
              'receiver_manifest_sha256':file_sha(RECEIVER/'manifest.json'),'compiler_sha256':COMPILER_SHA}
        write(job/'assets/table',table)
        for row in rows:
            off,n=row['offset'],row['length'];write(job/'assets'/row['name'],before[off:off+n]+after[off:off+n])
        write(job/'job.h',job_header(meta).encode())
        for path in originals:
            part='writer' if path.parent==WRITER else 'native';dest=job/'source'/part/path.name
            dest.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
            write(dest,derived_source(path.read_bytes(),test_only) if path.name=='writer.c' else path.read_bytes())
        flags=['-target','aarch64-linux-gnu','-mcpu=generic','-Os','-g','-ffreestanding','-fno-builtin','-fno-stack-protector',
               '-fno-unwind-tables','-fno-asynchronous-unwind-tables','-nostdlib','-ffunction-sections','-fdata-sections',
               '-Wl,--gc-sections','-Wl,--no-undefined','-Wl,--build-id=none','-Wl,-z,noexecstack','-Wl,-z,max-page-size=4096',
               '-Wl,-z,common-page-size=4096','-I',str(job),'-I',str(job/'source/native')]
        def compile(source,name,extra):
            result=subprocess.run([str(COMPILER),'cc',*flags,*extra,str(source),'-o',str(job/name)],capture_output=True,timeout=120)
            write(job/(name+'.compile.log'),result.stdout+result.stderr);require(result.returncode==0,'Offline compilation failed')
            (job/name).chmod(0o600)
        compile(job/'source/writer/writer.c','worker.debug.elf',['-static','-fno-pic','-Wl,-e,_start'])
        compact=compact_elf((job/'worker.debug.elf').read_bytes());write(job/'worker.elf',compact)
        write(job/'worker_blob.h',('static const unsigned char worker_blob[]={'+','.join(map(str,compact))+'};\n').encode())
        compile(job/'source/native/bootstrap.c','libJit.so',['-shared','-fPIC','-Wl,-Bsymbolic','-s'])
        require((job/'libJit.so').stat().st_size<=65520,'Bounded upload module too large')
        meta.update(debug_sha256=file_sha(job/'worker.debug.elf'),debug_elf=inspect(job/'worker.debug.elf',True),
                    compact_worker_sha256=sha(compact),module=inspect(job/'libJit.so',False),
                    compact_loads_preserved_except_section_header=True)
        dependencies=[*originals,Path(__file__),RECEIVER/'manifest.json',*job.rglob('*.h'),job/'source/writer/writer.c',job/'source/native/lifecycle_worker.c',job/'source/native/bootstrap.c']
        meta['sources']={str(p.relative_to(ROOT)):file_sha(p) for p in dependencies}
        save(job/'job.json',meta);validate_job(job,allow_test=True)
        print(json.dumps({'job':str(job.relative_to(ROOT)),'test_only':test_only,'rows':len(rows),'stage_bytes':stage,
                          'module_bytes':meta['module']['size'],'module_sha256':meta['module']['sha256']}),flush=True)
    require(file_sha(SOURCE)==SOURCE_SHA and file_sha(RECEIVER/'p1_candidate.bin')==TARGET_SHA,'Personal images changed')


if __name__=='__main__': build()
