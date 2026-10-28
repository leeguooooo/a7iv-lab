"""Explicit, fixed-scope USB backups; no partition writer or installer."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import struct
import subprocess
import sys
import time

from camera_inventory import ROOT, UPSTREAM, NATIVE, COMMIT, LAUNCH, LIBRARIES, inspect, require, save, sha

RESULT = struct.Struct("<8s16s12q32s32s")
FIELDS = ("version", "phase", "error", "euid", "pid", "ppid", "loader_pid", "cleanup", "index", "bytes", "chunks", "flags")
TARGETS = [("cnflasha1", 129, 24512 * 1024), ("cnflasha2", 130, 20480 * 1024),
           ("cnflasha6", 134, 25600 * 1024), ("nflashaB0", 126, 4096 * 1024), ("nflashaB1", 127, 4096 * 1024)]


def prepare(out, test_only=False):
    require(not out.exists(), "Choose a new output directory")
    require(subprocess.check_output(["git", "-C", str(UPSTREAM), "rev-parse", "HEAD"], text=True).strip() == COMMIT, "Upstream changed")
    require(not subprocess.check_output(["git", "-C", str(UPSTREAM), "status", "--porcelain"], text=True).strip(), "Upstream dirty")
    out.mkdir(parents=True);nonce=secrets.token_bytes(16);directory="/tmp_wbshd/m4bkp_"+nonce.hex()
    targets=[(n,m,4096 if test_only else size) for n,m,size in TARGETS]
    header='#define JOB_DIR "'+directory+'"\nstatic const unsigned char job_nonce[]={'+','.join(map(str,nonce))+'};\n'
    header+='struct Target {const char*path;u64 size,rdev;const char*sysdev,*dev;u64 devlen;const char*syssize,*sectors;u64 sectorlen;};\nstatic const struct Target targets[]={\n'
    for name,minor,size in targets:
        dev=f"252:{minor}\n";sectors=f"{size//512}\n"
        header+='{'+','.join([json.dumps('/dev/'+name),str(size),str((252<<8)|minor),json.dumps('/sys/class/block/'+name+'/dev'),json.dumps(dev),str(len(dev)),json.dumps('/sys/class/block/'+name+'/size'),json.dumps(sectors),str(len(sectors))])+'},\n'
    header+='};\n';(out/'job.h').write_text(header)
    compiler=ROOT/'local/zig-aarch64-macos-0.15.2/zig'
    flags=['cc','-target','aarch64-linux-gnu','-mcpu=generic','-Os','-g','-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-unwind-tables','-fno-asynchronous-unwind-tables','-nostdlib','-ffunction-sections','-fdata-sections','-Wl,--gc-sections','-Wl,--no-undefined','-Wl,--build-id=none','-Wl,-z,noexecstack','-Wl,-z,max-page-size=4096','-Wl,-z,common-page-size=4096','-I',str(out),'-I',str(NATIVE),'-I',str(NATIVE.parent/'writer')]
    def compile(src,name,extra):
        r=subprocess.run([str(compiler),*flags,*extra,str(src),'-o',str(out/name)],capture_output=True,text=True,timeout=120)
        (out/(name+'.compile.log')).write_text(r.stdout+r.stderr);require(r.returncode==0,r.stderr[-3000:])
    compile(ROOT/'native/backup.c','worker.debug.elf',['-static','-fno-pic','-Wl,-e,_start'])
    worker=inspect(out/'worker.debug.elf',True);raw=(out/'worker.debug.elf').read_bytes()
    limit=max(s['p_offset']+s['p_filesz'] for s in worker['segments'] if s['p_type']=='PT_LOAD')
    compact=bytearray(raw[:limit]);struct.pack_into('<Q',compact,40,0);struct.pack_into('<3H',compact,58,0,0,0)
    (out/'worker.elf').write_bytes(compact);(out/'worker_blob.h').write_text('static const unsigned char worker_blob[]={'+','.join(map(str,compact))+'};\n')
    compile(NATIVE/'bootstrap.c','libJit.so',['-shared','-fPIC','-Wl,-Bsymbolic','-s'])
    module=inspect(out/'libJit.so',False);require(module['size']<=65520,'Oversize one-shot module')
    sources=[ROOT/'native/backup.c',Path(__file__),ROOT/'camera_inventory.py',NATIVE/'linux_a64.h',NATIVE/'bootstrap.c',NATIVE/'lifecycle_worker.c',NATIVE.parent/'writer/sha256.h']
    identities={str(p.relative_to(ROOT)):sha(p) for p in sources}
    for p in sources:
        dest=out/'sources'/p.relative_to(ROOT);dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(p.read_bytes())
    meta={'schema':'camera-use-backup-test/1' if test_only else 'camera-use-backup/1','nonce':nonce.hex(),'job_dir':directory,
          'targets':targets,'worker':worker,'worker_sha256':sha(out/'worker.elf'),'module':module,'header_sha256':sha(out/'job.h'),
          'sources':identities,'compiler_sha256':sha(compiler),'block_writes':False,'whole_emmc_backup':False,'nor_backup':False}
    save(out/'job.json',meta);print(json.dumps({'job':str(out),'test_only':test_only,'module_bytes':module['size']}))


def decode(raw,meta):
    require(len(raw)==RESULT.size,'Partial backup record');magic,nonce,*v=RESULT.unpack(raw)
    require(magic==b'M4BKP001' and nonce.hex()==meta['nonce'],'Backup identity mismatch')
    return dict(zip(FIELDS,v[:12]))|{'first_sha256':v[12].hex(),'second_sha256':v[13].hex()}


def run(out):
    meta=json.loads((out/'job.json').read_text());require(meta['schema']=='camera-use-backup/1','Test jobs cannot access a camera')
    require(meta['targets']==[list(x) for x in TARGETS],'Target list changed')
    require(all(sha(ROOT/p)==h for p,h in meta['sources'].items()),'Sources changed; rebuild and retest')
    require(sha(out/'worker.elf')==meta['worker_sha256'] and sha(out/'libJit.so')==meta['module']['sha256'] and sha(out/'job.h')==meta['header_sha256'],'Job changed')
    em=json.loads((out/'emulation.json').read_text())
    require(em['all_passed'] and em['worker_sha256']==meta['worker_sha256'] and em['module_sha256']==meta['module']['sha256'],'Missing exact-job validation')
    require(not (out/'attempt.json').exists(),'Already attempted; do not resend a module')
    sys.path.insert(0,str(ROOT/'Sony-PMCA-RE'))
    import usb.core,usb.util,usb.backend.libusb1
    backend=usb.backend.libusb1.get_backend(find_library=lambda _:'/opt/homebrew/lib/libusb-1.0.dylib')
    devices=list(usb.core.find(find_all=True,idVendor=0x054c,idProduct=0x0da5,backend=backend))
    require(len(devices)==1 and devices[0].product=='ILCE-7M4','One normal MSC A7M4 required')
    serial=devices[0].serial_number;require(bool(serial),'Missing normal USB identity')
    body={'model':'ILCE-7M4','usb_serial_sha256':hashlib.sha256(serial.encode()).hexdigest()};usb.util.dispose_resources(devices[0])
    expected=json.loads((ROOT/'output/inventory-04/execution/run.json').read_text())['body'];require(body['usb_serial_sha256']==expected['usb_serial_sha256'],'Body changed')
    from pmca.commands.usb import senserShellCommand
    from pmca.platform.backend.senser import SenserPlatformBackend
    from a7m4.fl23 import bk4_rows
    evidence=out/'execution';evidence.mkdir();save(out/'attempt.json',{'time':time.time(),'body':body,'automatic_retry':False})
    report={'body':body,'block_writes':False,'settings_writes':False,'module_uploads':0,'partitions':{},'nor_backup':False,'whole_emmc_backup':False,'atomic_whole_camera_snapshot':False,'verdict':'NOT_STARTED'}
    def complete(camera):
        SenserPlatformBackend(camera).start();healthy=True
        old=(ROOT/'dumps/20261026-031555/backup_preset.bin').read_bytes()
        recs=[row['records'][0x00e70003] for row in bk4_rows(old) if 0x00e70003 in row['records']];require(len(recs)==1,'Ambiguous original serial')
        r=recs[0];require(bytes(camera.readBackup(0x00e70003))==old[r['offset']:r['offset']+r['size']],'Service body changed')
        def packet(cmd,data):
            nonlocal healthy
            require(healthy,'Unknown USB outcome; stop')
            try:
                status,raw=camera.dev.sendSenserPacket(0x40,struct.pack('<HH',0x1001,cmd)+data);raw=bytes(raw or b'')
                require(status==0 and len(raw)>=4,'Malformed response');code=struct.unpack_from('<I',raw)[0]
                if code:
                    from camera_inventory import CameraStatusError
                    raise CameraStatusError(code)
                return raw[4:]
            except BaseException as e:
                from camera_inventory import CameraStatusError
                if not isinstance(e,CameraStatusError):healthy=False
                raise
        def select(path):require(packet(15,b'\0'+path.encode()+b'\0')==b'','Select response changed')
        def readpath(path,maximum,missing=False):
            from camera_inventory import CameraStatusError
            select('/tmp/jiritsu/../..'+path)
            try:data=packet(17,b'\0\xff\0')
            except CameraStatusError as e:
                if missing and e.status==0x10000006:return None
                raise
            require(len(data)<=maximum,'Read exceeds bound');return data
        def read(name,size,missing=False):return readpath(meta['job_dir']+'/'+name,size,missing)
        def write(name,data):
            require(name in ['module','start',*[f'ack{i}' for i in range(5)]],'Invalid upload name')
            path='/tmp/jiritsu/libJit.so' if name=='module' else '/tmp/jiritsu/../..'+meta['job_dir']+'/'+name
            select(path);require(packet(16,b'\0\xff\0'+data)==b'','Upload response changed')
        def poll(name,size,seconds=90):
            until=time.monotonic()+seconds
            while time.monotonic()<until:
                raw=read(name,size,True)
                if raw is not None:
                    require(len(raw)==size,'Partial publication');(evidence/(name+'.bin')).write_bytes(raw);return raw
                if name!='result':
                    failure=read('exec_failure',8,True);require(failure is None,'Native exec failed')
                    final=read('result',RESULT.size,True)
                    if final is not None:
                        report['native']=decode(final,meta);require(report['native']['phase']!=90,'Native stopped: '+str(report['native']))
                time.sleep(.2)
            raise TimeoutError('Native deadline; never automatically reupload')
        for path,expected in LIBRARIES.items():
            raw=readpath(path,300000);require(hashlib.sha256(raw).hexdigest()==expected,'Loader library mismatch');(evidence/Path(path).name).write_bytes(raw)
        require(readpath('/tmp/jiritsu/libJit.so',65520,True) is None,'Existing module cannot be replaced')
        preset=bytes(SenserPlatformBackend(camera).getBackupData());(evidence/'backup_preset.fresh.bin').write_bytes(preset);bk4_rows(preset)
        report['module_uploads']=1;report['jiritsu_workarea_filesystem_touched']=True;save(evidence/'run.json',report)
        write('module',(out/'libJit.so').read_bytes())
        launch=LAUNCH.unpack(poll('launch',LAUNCH.size))
        require(launch[:3]==(b'M4BOOT01',bytes.fromhex(meta['nonce']),1) and launch[3:6]==(3,0,0) and launch[7]==0 and launch[8]>0 and launch[8]==launch[9] and launch[10]==0,'Bootstrap rejected')
        ready=decode(poll('ready',RESULT.size),meta)
        require(ready['phase']==1 and ready['error']==0 and ready['euid']==0 and ready['ppid']==1 and ready['cleanup']==0 and ready['loader_pid']==launch[6],'Readiness failed')
        write('start',b'M4START1'+bytes.fromhex(meta['nonce'])+struct.pack('<Q',1))
        for i,(name,minor,size) in enumerate(TARGETS):
            native=decode(poll(f'part{i}',RESULT.size,180),meta);report['native']=native
            count=(size+32767)//32768
            require(native['phase']==4 and native['error']==0 and native['index']==i and native['bytes']==size and native['chunks']==count and native['flags']==127 and native['first_sha256']==native['second_sha256'],'Partition consistency rejected')
            hashes=read(f'digests{i}',count*32);require(len(hashes)==count*32,'Partial chunk digests')
            full=hashlib.sha256();dest=evidence/(name+'.bin')
            with dest.open('xb') as f:
                for j in range(count):
                    length=min(32768,size-j*32768);raw=read(f't{i}c{j:04d}',length)
                    require(len(raw)==length and hashlib.sha256(raw).digest()==hashes[j*32:(j+1)*32],'Chunk corruption')
                    f.write(raw);full.update(raw)
                    if j%64==0:print(json.dumps({'partition':name,'bytes':min((j+1)*32768,size),'total':size}),flush=True)
                f.flush();os.fsync(f.fileno())
            require(full.hexdigest()==native['first_sha256'] and sha(dest)==full.hexdigest(),'Host full-image readback mismatch')
            report['partitions'][name]={'bytes':size,'sha256':full.hexdigest(),'two_source_reads_equal':True,'host_readback_verified':True};save(evidence/'run.json',report)
            write(f'ack{i}',b'M4ACK001'+bytes.fromhex(meta['nonce'])+struct.pack('<Q',i+1))
            cleaned=decode(poll(f'cleaned{i}',RESULT.size),meta);require(cleaned['phase']==5 and not cleaned['error'] and not cleaned['cleanup'],'RAM cleanup failed')
        final=decode(poll('result',RESULT.size),meta);require(final['phase']==6 and not final['error'],'Final backup status failed')
        for name,cap in [('mountinfo',131072),('loader_maps',524288),('loader_fds',131072)]:
            raw=read(name,cap);(evidence/name).write_bytes(raw)
        require(readpath('/tmp/jiritsu/libJit.so',65520,True) is None,'Module cleanup missing')
        report['verdict']='FIVE_PARTITION_BACKUPS_VERIFIED';report['final_native']=final
    try:
        senserShellCommand(complete=complete);require(report['verdict']=='FIVE_PARTITION_BACKUPS_VERIFIED','No successful callback')
    except BaseException as e:
        report['error']={'type':type(e).__name__,'message':str(e)};raise
    finally:save(evidence/'run.json',report)
    print(json.dumps({'verdict':report['verdict'],'evidence':str(evidence),'block_writes':False}),flush=True)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=['prepare','run']);p.add_argument('--job',type=Path,required=True);p.add_argument('--test-only',action='store_true');a=p.parse_args()
    if a.action=='prepare':prepare(a.job.resolve(),a.test_only)
    else:
        code=0
        try:run(a.job.resolve())
        except BaseException:
            import traceback
            traceback.print_exc();code=1
        sys.stdout.flush();sys.stderr.flush();os._exit(code)
