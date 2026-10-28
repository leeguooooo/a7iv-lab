"""Collect the fixed existing /cp/nor_ldr.img file, not physical NOR.

The updater-generated cache may differ from physical flash. This tool does
not initialize a flash controller, load CP code, issue MP commands or save
settings. It never accepts an arbitrary device-side path.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import time

from a7m4.fl23 import bk4_rows
from camera_inventory import ROOT, require, save

PATH='/cp/nor_ldr.img'
LIMIT=64*1024*1024
RECEIPT=ROOT/'output/cached-nor-reader-review-01/tests.json'


def digest(b):return hashlib.sha256(b).hexdigest()


def parse_file_response(status,raw,limit=LIMIT):
    raw=bytes(raw or b'')
    require(status==0 and len(raw)>=4,'Malformed fixed cache response')
    code=struct.unpack_from('<I',raw)[0]
    require(code==0,'Cache read failed; no alternate paths or retry')
    require(0<len(raw)-4<=limit,'Cache size outside the reviewed bound')
    return raw[4:]


def read_cache(camera,expected_identity,report,publish):
    report['pending_request']='body-identity-read';publish()
    require(bytes(camera.readBackup(0x00e70003))==expected_identity,'Service identity differs')
    report['pending_request']='select-cache';publish()
    status,raw=camera.dev.sendSenserPacket(0x40,struct.pack('<HH',0x1001,15)+b'\0'+('/tmp/jiritsu/../..'+PATH).encode()+b'\0')
    require(status==0 and bytes(raw or b'')==bytes(4),'Cache selection failed; stop')
    report['pending_request']='get-cache';publish()
    status,raw=camera.dev.sendSenserPacket(0x40,struct.pack('<HH',0x1001,17)+b'\0\xff\0')
    data=parse_file_response(status,raw)
    report['pending_request']=None;report['cache_bytes']=len(data);report['cache_sha256']=digest(data);publish()
    return data


def self_test():
    class Fake:
        def __init__(self,kind):self.dev=self;self.kind=kind;self.calls=[]
        def readBackup(self,key):
            assert key==0x00e70003
            return b'wrong' if self.kind=='wrong_body' else b'identity'
        def sendSenserPacket(self,function,payload):
            assert function==0x40
            group,command=struct.unpack_from('<HH',payload)
            assert group==0x1001 and command in (15,17),'Unexpected mutation or request'
            self.calls.append(command)
            if command==15:
                assert payload[4:]==b'\0/tmp/jiritsu/../../cp/nor_ldr.img\0'
                return (1,b'') if self.kind=='bad_select' else (0,bytes(4))
            assert payload[4:]==b'\0\xff\0'
            if self.kind=='transport':raise OSError('synthetic read failure')
            if self.kind=='missing':return 0,struct.pack('<I',0x10000006)
            if self.kind=='short_header':return 0,b'xx'
            if self.kind=='outer_error':return 1,bytes(4)+b'bad'
            return 0,bytes(4)+b'EXBL synthetic cache'
    rows=[]
    for kind in ['success','wrong_body','bad_select','transport','missing','short_header','outer_error']:
        camera=Fake(kind);report={};error=None
        try:data=read_cache(camera,b'identity',report,lambda:None)
        except Exception as exc:error=type(exc).__name__
        assert (error is None)==(kind=='success')
        assert camera.calls==([] if kind=='wrong_body' else [15] if kind=='bad_select' else [15,17])
        rows.append({'case':kind,'passed':True,'file_commands':camera.calls})
    try:parse_file_response(0,bytes(4)+bytes(65),limit=64)
    except RuntimeError:pass
    else:raise AssertionError('Oversize response accepted')
    rows.append({'case':'oversize_bound','passed':True})
    RECEIPT.parent.mkdir(exist_ok=True)
    save(RECEIPT,{'all_passed':True,'tests':rows,'source_sha256':digest(Path(__file__).read_bytes()),
                  'hardware_io':False,'scope':'fixed existing file read protocol/failure checks, not device validation'})
    print(json.dumps({'all_passed':True,'cases':len(rows),'hardware_io':False}))


def collect(out):
    require(not out.exists(),'Use a fresh one-shot path; never retry an unknown outcome')
    tests=json.loads(RECEIPT.read_text())
    require(tests['all_passed'] and len(tests['tests'])==8 and tests['source_sha256']==digest(Path(__file__).read_bytes()),'Current source has no matching checks')
    require(json.load(open(ROOT/'output/rea-study/nor-probe-hold.json'))['enabled'] is True,'NOR hold must stay enabled')
    metadata=json.load(open(ROOT/'output/boot-selection-metadata-01/completion.json'))
    require(metadata['cp_cached_nor_image_name']==['nor_ldr.img'],'Fixed file was not observed in directory metadata')
    baseline=ROOT/'output/backup-01/execution'
    original=(baseline/'backup_preset.fresh.bin').read_bytes()
    recs=[row['records'][0x00e70003] for row in bk4_rows(original) if 0x00e70003 in row['records']]
    require(len(recs)==1,'Original identity is ambiguous');rec=recs[0]
    identity=original[rec['offset']:rec['offset']+rec['size']]
    expected=json.load(open(baseline/'run.json'))['body']['usb_serial_sha256']
    sys.path.insert(0,str(ROOT/'Sony-PMCA-RE'))
    import usb.core,usb.util,usb.backend.libusb1
    backend=usb.backend.libusb1.get_backend(find_library=lambda _: '/opt/homebrew/lib/libusb-1.0.dylib')
    devices=list(usb.core.find(find_all=True,idVendor=0x054c,idProduct=0x0da5,backend=backend))
    require(len(devices)==1 and devices[0].product=='ILCE-7M4','Exactly one normal MSC M4 required')
    require(bool(devices[0].serial_number) and digest(devices[0].serial_number.encode())==expected,'USB identity differs')
    usb.util.dispose_resources(devices[0])
    from pmca.commands.usb import senserShellCommand
    from pmca.platform.backend.senser import SenserPlatformBackend
    out.mkdir(parents=True,mode=0o700)
    report={'started':time.time(),'verdict':'NOT_STARTED','cache_path':PATH,'kind':'existing updater-generated image cache, NOT physical NOR readback',
            'nor_commands':0,'save_requests':0,'settings_write_requests':0,'module_uploads':0,
            'physical_mapping':False,'cp_code_loads':0,'automatic_retry':False,
            'source_sha256':digest(Path(__file__).read_bytes()),'ready_to_flash':False}
    def publish():save(out/'run.json',report)
    publish()
    def complete(camera):
        SenserPlatformBackend(camera).start()
        data=read_cache(camera,identity,report,publish)
        target=out/'cached-nor-image.bin';target.write_bytes(data);target.chmod(0o600)
        require(digest(target.read_bytes())==report['cache_sha256'],'Host file readback differs')
        report['verdict']='EXISTING_CACHE_COLLECTED_NOT_NOR_DUMP';publish()
    try:
        senserShellCommand(complete=complete)
        require(report['verdict']=='EXISTING_CACHE_COLLECTED_NOT_NOR_DUMP','No completed callback')
    except BaseException as error:
        report['error']={'type':type(error).__name__,'message':str(error)};raise
    finally:publish()
    print(json.dumps({k:report[k] for k in ['verdict','cache_bytes','cache_sha256','nor_commands','module_uploads','ready_to_flash']}))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--self-test',action='store_true');p.add_argument('--collect',action='store_true');p.add_argument('--output',type=Path)
    a=p.parse_args();os.umask(0o077)
    if a.self_test:self_test()
    elif not a.collect:print(json.dumps({'path':PATH,'maximum_bytes':LIMIT,'kind':'cached image only','device_commands':['identity READ','SELECT15','GET_FILE2 17']}))
    else:
        require(a.output is not None,'Choose a fresh output path');code=0
        try:collect(a.output.resolve())
        except BaseException:
            import traceback
            traceback.print_exc();code=1
        finally:sys.stdout.flush();sys.stderr.flush()
        os._exit(code)
