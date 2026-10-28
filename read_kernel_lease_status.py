"""Read only fixed metadata from the already-authorized resident lease module.

No module upload/load/unload or guest program exists in this reader. The
existing Jiritsu file protocol is restricted to select/read commands15/17.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import sys

ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'ref/sony-a7m4-custom-firmware'))
sys.path.insert(0,str(ROOT/'Sony-PMCA-RE'))
from a7m4.fl23 import bk4_rows
from camera_inventory import require

FILES={
    'initstate':'/sys/module/m4btl_lease_01/initstate',
    'status':'/sys/module/m4btl_lease_01/parameters/status',
    'nonce':'/sys/module/m4btl_lease_01/parameters/nonce',
    'state':'/sys/module/m4btl_lease_01/parameters/state',
    'bytes':'/sys/module/m4btl_lease_01/parameters/bytes',
    'phys':'/sys/module/m4btl_lease_01/parameters/phys',
}


def main(out):
    require(sys.platform!='darwin' or os.geteuid()==0,'macOS file access requires sudo')
    require(not out.exists(),'Choose a new read receipt; never overwrite an observation')
    job=ROOT/'output/kernel-lease-OFFLINE-05'
    prior=json.loads((job/'execution/run.json').read_text())
    require(prior['lease']['attempts']==1 and prior['lease']['load_return']==0,'No matching successful authorized load call')
    manifest=json.loads((ROOT/'output/pcidma-OFFLINE_LEASE_ONLY-02/manifest.json').read_text())
    out.mkdir(mode=0o700,parents=True)
    report={'scope':'fixed resident metadata only','kernel_loads':0,'module_uploads':0,'DMA':0,'NOR':0,'files':{},'verdict':'NOT_READ'}
    def save():
        p=out/'report.json';p.write_text(json.dumps(report,indent=2)+'\n');p.chmod(0o600)
    import usb.core,usb.util,usb.backend.libusb1
    backend=usb.backend.libusb1.get_backend(find_library=lambda _: '/opt/homebrew/lib/libusb-1.0.dylib')
    ds=list(usb.core.find(find_all=True,idVendor=0x054c,idProduct=0x0da5,backend=backend))
    require(len(ds)==1 and ds[0].product=='ILCE-7M4','Exactly one normal MSC M4 required')
    require(hashlib.sha256(ds[0].serial_number.encode()).hexdigest()==prior['body']['usb_serial_sha256'],'USB body changed')
    usb.util.dispose_resources(ds[0])
    original=(ROOT/'dumps/20261026-031555/backup_preset.bin').read_bytes()
    records=[r['records'][0x00e70003]for r in bk4_rows(original)if 0x00e70003 in r['records']]
    require(len(records)==1,'Body binding ambiguous');record=records[0]
    expected=original[record['offset']:record['offset']+record['size']]
    from pmca.commands.usb import senserShellCommand
    from pmca.platform.backend.senser import SenserPlatformBackend
    def collect(camera):
        SenserPlatformBackend(camera).start()
        require(bytes(camera.readBackup(0x00e70003))==expected,'Service body changed')
        for name,path in FILES.items():
            report['pending']=name;save()
            outer,raw=camera.dev.sendSenserPacket(0x40,struct.pack('<HH',0x1001,15)+b'\0'+('/tmp/jiritsu/../..'+path).encode()+b'\0')
            require(outer==0 and bytes(raw or b'')==bytes(4),'Metadata selection failed; stop')
            outer,raw=camera.dev.sendSenserPacket(0x40,struct.pack('<HH',0x1001,17)+b'\0\xff\0')
            raw=bytes(raw or b'');require(outer==0 and len(raw)>=4,'Read transport failed; stop')
            code=struct.unpack_from('<I',raw)[0];report['files'][name]={'service_status':code,'bytes':len(raw)-4};save()
            require(code==0 and 0<len(raw)-4<=4096,'Fixed metadata read failed; no alternate paths or retry')
            data=raw[4:];p=out/name;p.write_bytes(data);p.chmod(0o600)
            report['files'][name]['sha256']=hashlib.sha256(data).hexdigest();save()
        report.pop('pending',None)
    try:
        senserShellCommand(complete=collect)
        require((out/'initstate').read_bytes()==b'live\n','Resident module is not live')
        nonce=manifest['module_nonce']
        pattern=rb'schema=1 profile=lease-only nonce='+nonce.encode()+rb' state=ready page_bytes=4096 page_phys=0x([0-9a-f]{1,16}) resident=boot dma=0\n\n'
        match=re.fullmatch(pattern,(out/'status').read_bytes());require(match is not None,'Raw metadata fields/known sysfs double-LF contract mismatch')
        phys=int(match.group(1),16);require(0x400000000<=phys<=0x4fffff000 and phys%4096==0,'Resident page out of range')
        require((out/'nonce').read_bytes()==nonce.encode()+b'\n\n' and (out/'state').read_bytes()==b'2\n\n' and (out/'bytes').read_bytes()==b'4096\n\n','Independent metadata fields disagree')
        require((out/'phys').read_bytes()==hex(phys).encode()+b'\n\n','Independent physical metadata disagrees')
        report.update(verdict='RESIDENT_LEASE_METADATA_VERIFIED',page_phys=phys,resident_until='reboot',raw_sysfs_final_LF_bytes=2)
    except BaseException as e:
        report['error']={'type':type(e).__name__,'message':str(e)}
        raise
    finally:save()
    print(json.dumps({'verdict':report['verdict'],'kernel_loads':0,'module_uploads':0,'files_read':len(report['files'])}))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    rc=0
    try:main(a.out.resolve())
    except BaseException:
        import traceback;traceback.print_exc();rc=1
    finally:sys.stdout.flush();sys.stderr.flush()
    os._exit(rc)
