"""Collect a fresh preset and a fixed existing driver log file. No export/erase.

Only the proven preset-read and Jiritsu select/GET_FILE2 paths are used.
Raw data and record deltas remain private. No arbitrary user path is accepted.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import time

from camera_inventory import ROOT,require,save
from a7m4.fl23 import bk4_rows


def records(data):
    return {(chip,key):(rec['attrs'],data[rec['offset']:rec['offset']+rec['size']])
            for chip,row in enumerate(bk4_rows(data)) for key,rec in row['records'].items()}


def collect(out):
    require(not out.exists(),'Choose a new one-shot directory; never overwrite/retry an unknown attempt')
    hold=json.loads((ROOT/'output/rea-study/nor-probe-hold.json').read_text());require(hold.get('enabled') is True,'NOR probe hold must remain active')
    sys.path.insert(0,str(ROOT/'Sony-PMCA-RE'))
    import usb.core,usb.util,usb.backend.libusb1
    backend=usb.backend.libusb1.get_backend(find_library=lambda _:'/opt/homebrew/lib/libusb-1.0.dylib')
    ds=list(usb.core.find(find_all=True,idVendor=0x054c,idProduct=0x0da5,backend=backend));require(len(ds)==1 and ds[0].product=='ILCE-7M4','One normal MSC A7M4 required')
    serial=ds[0].serial_number;require(bool(serial),'Normal identity unavailable');binding=hashlib.sha256(serial.encode()).hexdigest();usb.util.dispose_resources(ds[0])
    baseline=ROOT/'output/backup-01/execution';expected=json.loads((baseline/'run.json').read_text())['body']['usb_serial_sha256'];require(binding==expected,'Body differs from backed-up camera')
    old=(baseline/'backup_preset.fresh.bin').read_bytes();before=records(old)
    from pmca.commands.usb import senserShellCommand
    from pmca.platform.backend.senser import SenserPlatformBackend
    out.mkdir(parents=True);report={'started':time.time(),'nor_requests':0,'module_uploads':0,'explicit_file_writes':0,'settings_write_requests':0,'automatic_retry':False,'verdict':'PREFLIGHT'};save(out/'run.json',report)
    def complete(camera):
        b=SenserPlatformBackend(camera);b.start()
        rs=[r['records'][0x00e70003] for r in bk4_rows(old) if 0x00e70003 in r['records']];require(len(rs)==1,'Ambiguous original serial');r=rs[0]
        require(bytes(camera.readBackup(0x00e70003))==old[r['offset']:r['offset']+r['size']],'Service body identity changed')
        data=bytes(b.getBackupData());require(1024*1024<=len(data)<=8*1024*1024,'Preset size outside expected bound');after=records(data)
        (out/'backup_preset.after.bin').write_bytes(data)
        delta=[]
        for key in sorted(before.keys()|after.keys()):
            a=before.get(key);z=after.get(key)
            if a==z:continue
            item={'chip':key[0],'id':f'{key[1]:08x}','old_size':len(a[1]) if a else None,'new_size':len(z[1]) if z else None,
                  'old_attrs':a[0] if a else None,'new_attrs':z[0] if z else None}
            if a:item['old_sha256']=hashlib.sha256(a[1]).hexdigest()
            if z:item['new_sha256']=hashlib.sha256(z[1]).hexdigest()
            if a and z and len(a[1])==len(z[1]):item['changed_bytes']=sum(x!=y for x,y in zip(a[1],z[1]))
            delta.append(item)
        save(out/'preset-record-deltas.private.json',delta)
        report.update(preset_sha256=hashlib.sha256(data).hexdigest(),record_count=len(after),changed_record_count=len(delta),preset_checksums_valid=True)
        save(out/'run.json',report)
        path='/tmp/kikilog.dat';payload=struct.pack('<HH',0x1001,15)+b'\0'+('/tmp/jiritsu/../..'+path).encode()+b'\0'
        res,raw=camera.dev.sendSenserPacket(0x40,payload);raw=bytes(raw or b'');require(res==0 and raw==bytes(4),'Log path selection failed')
        res,raw=camera.dev.sendSenserPacket(0x40,struct.pack('<HH',0x1001,17)+b'\0\xff\0');raw=bytes(raw or b'');require(res==0 and len(raw)>=4,'Malformed fixed-file response')
        code=struct.unpack_from('<I',raw)[0]
        report['driver_file']={'path':path,'camera_status':hex(code)}
        if code==0:
            data=raw[4:];require(len(data)<=0x408000,'Existing driver log exceeds reviewed size')
            (out/'kikilog.existing.bin').write_bytes(data);report['driver_file'].update(bytes=len(data),sha256=hashlib.sha256(data).hexdigest())
        elif code!=0x10000006:raise RuntimeError(f'Fixed log file read status {code:#x}; no retries')
        report['verdict']='EXISTING_FAULT_DATA_COLLECTED'
    try:
        senserShellCommand(complete=complete);require(report['verdict']=='EXISTING_FAULT_DATA_COLLECTED','No successful callback')
    except BaseException as error:
        report['error']={'type':type(error).__name__,'message':str(error)};raise
    finally:save(out/'run.json',report)
    print(json.dumps({k:report.get(k) for k in ['verdict','record_count','changed_record_count','driver_file','nor_requests','module_uploads']},indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--collect',action='store_true');p.add_argument('--output',type=Path);a=p.parse_args()
    if not a.collect:print(json.dumps({'paths':['preset from memory','/tmp/kikilog.dat'],'nor_requests':0,'settings_write_requests':0,'automatic_retry':False}))
    else:
        require(a.output is not None,'Choose a fresh output directory');os.umask(0o077);code=0
        try:collect(a.output.resolve())
        except BaseException:
            import traceback
            traceback.print_exc();code=1
        sys.stdout.flush();sys.stderr.flush();os._exit(code)
