"""Describe or explicitly issue ONE 32-byte NOR header read; never write NOR.

6.02 CP dispatcher at 0x4d4bf0: category 0x060b, code 1 DEBUG_NOR_READ.
The host-to-CP forwarding is still a hypothesis until a real read succeeds.
No native upload, direct SPI access, memory patch, save or firmware update.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import time

from camera_inventory import ROOT, require, save
from emulate_nor_read import SOURCE_SHA


def describe():
    return {'category':'0x060b','command':1,'address':0,'length':32,
            'adjust_control_payload_hex':struct.pack('<HHII',0x060b,1,0,32).hex(),
            'expected_result_bytes':32,'nor_write_command_in_tool':False,'automatic_retry':False,
            'source_cp_sha256':SOURCE_SHA,'forwarding_verified_on_hardware':False}


def run(out):
    require(not (ROOT/'output/rea-study/nor-probe-hold.json').exists(),
            'NOR probing is paused after an unresolved USB outcome; offline review is required')
    em=json.loads((ROOT/'output/rea-study/nor-dispatch-emulation.json').read_text())
    require(em.get('all_passed') is True and em['source_sha256']==SOURCE_SHA,'Required CP instruction emulation missing')
    require(not out.exists(),'One-shot evidence directory already exists; never resend an unknown outcome')
    sys.path.insert(0,str(ROOT/'Sony-PMCA-RE'))
    import usb.core,usb.util,usb.backend.libusb1
    backend=usb.backend.libusb1.get_backend(find_library=lambda _:'/opt/homebrew/lib/libusb-1.0.dylib')
    ds=list(usb.core.find(find_all=True,idVendor=0x054c,idProduct=0x0da5,backend=backend))
    require(len(ds)==1 and ds[0].product=='ILCE-7M4','One normal MSC A7M4 is required')
    serial=ds[0].serial_number;require(bool(serial),'USB serial missing')
    binding=hashlib.sha256(serial.encode()).hexdigest();usb.util.dispose_resources(ds[0])
    expected=json.loads((ROOT/'output/backup-01/execution/run.json').read_text())['body']['usb_serial_sha256']
    require(binding==expected,'Camera differs from the backed-up body')
    from pmca.commands.usb import senserShellCommand
    from pmca.platform.backend.senser import SenserPlatformBackend
    from a7m4.fl23 import bk4_rows
    out.mkdir(parents=True);report=describe()|{'usb_serial_sha256':binding,'nor_read_attempts':0,'nor_write_attempts':0,'module_uploads':0,'verdict':'PREFLIGHT','created_time':time.time()}
    save(out/'run.json',report)
    def complete(camera):
        SenserPlatformBackend(camera).start()
        old=(ROOT/'dumps/20261026-031555/backup_preset.bin').read_bytes()
        rs=[r['records'][0x00e70003] for r in bk4_rows(old) if 0x00e70003 in r['records']];require(len(rs)==1,'Ambiguous body AP serial')
        r=rs[0];require(bytes(camera.readBackup(0x00e70003))==old[r['offset']:r['offset']+r['size']],'Service identity changed')
        # Confirm the actual filesystem CP matches the analyzed artifact. These
        # are selection/GET_FILE2 reads only; the selection can mount Jiritsu.
        path=b'/tmp/jiritsu/../../cp/cpapp-b.bin'
        res,data=camera.dev.sendSenserPacket(0x40,struct.pack('<HH',0x1001,15)+b'\0'+path+b'\0')
        data=bytes(data or b'');require(res==0 and data==bytes(4),'CP select failed')
        res,data=camera.dev.sendSenserPacket(0x40,struct.pack('<HH',0x1001,17)+b'\0\xff\0')
        data=bytes(data or b'');require(res==0 and len(data)==16236816+4 and data[:4]==bytes(4),'CP file read failed')
        require(hashlib.sha256(data[4:]).hexdigest()==SOURCE_SHA,'CP file differs from analyzed 6.02 source')
        report['filesystem_cp_sha256_verified']=True
        report['nor_read_attempts']=1;report['verdict']='NOR_READ_REQUESTED';save(out/'run.json',report)
        result=bytes(camera._sendAdjustControlPacket(0x060b,1,struct.pack('<II',0,32)))
        (out/'nor-header.raw.bin').write_bytes(result)
        require(len(result)==32,'NOR response length differs; no retries')
        swapped=bytes(x for i in range(0,len(result),2) for x in result[i:i+2][::-1])
        (out/'nor-header.swap16.bin').write_bytes(swapped)
        report.update(verdict='NOR_HEADER_READ_RETURNED',response_sha256=hashlib.sha256(result).hexdigest(),
                      raw_header_magic=result[:4].hex(),swap16_header_magic=swapped[:4].hex(),
                      exbl_raw=result[:4]==b'EXBL',exbl_swap16=swapped[:4]==b'EXBL',
                      forwarding_verified_on_hardware=True,complete_nor_backup=False)
        # A 32-byte response, even with EXBL, is not a NOR dump or install gate.
    try:
        senserShellCommand(complete=complete);require(report['verdict']=='NOR_HEADER_READ_RETURNED','No successful read callback')
    except BaseException as e:
        report['error']={'type':type(e).__name__,'message':str(e)};raise
    finally:save(out/'run.json',report)
    print(json.dumps(report,indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--read-header',action='store_true');p.add_argument('--output',type=Path);a=p.parse_args()
    if not a.read_header:print(json.dumps(describe(),indent=2))
    else:
        require(a.output is not None,'Choose a new one-shot output directory')
        code=0
        try:run(a.output.resolve())
        except BaseException:
            import traceback
            traceback.print_exc();code=1
        sys.stdout.flush();sys.stderr.flush();os._exit(code)
