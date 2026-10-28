"""Read fresh M4 colour snapshots without WRITE41, SAVE3 or a native upload.

Only fixed existing files, proven preset READ5(mode1), unit READ40(chip1),
body identity READ and Jiritsu SELECT/GET_FILE2 are used. Returned config
strings are never followed. A failed/unknown request ends the capture.
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

GROUP = 0x02a4
KEYS = tuple((GROUP << 16) | n for n in range(19))
CP_PATH = '/cp/cpapp-b.bin'
CP_SHA = '7b9b137d696e5972d20db7f9119076172ed8e0730805d7f0b4c31b87689e2c2b'
FIXED_FILES = {
    CP_PATH: (16236816, 'cp.identity.bin'),
    '/setting/Backup.bin': (8*1024*1024, 'backup-primary.bin'),
    '/setting/Backup.bak': (8*1024*1024, 'backup-secondary.bin'),
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def group_records(data):
    rows = bk4_rows(data)
    found = {}
    for chip, row in enumerate(rows):
        for key, rec in row['records'].items():
            if key >> 16 == GROUP:
                require(chip == 1, 'Colour group appeared in an unexpected chip')
                require(key not in found, 'Duplicate colour key')
                found[key] = (rec['attrs'], data[rec['offset']:rec['offset']+rec['size']])
    require(tuple(sorted(found)) == KEYS, 'Unexpected colour group inventory')
    require(len(found[0x02a40001][1]) == 8192 and len(found[0x02a4000d][1]) == 28672,
            'Colour unit lengths changed')
    return found


class FixedReader:
    def __init__(self, camera, report, publish):
        self.camera, self.report, self.publish = camera, report, publish
        self.healthy = True

    def request(self, label, action):
        require(self.healthy, 'An earlier outcome is unknown; stop')
        self.report['pending_request'] = label
        self.publish()
        try:
            result = action()
        except BaseException:
            self.healthy = False
            raise
        self.report['completed_requests'].append(label)
        self.report['pending_request'] = None
        self.publish()
        return result

    def fixed_file(self, path):
        require(path in FIXED_FILES, 'File path is not allowlisted')
        limit, _ = FIXED_FILES[path]
        def select():
            status, raw = self.camera.dev.sendSenserPacket(
                0x40, struct.pack('<HH',0x1001,15)+b'\0'+('/tmp/jiritsu/../..'+path).encode()+b'\0')
            require(status == 0 and bytes(raw or b'') == bytes(4), 'Fixed file select failed')
        self.request('select:'+path, select)
        def read():
            status, raw = self.camera.dev.sendSenserPacket(0x40, struct.pack('<HH',0x1001,17)+b'\0\xff\0')
            raw = bytes(raw or b'')
            require(status == 0 and len(raw) >= 4, 'Malformed fixed file response')
            require(struct.unpack_from('<I',raw)[0] == 0, 'Fixed file read failed; do not retry')
            require(0 < len(raw)-4 <= limit, 'Fixed file length outside reviewed bound')
            return raw[4:]
        return self.request('get:'+path, read)

    def preset(self, label):
        data = bytes(self.request(label, lambda: self.camera.getBackupPresetData(True)))
        require(1024*1024 <= len(data) <= 8*1024*1024, 'Preset length outside expected bound')
        group_records(data)
        return data

    def unit(self, key, length):
        require(key in KEYS, 'Unit key not allowlisted')
        data = bytes(self.request(f'READ40:{key:08x}', lambda:
            self.camera._sendAdjustControlPacket(0x0603,0x40,struct.pack('<II',key,1))))
        require(len(data) == length, 'Partial or changed-size colour unit')
        return data


def capture(camera, out, report, original):
    def publish():
        save(out/'run.json', report)
    reader = FixedReader(camera, report, publish)
    serial = [row['records'][0x00e70003] for row in bk4_rows(original) if 0x00e70003 in row['records']]
    require(len(serial) == 1, 'Original service identity ambiguous')
    rec = serial[0]
    actual = bytes(reader.request('body-identity-read', lambda: camera.readBackup(0x00e70003)))
    require(actual == original[rec['offset']:rec['offset']+rec['size']], 'Service identity differs')
    cp = reader.fixed_file(CP_PATH)
    require(digest(cp) == CP_SHA and len(cp) == 16236816, 'Current CP differs from reviewed stock')
    report['cp_sha256'] = digest(cp)
    # Program identity only: do not save an unnecessary second proprietary dump.
    del cp
    snapshots = {}
    before = reader.preset('PDT_READ-memory-before')
    (out/'preset-memory-before.bin').write_bytes(before)
    snapshots['memory_before'] = group_records(before)
    for path in ['/setting/Backup.bin','/setting/Backup.bak']:
        data = reader.fixed_file(path)
        (out/FIXED_FILES[path][1]).write_bytes(data)
        snapshots[path] = group_records(data)
        report.setdefault('file_sha256', {})[path] = digest(data)
    direct = {}
    for key in KEYS:
        attrs, prior = snapshots['memory_before'][key]
        data = reader.unit(key, len(prior))
        (out/f'cp-unit-{key:08x}.bin').write_bytes(data)
        direct[key] = (attrs, data)
    after = reader.preset('PDT_READ-memory-after')
    (out/'preset-memory-after.bin').write_bytes(after)
    snapshots['memory_after'] = group_records(after)
    snapshots['direct_cp_reads'] = direct
    stable = snapshots['memory_before'] == snapshots['memory_after'] == direct
    comparisons = {}
    for name, records in snapshots.items():
        comparisons[name] = {
            'different_from_memory': [f'{key:08x}' for key in KEYS if records[key] != direct[key]],
            'records': {f'{key:08x}': {'attrs': value[0], 'size': len(value[1]), 'sha256': digest(value[1])}
                        for key, value in records.items()},
        }
    save(out/'group-comparison.private.json', comparisons)
    report.update(colour_group_stable_during_capture=stable, records_per_snapshot=19,
                  direct_read_attributes_source='memory-before preset; READ40 returns data only',
                  snapshot_kind='existing files and RAM, not an atomic or power-loss durability proof',
                  verdict='READ_CAPTURE_COMPLETE' if stable else 'READ_CAPTURE_COMPLETE_GROUP_CHANGED',
                  ready_to_write=False)
    publish()
    return report


def collect(out):
    require(not out.exists(), 'Use a new one-shot output; never overwrite or retry')
    test_path = ROOT/'output/color-snapshot-review-01/tests.json'
    require(test_path.exists(), 'Offline protocol and failure checks must pass first')
    tests = json.loads(test_path.read_text())
    require(tests.get('passed') is True and tests.get('cases',0) >= 8
            and tests.get('source_sha256') == digest(Path(__file__).read_bytes()),
            'Test receipt does not cover the current source')
    config = ROOT/'output/backup-config-01'
    require(json.load(open(config/'completion.json'))['verdict'] == 'BACKUP_CONFIG_AND_CLEANUP_VERIFIED',
            'Runtime backup configuration was not captured')
    require(all((config/'execution'/name).read_text().strip() == '/setting/Backup.bin'
                for name in ('backup_primary','backup_secondary')), 'Reviewed backup configuration differs')
    hold = json.load(open(ROOT/'output/rea-study/nor-probe-hold.json'))
    require(hold.get('enabled') is True, 'NOR hold must remain enabled')
    baseline = ROOT/'output/backup-01/execution'
    expected = json.load(open(baseline/'run.json'))['body']['usb_serial_sha256']
    original = (baseline/'backup_preset.fresh.bin').read_bytes()
    group_records(original)
    sys.path.insert(0,str(ROOT/'Sony-PMCA-RE'))
    import usb.core, usb.util, usb.backend.libusb1
    backend = usb.backend.libusb1.get_backend(find_library=lambda _: '/opt/homebrew/lib/libusb-1.0.dylib')
    devices = list(usb.core.find(find_all=True,idVendor=0x054c,idProduct=0x0da5,backend=backend))
    require(len(devices) == 1 and devices[0].product == 'ILCE-7M4', 'One normal MSC M4 required')
    require(bool(devices[0].serial_number) and digest(devices[0].serial_number.encode()) == expected,
            'USB identity differs')
    usb.util.dispose_resources(devices[0])
    from pmca.commands.usb import senserShellCommand
    from pmca.platform.backend.senser import SenserPlatformBackend
    out.mkdir(parents=True,mode=0o700)
    report = {'started':time.time(),'verdict':'PREFLIGHT','completed_requests':[],
              'nor_requests':0,'module_uploads':0,'settings_write_requests':0,'save_requests':0,
              'block_reads':False,'block_writes':False,'automatic_retry':False,
              'source_sha256':digest(Path(__file__).read_bytes())}
    save(out/'run.json',report)
    def complete(camera):
        SenserPlatformBackend(camera).start()
        capture(camera,out,report,original)
    try:
        senserShellCommand(complete=complete)
        require(report['verdict'].startswith('READ_CAPTURE_COMPLETE'), 'Capture callback did not complete')
    except BaseException as error:
        report['error']={'type':type(error).__name__,'message':str(error)}
        raise
    finally:
        save(out/'run.json',report)
    print(json.dumps({k:report[k] for k in ['verdict','records_per_snapshot','colour_group_stable_during_capture','nor_requests','settings_write_requests','save_requests']}))


if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--collect',action='store_true')
    p.add_argument('--output',type=Path)
    a=p.parse_args()
    if not a.collect:
        print(json.dumps({'fixed_files':list(FIXED_FILES),'unit_read_count':19,
                          'preset_reads':2,'settings_write_requests':0,'save_requests':0,'nor_requests':0}))
    else:
        require(a.output is not None, 'Choose a fresh output path')
        os.umask(0o077)
        code=0
        try:collect(a.output.resolve())
        except BaseException:
            import traceback
            traceback.print_exc()
            code=1
        finally:sys.stdout.flush();sys.stderr.flush()
        os._exit(code)
