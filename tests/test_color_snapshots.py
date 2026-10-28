"""Exercise the fixed USB read protocol with real captured BK4/FAT inputs.

No USB library/backend or camera is opened. Fake transport rejects every
packet except the small, explicit identity/file/unit/preset read allowlist.
"""
import json
import struct
from pathlib import Path

import pytest
from a7m4.fat import Fat
from a7m4.fl23 import bk4_rows
import collect_color_snapshots as m


@pytest.fixture(scope='module')
def originals():
    root=Path(__file__).resolve().parents[1]
    preset=(root/'output/backup-01/execution/backup_preset.fresh.bin').read_bytes()
    fs=Fat((root/'output/backup-01/execution/cnflasha2.bin').read_bytes())
    cp=(root/'dumps/20261026-032053-probe3/cp_cpapp-b.bin').read_bytes()
    assert m.digest(cp)==m.CP_SHA
    return preset,fs.read('BACKUP.BIN'),fs.read('BACKUP.BAK'),cp


def change_record(data,key=0x02a40002):
    result=bytearray(data)
    for row in bk4_rows(data):
        if key not in row['records']:continue
        rec=row['records'][key]
        assert rec['size']>0
        result[rec['offset']]^=1
        base=row['base']
        extent=struct.unpack_from('<I',result,base+0x18)[0]+struct.unpack_from('<I',result,base+0x1c)[0]
        checksum=(sum(result[base:base+0x20])+sum(result[base+0x24:base+extent]))&0xffffffff
        struct.pack_into('<I',result,base+0x20,checksum)
        bk4_rows(result)
        return bytes(result)
    raise AssertionError('Fixture record missing')


class FakeCamera:
    def __init__(self,originals,fault=None):
        self.preset,self.primary,self.secondary,self.cp=originals
        self.group=m.group_records(self.preset)
        self.dev=self
        self.path=None
        self.calls=[]
        self.fault=fault
        self.presets=0
        self.units=0

    def readBackup(self,key):
        assert key==0x00e70003
        self.calls.append('identity')
        rows=[x['records'][key] for x in bk4_rows(self.preset) if key in x['records']]
        assert len(rows)==1
        rec=rows[0]
        return self.preset[rec['offset']:rec['offset']+rec['size']]

    def getBackupPresetData(self,from_memory):
        assert from_memory is True
        self.calls.append('preset')
        self.presets+=1
        if self.fault=='group_changed' and self.presets==2:return change_record(self.preset)
        return self.preset

    def _sendAdjustControlPacket(self,block,command,payload):
        assert block==0x0603 and command==0x40, 'WRITE/SAVE or unknown command'
        assert len(payload)==8
        key,chip=struct.unpack('<II',payload)
        assert key in m.KEYS and chip==1
        self.calls.append(f'unit:{key:08x}')
        self.units+=1
        value=self.group[key][1]
        if self.fault=='short_unit' and self.units==3:return value[:-1]
        return value

    def sendSenserPacket(self,function,payload):
        assert function==0x40 and len(payload)>=4
        group,command=struct.unpack_from('<HH',payload)
        assert group==0x1001 and command in (15,17), 'Mutation or unknown command'
        if command==15:
            assert payload[4:5]==b'\0' and payload[-1:]==b'\0'
            path=payload[5:-1].decode()
            assert path.startswith('/tmp/jiritsu/../..')
            path=path[len('/tmp/jiritsu/../..'):]
            assert path in m.FIXED_FILES
            self.path=path
            self.calls.append('select:'+path)
            return 0,bytes(4)
        assert payload[4:]==b'\0\xff\0' and self.path
        self.calls.append('get:'+self.path)
        if self.path.endswith('.bak') and self.fault=='transport_error':raise OSError('synthetic transfer failure')
        data={m.CP_PATH:self.cp,'/setting/Backup.bin':self.primary,'/setting/Backup.bak':self.secondary}[self.path]
        if self.path==m.CP_PATH and self.fault=='wrong_cp':data=data[:-1]+bytes([data[-1]^1])
        if self.path=='/setting/Backup.bin' and self.fault=='dirty_disk':data=change_record(data)
        if self.path.endswith('.bak') and self.fault=='bad_checksum':data=data[:-1]+bytes([data[-1]^1])
        return 0,bytes(4)+data


def perform(tmp_path,originals,fault=None):
    camera=FakeCamera(originals,fault)
    report={'completed_requests':[],'verdict':'PREFLIGHT'}
    result=m.capture(camera,tmp_path,report,originals[0])
    return camera,result,json.loads((tmp_path/'group-comparison.private.json').read_text())


def test_full_capture_is_fixed_read_protocol(tmp_path,originals):
    camera,result,groups=perform(tmp_path,originals)
    assert result['verdict']=='READ_CAPTURE_COMPLETE' and result['colour_group_stable_during_capture']
    assert camera.units==19 and camera.presets==2
    assert len(list(tmp_path.glob('cp-unit-*.bin')))==19
    assert all(not g['different_from_memory'] for g in groups.values())
    assert result['ready_to_write'] is False


def test_dirty_disk_is_recorded_without_save(tmp_path,originals):
    camera,result,groups=perform(tmp_path,originals,'dirty_disk')
    assert groups['/setting/Backup.bin']['different_from_memory']==['02a40002']
    assert result['ready_to_write'] is False and camera.units==19


def test_changes_during_capture_are_not_called_stable(tmp_path,originals):
    camera,result,groups=perform(tmp_path,originals,'group_changed')
    assert result['verdict']=='READ_CAPTURE_COMPLETE_GROUP_CHANGED'
    assert not result['colour_group_stable_during_capture']
    assert groups['memory_after']['different_from_memory']==['02a40002']


@pytest.mark.parametrize('fault',['wrong_cp','short_unit','bad_checksum','transport_error'])
def test_failed_read_stops_sequence(tmp_path,originals,fault):
    camera=FakeCamera(originals,fault)
    report={'completed_requests':[],'verdict':'PREFLIGHT'}
    with pytest.raises(Exception):m.capture(camera,tmp_path,report,originals[0])
    assert report['verdict']=='PREFLIGHT'
    if fault=='short_unit':assert camera.units==3 and camera.presets==1
    else:assert camera.units==0 and camera.presets<=1
    assert not (tmp_path/'group-comparison.private.json').exists()


def test_arbitrary_path_is_rejected_before_transport(tmp_path,originals):
    camera=FakeCamera(originals)
    reader=m.FixedReader(camera,{'completed_requests':[]},lambda:None)
    with pytest.raises(RuntimeError):reader.fixed_file('/dev/mem')
    assert not camera.calls
