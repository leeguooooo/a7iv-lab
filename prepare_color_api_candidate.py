"""Prepare two same-body colour payloads and their rollback bytes offline.

This does not provide a device runner. It requires the completed fresh read
capture, checks all 19 group records, and exports only the two colour units.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path

from a7m4.fl23 import RECIPES, bk4_rows, patch_backup
from camera_inventory import ROOT, require, save
from collect_color_snapshots import group_records, digest

TARGETS=(0x02a40001,0x02a4000d)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--capture',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();capture=a.capture.resolve();out=a.output.resolve()
    require(not out.exists(),'Use a new candidate output')
    completion=json.loads((capture/'completion.json').read_text())
    journal=json.loads((capture/'run.json').read_text())
    require(completion['verdict']=='FRESH_COLOUR_SNAPSHOTS_VERIFIED' and completion['group_stable_during_capture'],
            'Fresh group was not stable/verified')
    require(all(not changes for changes in completion['snapshot_differences'].values()),
            'Fresh memory and file group differ; stop')
    require(journal['nor_requests']==journal['settings_write_requests']==journal['save_requests']==0,
            'Unexpected capture actions')
    before=(capture/'preset-memory-before.bin').read_bytes()
    records=group_records(before)
    inputs={'preset_memory_before':digest(before)}
    for name in ('preset-memory-after.bin','backup-primary.bin','backup-secondary.bin'):
        data=(capture/name).read_bytes();require(group_records(data)==records,'Group changed in '+name)
        inputs[name]=digest(data)
    for key,(attrs,data) in records.items():
        direct=(capture/f'cp-unit-{key:08x}.bin').read_bytes()
        require(direct==data,'Direct CP read differs')
    donor=ROOT/'local/firmware/fx2-1.01/color'
    cc=(donor/'cc1.bin').read_bytes();matrix=(donor/'block13.bin').read_bytes()
    expected=json.loads((RECIPES/'cp-v7-recipe.json').read_text())['donors']
    require(digest(cc)==expected['fx2_cc1'] and digest(matrix)==expected['fx2_block13'],'Donor identity differs')
    old_cc=records[TARGETS[0]][1];old_matrix=records[TARGETS[1]][1]
    require(old_cc[0x1236:0x123a]==bytes(4) and old_matrix[0x1cc:0x1d0]==bytes(4),
            'Target mappings are already occupied')
    for bank in (22,23,24,25):
        require(bank not in old_cc[0x1200:0x1250] and bank not in old_matrix[0x196:0x1e0],
                'A current colour mapping references a target bank')
        require(not any(old_cc[0x1250+bank*64:0x1250+bank*64+48])
                and not any(old_matrix[0x1e0+bank*768:0x1e0+bank*768+576]),'Target bank data is not free')
    modified=patch_backup(before,cc,matrix,'fixed-a1')
    after=group_records(modified)
    changed=[key for key in sorted(records) if records[key]!=after[key]]
    require(changed==list(TARGETS),'Group change set is not exactly the two target records')
    payloads={}
    for key in TARGETS:
        attrs,original=records[key];new_attrs,target=after[key]
        require(attrs==new_attrs and len(original)==len(target),'Unit metadata/length changed')
        ranges=[(0x1236,4)] if key==TARGETS[0] else [(0x1cc,4)]
        ranges += [(0x1250+bank*64,48) if key==TARGETS[0] else (0x1e0+bank*768,576) for bank in (22,23,24,25)]
        allowed={n for offset,size in ranges for n in range(offset,offset+size)}
        delta=[n for n,(x,y) in enumerate(zip(original,target)) if x!=y]
        require(delta and all(n in allowed for n in delta),'Changed bytes outside the reviewed colour windows')
        payloads[key]=(original,target,{'attrs':attrs,'bytes':len(original),'changed_bytes':len(delta),
                                     'original_sha256':digest(original),'target_sha256':digest(target),
                                     'allowed_windows':[{'offset':hex(x),'bytes':n} for x,n in ranges]})
    out.mkdir(parents=True,mode=0o700)
    for key,(original,target,meta) in payloads.items():
        (out/f'{key:08x}.original.bin').write_bytes(original)
        (out/f'{key:08x}.candidate.bin').write_bytes(target)
        require((out/f'{key:08x}.original.bin').read_bytes()==original
                and (out/f'{key:08x}.candidate.bin').read_bytes()==target,'Local payload readback differs')
    report={'schema':'camera-use-offline-colour-payloads/1','status':'BLOCKED_AUDIT_NOT_READY',
            'hardware_io':False,'device_runner_present':False,'capture':str(capture),
            'capture_inputs':inputs,'source_sha256':digest(Path(__file__).read_bytes()),
            'subsystem':'02a4','chip':1,'record_count':19,'changed_records':[f'{x:08x}' for x in changed],
            'unchanged_records':17,'matrix_mode':'fixed-a1','nfa6_write_planned':False,
            'units':{f'{k:08x}':v[2] for k,v in payloads.items()},
            'remaining_gates':['WRITE41 large-transfer and notification/lock error handling review',
                               'Independent memory/file/coldboot acceptance and partial-failure recovery plan',
                               'Complete FL23 installation separately needs CP boot/NOR update and recovery evidence'],
            'rollback_note':'Original unit bytes are exported, but no device rollback capability is proven by this offline export'}
    save(out/'manifest.json',report)
    for f in out.iterdir():f.chmod(0o600)
    print(json.dumps({'status':report['status'],'changed_records':report['changed_records'],
                      'unchanged_records':17,'hardware_io':False,'output':str(out)}))


if __name__=='__main__':
    os.umask(0o077)
    main()
