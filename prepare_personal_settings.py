"""Build only parsed nfa2 BACKUP.BIN/BAK candidates. Never write nfa6 offsets."""
import argparse
import hashlib
import json
from pathlib import Path

from a7m4.fat import Fat
from a7m4.fl23 import RECIPES, SLOTS, bk4_rows, patch_backup
from camera_inventory import ROOT, require, save, sha


def records(data):
    return {(chip,key):(r['attrs'],data[r['offset']:r['offset']+r['size']])
            for chip,row in enumerate(bk4_rows(data)) for key,r in row['records'].items()}


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    require(not a.output.exists(),'Choose a new output directory')
    source=ROOT/'output/backup-01/execution';evidence=json.loads((source/'run.json').read_text())
    require(evidence['verdict']=='FIVE_PARTITION_BACKUPS_VERIFIED','Backup did not finish')
    identities=evidence['partitions'];raw=(source/'cnflasha2.bin').read_bytes()
    require(hashlib.sha256(raw).hexdigest()==identities['cnflasha2']['sha256'],'Original nfa2 changed')
    scratch=(source/'cnflasha6.bin').read_bytes();require(hashlib.sha256(scratch).hexdigest()==identities['cnflasha6']['sha256'],'Original nfa6 changed')
    donor=ROOT/'local/firmware/fx2-1.01/color';cc=(donor/'cc1.bin').read_bytes();matrix=(donor/'block13.bin').read_bytes()
    expected=json.loads((RECIPES/'cp-v7-recipe.json').read_text())['donors']
    require(hashlib.sha256(cc).hexdigest()==expected['fx2_cc1'] and hashlib.sha256(matrix).hexdigest()==expected['fx2_block13'],'Donor differs')
    fs=Fat(raw);report={'camera_io':False,'nfa6_modified':False,'installable':False,'source_sha256':hashlib.sha256(raw).hexdigest(),'backups':{}}
    for filename in ['BACKUP.BIN','BACKUP.BAK']:
        original=fs.read(filename);rows=bk4_rows(original);before=records(original)
        parsed={key:r for row in rows for key,r in row['records'].items()}
        cc_rec=parsed[0x02a40001];mat_rec=parsed[0x02a4000d]
        old_cc=original[cc_rec['offset']:cc_rec['offset']+cc_rec['size']]
        old_matrix=original[mat_rec['offset']:mat_rec['offset']+mat_rec['size']]
        require(old_cc[0x1236:0x123a]==bytes(4) and old_matrix[0x1cc:0x1d0]==bytes(4),'New look parameters already assigned')
        for bank in [22,23,24,25]:
            require(bank not in old_cc[0x1200:0x1250] and bank not in old_matrix[0x196:0x1e0],'Target bank already referenced')
            require(not any(old_cc[0x1250+bank*64:0x1250+bank*64+48]) and not any(old_matrix[0x1e0+bank*768:0x1e0+bank*768+576]),'Target color payload occupied')
        modified=patch_backup(original,cc,matrix,'fixed-a1');after=records(modified)
        allowed=set()
        def allow(offset,length):allowed.update(range(offset,offset+length))
        allow(cc_rec['offset']+0x1236,4);allow(mat_rec['offset']+0x1cc,4)
        for bank in [22,23,24,25]:
            allow(cc_rec['offset']+0x1250+bank*64,48);allow(mat_rec['offset']+0x1e0+bank*768,576)
        for key in SLOTS:
            rec=parsed[key];require(rec['attrs']==0x60 and rec['size']==1,'Unknown selected slot format');allow(rec['offset'],1)
        for row in rows:allow(row['base']+0x20,4)
        require(len(original)==len(modified) and all(x==y or i in allowed for i,(x,y) in enumerate(zip(original,modified))),'Change outside precise color/slot/checksum windows')
        changed=[f'chip{chip}:{key:08x}' for chip,key in before if before[(chip,key)]!=after[(chip,key)]]
        require(len(changed)==8 and before.keys()==after.keys(),'Unexpected changed record count')
        fs.replace(filename,modified)
        report['backups'][filename]={'record_count':len(before),'unchanged_records':len(before)-8,'changed_records':changed,'bk4_checksums_valid':True,'sha256':hashlib.sha256(modified).hexdigest()}
    result=fs.bytes();require(len(result)==len(raw),'Partition length changed')
    # FAT headers, allocation tables and directory metadata must be identical.
    require(raw[:fs.data_start]==result[:fs.data_start],'FAT metadata changed')
    require(sha(source/'cnflasha2.bin')==report['source_sha256'],'Original changed during processing')
    a.output.mkdir(parents=True)
    dest=a.output/'nflasha2.candidate.bin';dest.write_bytes(result);require(dest.read_bytes()==result,'Output readback mismatch')
    report.update(output_sha256=sha(dest),size=len(result),changed_bytes=sum(x!=y for x,y in zip(raw,result)),
                  nfa6_reason='Jiritsu scratch FAT is empty; prefix locations are free clusters, not proven active settings')
    save(a.output/'manifest.json',report);print(json.dumps(report,indent=2))


if __name__=='__main__':main()
