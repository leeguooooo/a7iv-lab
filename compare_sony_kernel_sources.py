"""Stream-hash official source archives without extracting or executing them."""
from pathlib import Path
import hashlib
import json
import tarfile

ROOT=Path(__file__).resolve().parent


def archive_identity(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for data in iter(lambda:f.read(4<<20),b''):
            h.update(data)
    return dict(path=str(path.relative_to(ROOT)),bytes=path.stat().st_size,sha256=h.hexdigest())


def inventory(path):
    result={}
    with tarfile.open(path,mode='r|gz') as tf:
        for item in tf:
            name=item.name.removeprefix('./')
            assert name not in result, 'Duplicate archive path'
            row=dict(kind='file' if item.isfile() else 'directory' if item.isdir() else 'link' if item.issym() or item.islnk() else repr(item.type),bytes=item.size)
            if item.isfile():
                h=hashlib.sha256();seen=0
                stream=tf.extractfile(item)
                for b in iter(lambda:stream.read(4<<20),b''):
                    h.update(b);seen+=len(b)
                assert seen==item.size
                row['sha256']=h.hexdigest()
            elif item.issym() or item.islnk():
                row['target']=item.linkname
            result[name]=row
    return result


def main():
    paths=[ROOT/'local/sony-gpl/linux-kernel-ver500.tar.gz',ROOT/'local/sony-gpl-ver600/linux-kernel-ver600.tar.gz']
    identities=[archive_identity(p)for p in paths]
    assert identities[0]['sha256']=='1e4925c6d2f8b5523eb255b0ea770d2823d3b3917211f77bcef3808cc8efd93e'
    a,b=[inventory(p)for p in paths]
    common=a.keys()&b.keys()
    changed=[n for n in sorted(common)if a[n]!=b[n]]
    out=ROOT/'output/sony-gpl-full-content-comparison-01'
    out.mkdir(exist_ok=False)
    for version,rows in [('500',a),('600',b)]:
        (out/(version+'-content-map.json')).write_text(json.dumps(rows,indent=2)+'\n')
    critical=['Makefile','.config','arch/arm64/configs/cxd90057_set_defconfig','include/linux/module.h','include/linux/moduleparam.h','include/linux/mm.h','include/linux/gfp.h','kernel/module.c','kernel/params.c','arch/arm64/include/asm/memory.h','arch/arm64/kernel/module.c','drivers/udif/mach-cxd900xx/include/mach/noncache.h','include/linux/udif/types.h']
    checks={p:dict(present_in_both='linux-kernel/'+p in common,identical=a.get('linux-kernel/'+p)==b.get('linux-kernel/'+p),before=a.get('linux-kernel/'+p),after=b.get('linux-kernel/'+p))for p in critical}
    report=dict(source_archives=identities,before_entries=len(a),after_entries=len(b),common_entries=len(common),changed_common_paths=changed,added_paths=sorted(b.keys()-a.keys()),removed_paths=sorted(a.keys()-b.keys()),critical=checks,executed_archive_code=False,files_extracted=False,camera_io=False,scope='All shared entries compared by file SHA/length or link target/type. Timestamps and owner metadata excluded. Not proof of exact6.02 source identity.')
    (out/'comparison.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:report[k]for k in ['before_entries','after_entries','common_entries','changed_common_paths','added_paths','removed_paths']},indent=2))


if __name__=='__main__':main()
