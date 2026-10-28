"""Create one offline AV-CAM allocation-error fix; no packaging/device action."""
from pathlib import Path
import argparse,hashlib,json,runpy,sys
R=Path(__file__).resolve().parents[1]
def digest(v):return hashlib.sha256(v).hexdigest()
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args();out=a.output.resolve()
 source=R/'local/analysis/cspi-coldboot/AV-CAM.BIN';raw=source.read_bytes()
 assert digest(raw)=='d70ea2d700bc5fb7aa1bcfdb46eb5adb45e7d8ed703f2167fb7526f89d177d3f'
 off=0x2b50b8;old=bytes.fromhex('e0031f2a');new=bytes.fromhex('e003082a');assert raw[off:off+4]==old
 fixed=raw[:off]+new+raw[off+4:];assert len(fixed)==len(raw)
 assert fixed[:off]==raw[:off] and fixed[off+4:]==raw[off+4:]
 out.mkdir(parents=False,exist_ok=False,mode=0o700);target=out/'AV-CAM.BIN'
 with target.open('xb') as f:f.write(fixed)
 target.chmod(0o600)
 recipe={'state':'OFFLINE_FIRMWARE_PATCH_NOT_INSTALLABLE','purpose':'Preserve OSAL allocation error return instead of false zero in existing queue producer','source':str(source.relative_to(R)),'source_sha256':digest(raw),'candidate_sha256':digest(fixed),'bytes':len(raw),'instruction_offset':hex(off),'old_hex':old.hex(),'old_instruction':'mov w0,wzr','new_hex':new.hex(),'new_instruction':'mov w0,w8','changed_bytes':sum(x!=y for x,y in zip(raw,fixed)),'device_operations':0,'installed':False,'limits':['No firmware image checksum/signature/container integration or boot verification','No receiver, register, DMA, actor ownership, timeout/callback or userspace bridge fix','Allocation failure now propagates a nonzero error; a successful return still does not prove completion']}
 (out/'manifest.json').write_text(json.dumps(recipe,indent=2)+'\n')
 runpy.run_path(str(R/'output/replay-a7m4-avcam-l3d-queue.py'),init_globals={'FIRMWARE_CANDIDATE':target,'REPORT_PATH':out/'queue-control-review.json'})
 review=json.loads((out/'queue-control-review.json').read_text());assert review['allocator_error_propagation_fix'] and review['modeled_firmware_candidate_sha256']==digest(fixed)
 (out/'admission.json').write_text(json.dumps({'state':recipe['state'],'candidate_sha256':digest(fixed),'source_exact':True,'outside_instruction_unchanged':True,'original_API_and_modified_queue_CPU_cases':len(review['cases']),'current_device_compatible':False,'boot_container_validated':False,'timeout_quiescence_verified':False,'installed':False,'device_operations':0},indent=2)+'\n')
 print(json.dumps({'candidate':str(target),'sha256':digest(fixed),'state':recipe['state'],'device_operations':0}))
if __name__=='__main__':main()
