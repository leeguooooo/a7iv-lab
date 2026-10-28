"""Build and audit one exact-v7 offline RAW matrix candidate. No DAT/device I/O.

Writes only a newly created output/fl23-v7-raw-candidate-01 directory. Original
CP and reference tree are read-only inputs. Not an installation tool.
"""
from pathlib import Path
import copy,hashlib,json,sys
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'ref/sony-a7m4-custom-firmware'))
from a7m4.fl23 import patch_program
import emulate_fl23_raw_recipe_offline as block
import emulate_fl23_raw_followup_offline as full
SOURCE=ROOT/'output/fl23-offline/CPAPP-B.BIN'
UPSTREAM=ROOT/'ref/sony-a7m4-custom-firmware/a7m4/profiles/fl23/cp-raw-lossless-recipe.json'
OUT=ROOT/'output/fl23-v7-raw-candidate-01'
SOURCE_SHA='4551c73386c27a0a9b247fd3e05c3bd5e3425bdb9fe9f8374c201c96533b3479'
def sha(b):return hashlib.sha256(b).hexdigest()
def save(p,x):p.write_text(json.dumps(x,indent=2)+'\n')
def main():
 source=SOURCE.read_bytes();up_raw=UPSTREAM.read_bytes();up=json.loads(up_raw)
 assert len(source)==16236816 and sha(source)==SOURCE_SHA,'Exact v7 baseline required'
 assert up['source_sha256']=='acecf0719e1b824723f8f232d5dd399e5814834bbffe907eaa025ecf48c505b2'
 assert up['target_sha256']=='9e312f58ceade78ab049ec317d5c4f6cf94165d13a8bb2b2fcad2bdbefe7611b'
 assert len(up['patches'])==2 and not up['donors'] and not up.get('donor_operations')
 assert [(p['offset'],len(bytes.fromhex(p['new_hex'])))for p in up['patches']]==[(0x5a90d2,4),(0xa9cda0,216)]
 # Lock complete upstream recipe identity to the independently reviewed evidence.
 reviewed=json.loads((ROOT/'output/rea-study/fl23-raw-lossless/review.json').read_text());assert sha(up_raw)==reviewed['recipe_sha256']
 candidate=bytearray(source);windows=[];allowed=set()
 for p in up['patches']:
  a=p['offset'];new=bytes.fromhex(p['new_hex']);z=a+len(new);old=source[a:z]
  assert sha(old)==p['old_sha256'],'Preimage mismatch'
  assert not allowed.intersection(range(a,z)),'Overlapping windows';allowed.update(range(a,z));candidate[a:z]=new
  windows.append(dict(offset=a,CP_VA=hex(a+0x108000),bytes=len(new),before_sha256=sha(old),after_sha256=sha(new),before_hex=old.hex(),after_hex=new.hex()))
 candidate=bytes(candidate);diff=[i for i,(a,b)in enumerate(zip(source,candidate))if a!=b]
 assert len(candidate)==len(source)and len(diff)==212 and set(diff)<=allowed
 cuts=[(0,0x5a90d2),(0x5a90d6,0xa9cda0),(0xa9ce78,len(source))]
 outside=[dict(start=a,end_exclusive=z,source_sha256=sha(source[a:z]),target_sha256=sha(candidate[a:z]),identical=source[a:z]==candidate[a:z])for a,z in cuts]
 assert all(x['identical']for x in outside)
 recipe=copy.deepcopy(up);recipe.update(baseline='Exact public official-6.02 v7 target4551c733; independent offline RAW matrix serialization adaptation',source_sha256=SOURCE_SHA,target_sha256=sha(candidate),deployment='OFFLINE_NOT_INSTALLABLE; no DAT/device transport; physical NOR/RAW acceptance unresolved',status='OFFLINE_NOT_INSTALLABLE',upstream_recipe_sha256=sha(up_raw),camera_tested=False)
 assert patch_program(source,recipe)==candidate,'Strict full-source/preimage/full-target replay failed'
 # Models load the complete actual new candidate; no in-model patch injection.
 assert block.b==source and full.V==source
 original=block.run(False);assert original['output9'][-1]==1615
 positives=[];consumer=[]
 for c,s in [(19,54),(19,56),(20,55),(20,57)]:
  for g,cap in [(block.GAIN,0),([4096]*4,65535)]:
   kw=dict(color=c,selector=s,gains=g,cap=cap)
   a=block.run(actual_image=candidate,**kw);assert a['stop']=='0x6b11e4'and a['output9']==block.MATRIX;positives.append(a)
   a=full.consumer(actual_image=candidate,**kw);assert a['output9']==full.M;consumer.append(dict(inputs=kw,result=a))
 options=[dict(root=False),dict(color=0),dict(color=19,selector=55),dict(color=20,selector=54),dict(bit3=16),dict(bit11=2),dict(cap=1),dict(aux_bad=True)]
 for k in range(4):g=block.GAIN.copy();g[k]=1024;options.append(dict(gains=g))
 fall=[];fullfall=[]
 for kw in options:
  a=block.run(actual_image=candidate,**kw);assert a['stop']=='0x6b10d6';fall.append(a)
  original_full=full.consumer(False,**kw);a=full.consumer(actual_image=candidate,**kw);assert a['output9']==original_full['output9']and'0xba4e70'in a['marks'];fullfall.append(dict(inputs=kw,original=original_full,candidate=a))
 maps=[dict(kind=k,**full.mappings(raw,flag))for k,raw in [('stock',full.S),('v7_source',source),('candidate',candidate)]for flag in [0,1]]
 for row in maps:
  expected=1 if row['kind']=='stock'else 0
  assert all(x['XN']==expected for x in row['translations']if x['CP_VA']in ['0xba4da0','0xba4e74'])
 tails=[]
 for kw in [dict(extra=True),dict(mode9=16384),dict(mode9=32768),dict(extra=True,mode9=32768,matrix=[30000,17,47,46,30000,-113,-406,-184,30000])]:
  a=full.consumer(actual_image=candidate,**kw);reference=full.consumer(tail_reference=True,actual_image=candidate,**kw);assert a['output9']==reference['output9'];tails.append(dict(inputs=kw,candidate=a,common_tail_reference=reference))
 tests=dict(status='PASS_OFFLINE_MODELS_ONLY',candidate_sha256=sha(candidate),uses_complete_actual_candidate=True,in_model_patch_injection=False,assertions_passed=True,original_rounding=original,direct8=positives,fallback12=fall,full_consumer8=consumer,full_fallback12=fullfall,mapper6=maps,tail4=tails,camera_io=False,physical_RAW_acceptance=False)
 assert SOURCE.read_bytes()==source and UPSTREAM.read_bytes()==up_raw,'Input changed during review'
 assert not OUT.exists(),'Refusing output overwrite'
 OUT.mkdir(mode=0o700)
 # Outputs appear only after successful preimage/replay/all-model verification.
 (OUT/'CPAPP-B.BIN').write_bytes(candidate);save(OUT/'cp-v7-raw-lossless-recipe.json',recipe);save(OUT/'tests.json',tests)
 assert (OUT/'CPAPP-B.BIN').read_bytes()==patch_program(SOURCE.read_bytes(),json.loads((OUT/'cp-v7-raw-lossless-recipe.json').read_text()))
 files={p.name:dict(bytes=p.stat().st_size,sha256=sha(p.read_bytes()))for p in OUT.iterdir()if p.is_file()}
 scripts={p.name:sha(p.read_bytes())for p in [Path(__file__),ROOT/'emulate_fl23_raw_recipe_offline.py',ROOT/'emulate_fl23_raw_followup_offline.py']}
 manifest=dict(status='OFFLINE_NOT_INSTALLABLE',source=dict(path=str(SOURCE.relative_to(ROOT)),bytes=len(source),sha256=SOURCE_SHA),target=dict(path='CPAPP-B.BIN',bytes=len(candidate),sha256=sha(candidate)),upstream=dict(path=str(UPSTREAM.relative_to(ROOT)),sha256=sha(up_raw),source_sha256=up['source_sha256'],target_sha256=up['target_sha256'],is_our_target=False),actual_changed_bytes=len(diff),approved_windows=windows,outside_windows=outside,strict_patch_program_replay=True,files=files,analysis_scripts_sha256=scripts,counts=dict(original_rounding=1,direct=8,fallback=12,full_consumer=8,full_fallback=12,mapper=6,common_tail=4),camera_io=False,DAT_generated=False,ref_modified=False,original_modified=False,camera_tested=False,RAW_acceptance=False,remaining=['Independent candidate/recipe verification','Full105-entry SR2 serializer and broader mode coverage','No current physical NOR backup/recovery or installation admission','Fresh original RAW validation after any future authorized installation'])
 save(OUT/'manifest.json',manifest)
 (OUT/'README.txt').write_text('OFFLINE_NOT_INSTALLABLE\nExact-v7 RAW matrix serialization candidate only. No DAT or device operation.\nSource SHA256: '+SOURCE_SHA+'\nTarget SHA256: '+sha(candidate)+'\nSynthetic models do not prove photographed RAW correctness.\n')
 print(json.dumps(dict(output=str(OUT.relative_to(ROOT)),status=manifest['status'],source_sha256=SOURCE_SHA,target_sha256=sha(candidate),actual_changed_bytes=len(diff),counts=manifest['counts'],camera_io=False,DAT_generated=False)))
if __name__=='__main__':main()
