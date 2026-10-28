"""Offline original-instruction evidence; no device/library execution."""
from pathlib import Path
import hashlib,json
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM
root=Path(__file__).resolve().parent
p=root/'local/analysis/updater-sdk/bodyfs/cp/udtrcp.bin';raw=p.read_bytes()
assert hashlib.sha256(raw).hexdigest()=='2c04cf41c63decc8bc9e4ff0441570aaf25a7c50687051716bfdcae69af0ac25'
cs=Cs(CS_ARCH_ARM,CS_MODE_ARM)
ranges=[('INIT handler',0x176b78,0x176ee8),('MODE handler',0x176850,0x176ae4),('hw_init',0x183c90,0x183f8c),('setDrvZ',0x184580,0x184690),('set_mode',0x1846e8,0x184b00),('readReg',0x185d38,0x185eb4),('controller protect switch',0x185eb4,0x185fd8),('command descriptor consumer',0x186310,0x186890),('Micron function table init',0x1869dc,0x186ba4),('Micron drive callback',0x18784c,0x18789c),('Micron config write helper',0x187a98,0x187ce8),('C2 drive callback',0x187ce8,0x188288),('C2 write enable',0x188618,0x188814),('C2 opcode72 command construction',0x189c60,0x189e00)]
chunks=[]
for name,a,z in ranges:
 b=raw[a-0x108000:z-0x108000]
 chunks.append({'label':name,'start':hex(a),'end_exclusive':hex(z),'raw_sha256':hashlib.sha256(b).hexdigest(),'raw_hex':b.hex(),'linear_disassembly':[{'address':hex(i.address),'bytes':i.bytes.hex(),'mnemonic':i.mnemonic,'operands':i.op_str}for i in cs.disasm(b,a)]})
tracep=root/'output/rea-study/cp-updater-init/command-traces.json'
tr=json.loads(tracep.read_text())
o={'source':str(p.relative_to(root)),'source_sha256':hashlib.sha256(raw).hexdigest(),'mapping':'VA=file_offset+0x108000; ARM32 ARM state; not AP physical map','camera_io':False,'range_caveat':'Linear evidence ranges can contain embedded literals/strings and adjacent instructions. Claimed executed paths are command-traces.json, not arbitrary linear decodes.','trace_sha256':hashlib.sha256(tracep.read_bytes()).hexdigest(),'case_count':len(tr['cases']),'assertions_passed':tr['assertions_passed'],'chunks':chunks}
(root/'output/rea-study/cp-updater-init/static-evidence.json').write_text(json.dumps(o,indent=2)+'\n')
print(json.dumps({'source_sha256':o['source_sha256'],'chunks':len(chunks),'cases':o['case_count']}))
