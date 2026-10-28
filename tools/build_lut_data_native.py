"""Build the data/store library for Linux AArch64; never deploy or load it."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
SOURCES=['native/cube_input.c','native/cube_input.h','native/lut_store.c','native/lut_store.h']
EXPORTS=['camera_cube_parse','camera_cube_sample','camera_cube_resample','camera_cube_pack_ap_integer',
         'camera_lut_record_build','camera_lut_record_validate','camera_lut_store_save','camera_lut_store_load']

def digest(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        while b:=f.read(4<<20):h.update(b)
    return h.hexdigest()

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--zig',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--with-media',action='store_true',help='Include normalized Fsys media adapter; no startup binding')
    p.add_argument('--with-ap-request',action='store_true',help='Include local AP object value capture; requires media')
    p.add_argument('--with-select-guard',action='store_true',help='Include synchronous select failure guard; no AP binding or CP acknowledgement')
    args=p.parse_args();zig=args.zig.resolve();out=args.output.resolve()
    if args.with_ap_request:args.with_media=True
    version=subprocess.check_output([str(zig),'version'],text=True).strip()
    if version!='0.15.2':raise SystemExit('This build recipe is pinned to Zig 0.15.2')
    sources=SOURCES+(['native/lut_media.c','native/lut_media.h'] if args.with_media else [])
    if args.with_ap_request:sources+=['native/lut_ap_request.c','native/lut_ap_request.h']
    if args.with_select_guard:sources+=['native/lut_select_guard.c','native/lut_select_guard.h']
    exports=EXPORTS+(['camera_lut_media_bind_wrappers','camera_lut_media_path','camera_lut_media_scan','camera_lut_media_read'] if args.with_media else [])
    if args.with_ap_request:exports+=['camera_lut_ap_capture_local_copy']
    if args.with_select_guard:exports+=['camera_lut_ap_select_checked']
    source_ids=[{'path':name,'sha256':digest(ROOT/name)} for name in sources]
    out.mkdir(mode=0o700,parents=False,exist_ok=False)
    flags=['cc','-target','aarch64-linux-gnu.2.25','-std=c11','-O2','-Wall','-Wextra','-Werror',
           '-fPIC','-shared','-ffp-contract=off','-fno-omit-frame-pointer',
           '-Wl,--no-undefined','-Wl,-z,relro','-Wl,-z,now','-Wl,-z,noexecstack']
    with tempfile.TemporaryDirectory(prefix='.build-',dir=out) as tmp:
        output=Path(tmp)/'libcamera_lut_data.so'
        command=[str(zig),*flags,*[str(ROOT/name) for name in sources if name.endswith('.c')],'-o',str(output)]
        result=subprocess.run(command,capture_output=True,text=True)
        (out/'compiler.log').write_text(result.stdout+result.stderr)
        if result.returncode:raise SystemExit(f'Compilation failed; see {out}/compiler.log')
        if source_ids!=[{'path':name,'sha256':digest(ROOT/name)} for name in sources]:
            raise SystemExit('Source changed during build; output not admitted')
        output.rename(out/output.name)
    lib=out/'libcamera_lut_data.so';lib.chmod(0o600)
    manifest={'scope':'Offline LUT components with optional unbound AP adapters; not a runtime binding or installer',
              'target':'aarch64-linux-gnu.2.25','zig_version':version,'zig_sha256':digest(zig),
              'compile_flags':flags,'sources':source_ids,'artifact':lib.name,
              'with_media':args.with_media,'exports_expected':exports,
              'with_ap_request':args.with_ap_request,
              'with_select_guard':args.with_select_guard,
              'bytes':lib.stat().st_size,'sha256':digest(lib),'device_operations':0,
              'loaded_or_installed':False,'runtime_compatible':False,
              'limits':['ELF dependency/version audit and matching target ABI still required.',
                        'No AP process discovery, startup/menu hook, live media/slot epoch binding or verified CP acknowledgement.']}
    (out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps({'artifact':str(lib),'bytes':manifest['bytes'],'sha256':manifest['sha256'],'loaded_or_installed':False}))

if __name__=='__main__':main()
