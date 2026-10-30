"""Build and seal the complete offline FL23 toolkit; never contact a camera."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from camera_install_receipts import safe_path, load_reference
from camera_install_patch_plan import assets_from_directories, seal as seal_patch
from camera_install_patch import preflight_assets as patch_preflight
from camera_install_runtime_session import RuntimeAssets, preflight_assets as runtime_preflight
from camera_install_runtime_plan import seal as seal_runtime
from camera_install_runtime_metadata import MetadataAssets
from camera_install_post_plan import assets_from_directory
from camera_install_post_session import preflight_assets as post_preflight
from camera_install_requirements import read_requirements
from camera_install_flow import source_paths, validate_config, CONFIG_SCHEMA
from camera_install_operator import prepare_static_facts, write_operator_template
from camera_stream_execution import durable_new
from camera_toolchain import PLAIN, PACKAGE_SHA
from camera_sd_stage import EXCLUSIVE_RENAME, ACTIVATION_PROTOCOLS, validate_activation_protocol

ROOT = Path(__file__).resolve().parent
CAPTURE_GROUPS = {'runtime-assets':('post_p1',),'patch-captures':('pre_app','pre_ufp'),
                  'post-assets':('post_app','post_cp','post_p1')}


def require(value,message):
    if not value:raise ValueError(message)


def _sha(path):
    with safe_path(path).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def _tool(script, arguments, log):
    require(script in ('build_firmware_file_capture_offline.py','build_install_volatile_offline.py',
        'emulate_install_volatile_offline.py','build_install_runtime_metadata_offline.py',
        'emulate_install_runtime_metadata_offline.py'), 'Fixed offline tool required')
    with log.open('x') as stream:
        done=subprocess.run([sys.executable,'-B',str(ROOT/'tools'/script),*map(str,arguments)],
                            stdout=stream,stderr=subprocess.STDOUT,timeout=600)
    require(done.returncode==0,'Offline asset preparation failed; inspect '+str(log))


def build_assets(output):
    """Create all static jobs with fresh distinct nonces, without SDK entry."""
    out=safe_path(output)
    require(out.is_relative_to(ROOT/'output') and not out.exists(),'Fresh workspace bundle directory required')
    out.mkdir(mode=0o700,parents=True);logs=out/'logs';logs.mkdir(mode=0o700)
    for group, profiles in CAPTURE_GROUPS.items():
        for profile in profiles:
            _tool('build_firmware_file_capture_offline.py',
                  ('--target',profile,'--output',out/group/profile,'--bundle'),logs/(group+'-'+profile+'.log'))
    patch=out/'patch-job'
    _tool('build_install_volatile_offline.py',('--output',patch),logs/'patch-build.log')
    from tools.verify_install_volatile_offline import verify
    durable_new(patch/'verification.json',verify(patch))
    _tool('emulate_install_volatile_offline.py',('--job',patch,'--report',patch/'native-model-report.json',
        '--bootstrap-report',patch/'bootstrap-model-report.json'),logs/'patch-model.log')
    meta=out/'metadata-job'
    _tool('build_install_runtime_metadata_offline.py',('--output',meta),logs/'metadata-build.log')
    from tools.verify_install_runtime_metadata_offline import verify as verify_meta
    from camera_install_patch_plan import _write
    _write(meta/'verification.json',json.dumps(verify_meta(meta),sort_keys=True,separators=(',',':'),allow_nan=False).encode())
    _tool('emulate_install_runtime_metadata_offline.py',('--job',meta),logs/'metadata-model.log')
    return out


def seal_bundle(assets_directory, output, *, body_reference, card_activation_protocol=EXCLUSIVE_RENAME):
    """Seal executable steps and truthful risk facts, not missing on-site approvals."""
    validate_activation_protocol(card_activation_protocol)
    assets=safe_path(assets_directory);out=safe_path(output)
    require(assets.is_relative_to(ROOT/'output') and assets.is_dir()
            and out.is_relative_to(ROOT/'output') and not out.exists(),'Existing assets and fresh workspace seal required')
    out.mkdir(mode=0o700,parents=True)
    patch,captures=assets_from_directories(assets/'patch-job',assets/'patch-captures')
    prepared_patch=patch_preflight(patch,captures)
    original=seal_patch(out/'original-plan',assets=patch,capture_assets=captures,body_reference=body_reference)
    original_ref=dict(path=original['plan'],sha256=original['plan_sha256'])
    _, master=load_reference(original_ref)
    binding=dict(body_sha256=master['body_sha256'],plan_sha256=original_ref['sha256'],model='ILCE-7M4')
    job=assets/'metadata-job'
    metadata=MetadataAssets(job,*(_sha(job/n) for n in ('manifest.json','libJit.so','native-model-report.json','bootstrap-model-report.json')))
    runtime=RuntimeAssets(assets/'runtime-assets',_sha(assets/'runtime-assets/post_p1/bootstrap/bootstrap.json'),metadata)
    prepared_runtime=runtime_preflight(runtime)
    runtime_review=seal_runtime(out/'runtime-review',assets=runtime,body_sha256=binding['body_sha256'],
        plan_sha256=binding['plan_sha256'],required_partition_sizes=read_requirements(PLAIN)['required_partition_sizes'])
    post=post_preflight(assets_from_directory(assets/'post-assets'))
    nonces=[prepared_runtime.reference['p1']['nonce'],prepared_runtime.reference['metadata']['nonce'],
            prepared_patch.reference['patch']['nonce'],
            *(prepared_patch.reference['captures'][n]['nonce'] for n in ('pre_app','pre_ufp')),
            *(r['nonce'] for r in post.reference['profiles'].values())]
    require(len(set(nonces))==len(nonces),'All eight static native jobs must have distinct nonces')
    snapshots=out/'sources';snapshots.mkdir(mode=0o700)
    sources={}
    from camera_install_patch_plan import _write,_sync
    for name in source_paths():
        raw=safe_path(ROOT/name).read_bytes();sources[name]=hashlib.sha256(raw).hexdigest()
        path=snapshots/name;path.parent.mkdir(mode=0o700,parents=True,exist_ok=True);_write(path,raw)
    for directory in sorted((p for p in snapshots.rglob('*') if p.is_dir()),key=lambda p:len(p.parts),reverse=True):_sync(directory)
    _sync(snapshots)
    config=dict(schema=CONFIG_SCHEMA,card_activation_protocol=card_activation_protocol,body_sha256=binding['body_sha256'],candidate_sha256=PACKAGE_SHA,
        original_plan_reference=original_ref,
        runtime=dict(review_reference=dict(path=runtime_review['review_path'],sha256=runtime_review['review_sha256']),asset_reference=prepared_runtime.reference),
        patch=dict(review_reference=original_ref,asset_reference=prepared_patch.reference),
        post=dict(directory=str(assets/'post-assets'),asset_reference=post.reference),
        sources=sources,source_snapshot_directory=str(snapshots),installation_authorized=False)
    path=out/'config.json';durable_new(path,config);reference=dict(path=str(path),sha256=_sha(path))
    validate_config(reference)
    facts=prepare_static_facts(out/'facts',binding=binding)
    template=write_operator_template(out/'operator-template.json',binding=binding)
    result=dict(schema='camera-install-offline-bundle/1',config_reference=reference,static_native_jobs=len(nonces),
        original_plan_reference=original_ref,static_facts=facts,operator_template=template,
        source_count=len(sources),hardware_operations=0,installation_authorized=False,
        site_only=['fresh body/runtime','card and power observations','exact recovery-risk decision',
                   'full-install approval','manual camera update','actual FL2/FL3 media and restart acceptance'])
    durable_new(out/'bundle.json',result)
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='command',required=True)
    build=sub.add_parser('build');build.add_argument('--output',type=Path,required=True)
    seal=sub.add_parser('seal');seal.add_argument('--assets',type=Path,required=True);seal.add_argument('--output',type=Path,required=True)
    seal.add_argument('--body-reference',type=Path,required=True)
    seal.add_argument('--card-activation-protocol',choices=sorted(ACTIVATION_PROTOCOLS),default=EXCLUSIVE_RENAME)
    a=p.parse_args()
    if a.command=='build':print(json.dumps(dict(assets_directory=str(build_assets(a.output)),hardware_operations=0)))
    else:print(json.dumps(seal_bundle(a.assets,a.output,body_reference=a.body_reference,card_activation_protocol=a.card_activation_protocol)))


if __name__=='__main__':main()
