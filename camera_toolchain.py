"""Offline integration check and plan sealing. This CLI has no device/run action.

Passing this check means local tools and declared CPU/host models agree. It does
not authorize card access, RAM changes, firmware installation or claim hardware
acceptance. Full SDK updates remain non-atomic.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import unittest
import uuid

ROOT=Path(__file__).resolve().parent
OUT=ROOT/'output/offline-toolchain'
PACKAGE=ROOT/'output/fl23-stock-receiver-container-01/BODYDATA.UNTESTED_DO_NOT_INSTALL.DAT'
PLAIN=ROOT/'output/fl23-stock-receiver-plain-01/plain.DO_NOT_INSTALL.bin'
PACKAGE_SHA='fc8a7865c95059dcb4ac2a347a06b4a76f016b9c37dcc8412dfe9c2c2111de6a'
PLAIN_SHA='ebc7f537c21b685609f646670ab8b381db15d7283d259cbb587a2c0a008a51bf'
TEST_MODULES=('test_camera_device_lease','test_camera_install_journal','test_camera_sd_stage',
              'test_camera_firmware_capture','test_camera_menu_window','test_camera_menu_session',
              'test_camera_postinstall_verify','test_camera_toolchain_integration','test_camera_exclusive_rename',
              'test_camera_capture_session','test_camera_operation_guard','test_camera_package_audit',
              'test_fl23_prewrite_guard','test_fl23_prewrite_adapter','test_camera_workflow',
              'test_camera_workflow_simulator','test_camera_local_rejection',
              'test_camera_install_volatile','test_camera_install_patch',
              'test_camera_install_patch_session','test_camera_install_patch_plan',
              'test_camera_install_patch_read','test_camera_install_cancel',
              'test_camera_install_patch_read_execution','test_camera_install_patch_read_session',
              'test_camera_install_card','test_camera_install_runtime',
              'test_camera_install_runtime_metadata','test_camera_install_runtime_session',
              'test_camera_install_requirements','test_camera_install_runtime_command',
              'test_camera_install_master_plan','test_camera_install_receipts','test_camera_install_admission',
              'test_camera_install_completion','test_camera_install_cancel_session','test_camera_install_card_withdraw',
              'test_camera_install_epoch_session','test_camera_install_epoch_cancel','test_camera_install_post_session',
              'test_camera_install_features','test_camera_install_io','test_camera_install_flow',
              'test_camera_install_operator','test_camera_install_bundle')


def require(ok,message):
    if not ok:raise ValueError(message)


def sha(path):
    with Path(path).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()


def read(path):return json.loads(Path(path).read_text())


def original_plan_body(plan, *, require_preparation=False):
    """Validate supported original-plan bindings without granting device entry."""
    require(isinstance(plan,dict) and plan.get('local_checks_passed') is True
            and plan.get('prepared_offline_only') is True
            and plan.get('execution_approval_received') is False
            and plan.get('model')=='ILCE-7M4'
            and plan.get('package_sha256')==PACKAGE_SHA and plan.get('plaintext_sha256')==PLAIN_SHA,
            'Pinned offline FL23 original plan required')
    if plan.get('schema')=='camera-install-patch-session-plan/1':
        require(plan.get('scope')=='INSTALL_PREPARATION_VOLATILE_PATCH_ONLY'
                and all(plan.get(name) is False for name in
                        ('installation_authorized','hardware_admission_proven','flash_authorized')),
                'Preparation plan must not authorize firmware installation')
        body=plan.get('body_sha256')
    else:
        require(not require_preparation and plan.get('schema')=='camera-offline-toolchain-plan/1',
                'Exact preparation plan required for formal installation')
        body=plan.get('reference_body_sha256')
    require(type(body) is str and len(body)==64 and all(c in '0123456789abcdef' for c in body),
            'Bound historical body SHA required')
    return body


def save(path,value):
    path=Path(path);path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    with path.open('x') as f:
        os.fchmod(f.fileno(),0o600);json.dump(value,f,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())


def checked_install_volatile(job, existing_nonces=()):
    from tools.verify_install_volatile_offline import verify
    from tools.emulate_install_volatile_offline import CASES
    from tools.model_toolchain_bootstraps_offline import CASES as BOOTSTRAP_CASES, PINS
    job=Path(job).absolute()
    require(job.resolve().is_relative_to(ROOT/'output')
            and all(not p.is_symlink() for p in (job,*job.parents)),
            'Install volatile assets must be a regular workspace output directory')
    require(all((job/name).is_file() and not (job/name).is_symlink()
                for name in ('manifest.json','verification.json','native-model-report.json',
                             'bootstrap-model-report.json')),
            'Regular install volatile evidence files required')
    verify(job)
    manifest=read(job/'manifest.json')
    require(manifest['nonce'] not in existing_nonces,'Install volatile nonce reused across tools')
    model=read(job/'native-model-report.json')
    require(model.get('all_passed') is True
            and model.get('coverage_complete_for_declared_matrix') is True
            and model.get('case_count')==len(CASES)
            and len(model.get('cases',()))==len(CASES)
            and {c.get('case') for c in model['cases']}==set(CASES)
            and all(c.get('passed') is True and c.get('hardware_operations')==0
                    and c.get('actual_native_instruction_execution') is True for c in model['cases']),
            'Complete install volatile native model coverage required')
    require(model.get('manifest_sha256')==sha(job/'manifest.json')
            and model.get('verification_sha256')==sha(job/'verification.json')
            and model.get('debug_worker_sha256')==sha(job/'worker.debug.elf')
            and model.get('emulator_sha256')==sha(ROOT/'tools/emulate_install_volatile_offline.py')
            and model.get('contract_sha256')==sha(ROOT/'camera_install_volatile.py')
            and model.get('verifier_sha256')==sha(ROOT/'tools/verify_install_volatile_offline.py')
            and model.get('fixture_helper_sha256')==sha(ROOT/'tools/emulate_menu_window_offline.py')
            and model.get('legacy_decoder_sha256')==sha(ROOT/'camera_menu_window.py')
            and model.get('profile_sha256')==sha(ROOT/'tools/install_volatile_profile.py')
            and model.get('base_profile_sha256')==sha(ROOT/'tools/menu_window_profile.py')
            and model.get('source_bindings')==manifest['sources']
            and model.get('artifact_bindings')==manifest['artifacts'],
            'Install volatile model bindings changed')
    require(model.get('hardware_operations')==0
            and model.get('real_ARM_process_executed') is False
            and model.get('bootstrap_executed') is False
            and model.get('runtime_executor_created') is False
            and model.get('workflow_unlocked') is False
            and model.get('admission')=='OFFLINE_NOT_BODY_BOUND'
            and model.get('execution_kind')=='EMULATED_INSTRUCTIONS_ONLY',
            'Offline install volatile evidence scope changed')
    bootstrap=read(job/'bootstrap-model-report.json')
    require(bootstrap.get('all_passed') is True and bootstrap.get('case_count')==len(BOOTSTRAP_CASES)
            and len(bootstrap.get('cases',()))==len(BOOTSTRAP_CASES)
            and {c.get('scenario') for c in bootstrap['cases']}==set(BOOTSTRAP_CASES)
            and all(c.get('passed') is True for c in bootstrap['cases'])
            and bootstrap.get('original_inputs_unchanged') is True
            and bootstrap.get('bootstrap_CPU_emulated') is True
            and bootstrap.get('worker_executed') is False
            and bootstrap.get('real_ARM_process_executed') is False
            and bootstrap.get('hardware_operations')==0,
            'Complete offline install volatile bootstrap coverage required')
    require(bootstrap.get('input_hashes')=={name:sha(job/name) for name in
                ('manifest.json','verification.json','libJit.so','worker.elf')}
            and bootstrap.get('pinned_source_and_model_hashes')==PINS
            and all(sha(ROOT/name)==digest for name,digest in PINS.items())
            and bootstrap.get('adapter_helper_sha256')==sha(ROOT/'tools/model_toolchain_bootstraps_offline.py')
            and bootstrap.get('runner_sha256')==sha(ROOT/'tools/emulate_install_volatile_offline.py'),
            'Install volatile bootstrap bindings changed')
    return dict(job=str(job.relative_to(ROOT)),nonce=manifest['nonce'],
        manifest_sha256=sha(job/'manifest.json'),module_sha256=sha(job/'libJit.so'),
        native_model_sha256=sha(job/'native-model-report.json'),native_cases=len(CASES),
        bootstrap_model_sha256=sha(job/'bootstrap-model-report.json'),bootstrap_cases=len(BOOTSTRAP_CASES),
        attempt_reserved=(job/'physical-attempt.json').exists(),
        offline_only=True,installation_authorized=False,hardware_acceptance_proven=False,
        runtime_executor_created=False,workflow_unlocked=False,success_is_RAM_restoration=False)


def checked_install_patch_read(job, existing_nonces=()):
    from camera_install_patch_read import spec_sha256
    from tools.verify_install_patch_read_offline import verify
    from tools.emulate_install_patch_read_offline import CASES, READ_BOOTSTRAP_CASES
    from tools.model_toolchain_bootstraps_offline import PINS
    job=Path(job).absolute()
    require(job.resolve().is_relative_to(ROOT/'output')
            and all(not p.is_symlink() for p in (job,*job.parents)),
            'Read assets must be a regular workspace output directory')
    require(all((job/name).is_file() and not (job/name).is_symlink()
                for name in ('manifest.json','verification.json','target-spec.json',
                             'native-model-report.json','bootstrap-model-report.json')),
            'Regular current-read evidence files required')
    verify(job)
    manifest=read(job/'manifest.json');spec=read(job/'target-spec.json')
    require(manifest['nonce'] not in existing_nonces,'Current-read nonce reused across tools')
    model=read(job/'native-model-report.json')
    require(model.get('all_passed') is True
            and model.get('coverage_complete_for_declared_matrix') is True
            and model.get('case_count')==len(CASES) and len(model.get('cases',()))==len(CASES)
            and {c.get('case') for c in model['cases']}==set(CASES)
            and all(c.get('passed') is True and c.get('actual_native_instruction_execution') is True
                    and c.get('process_memory_writes')==0 and c.get('all_memory_opens_readonly') is True
                    and c.get('hardware_operations')==0 for c in model['cases']),
            'Complete readonly native fault matrix required')
    require(model.get('manifest_sha256')==sha(job/'manifest.json')
            and model.get('verification_sha256')==sha(job/'verification.json')
            and model.get('debug_worker_sha256')==sha(job/'worker.debug.elf')
            and model.get('emulator_sha256')==sha(ROOT/'tools/emulate_install_patch_read_offline.py')
            and model.get('contract_sha256')==sha(ROOT/'camera_install_patch_read.py')
            and model.get('profile_sha256')==sha(ROOT/'tools/install_patch_read_profile.py')
            and model.get('verifier_sha256')==sha(ROOT/'tools/verify_install_patch_read_offline.py')
            and model.get('source_bindings')==manifest['sources']
            and model.get('artifact_bindings')==manifest['artifacts'], 'Current-read model bindings changed')
    require(model.get('process_memory_writes')==0 and model.get('all_memory_opens_readonly') is True
            and model.get('hardware_operations')==0 and model.get('real_ARM_process_executed') is False
            and model.get('bootstrap_executed') is False and model.get('runtime_executor_created') is False
            and model.get('workflow_unlocked') is False and model.get('restoration_proven') is False
            and model.get('original_mm_continuity_proven') is False
            and model.get('installation_authorized') is False
            and model.get('execution_kind')=='EMULATED_INSTRUCTIONS_ONLY'
            and model.get('admission')=='OFFLINE_NOT_BODY_BOUND', 'Readonly model scope changed')
    bootstrap=read(job/'bootstrap-model-report.json')
    require(bootstrap.get('all_passed') is True
            and bootstrap.get('coverage_complete_for_declared_matrix') is True
            and set(bootstrap.get('declared_cases',()))==set(READ_BOOTSTRAP_CASES)
            and bootstrap.get('case_count')==len(READ_BOOTSTRAP_CASES)
            and len(bootstrap.get('cases',()))==len(READ_BOOTSTRAP_CASES)
            and {c.get('scenario') for c in bootstrap['cases']}==set(READ_BOOTSTRAP_CASES)
            and all(c.get('passed') is True for c in bootstrap['cases'])
            and bootstrap.get('original_inputs_unchanged') is True
            and bootstrap.get('bootstrap_CPU_emulated') is True
            and bootstrap.get('worker_executed') is False
            and bootstrap.get('real_ARM_process_executed') is False
            and bootstrap.get('hardware_operations')==0, 'Complete current-read bootstrap matrix required')
    require(bootstrap.get('input_hashes')=={name:sha(job/name) for name in
                ('manifest.json','verification.json','libJit.so','worker.elf')}
            and bootstrap.get('pinned_source_and_model_hashes')==PINS
            and all(sha(ROOT/name)==digest for name,digest in PINS.items())
            and bootstrap.get('adapter_helper_sha256')==sha(ROOT/'tools/model_toolchain_bootstraps_offline.py')
            and bootstrap.get('engine_reference_sha256')==sha(ROOT/'tools/emulate_stream_bootstrap.py')
            and bootstrap.get('runner_sha256')==sha(ROOT/'tools/emulate_install_patch_read_offline.py'),
            'Current-read bootstrap bindings changed')
    return dict(job=str(job.relative_to(ROOT)),nonce=manifest['nonce'],
        manifest_sha256=sha(job/'manifest.json'),module_sha256=sha(job/'libJit.so'),
        target_spec_sha256=spec_sha256(spec),target_spec_file_sha256=sha(job/'target-spec.json'),
        prior_pending_sha256=spec['pending_receipt_sha256'],
        derived_body_sha256=spec['body_sha256'],derived_plan_sha256=spec['plan_sha256'],
        native_model_sha256=sha(job/'native-model-report.json'),native_cases=len(CASES),
        bootstrap_model_sha256=sha(job/'bootstrap-model-report.json'),bootstrap_cases=len(READ_BOOTSTRAP_CASES),
        original_source_declaration=spec['original_source_is_hardware'],
        original_hardware_origin_proven=False,current_observation_is_hardware=False,
        SDK_executor_created=False,cancellation_recorded=False,journal_cleared=False,
        ready_for_confirmation=False,installation_authorized=False,offline_only=True,
        component_scope='INDEPENDENT_CURRENT_READ_MODEL_NOT_A_SESSION_PLAN')


def checked_runtime_metadata(job):
    from camera_install_runtime_metadata import MetadataAssets, preflight_assets
    from tools.emulate_install_runtime_metadata_offline import CASES, BOOTSTRAP_CASES
    job=Path(job).absolute()
    require(job.is_relative_to(ROOT/'output') and job.is_dir()
            and all(not p.is_symlink() for p in (job,*job.parents)),
            'Runtime metadata job must be a regular workspace output directory')
    assets=MetadataAssets(job,*(sha(job/name) for name in
        ('manifest.json','libJit.so','native-model-report.json','bootstrap-model-report.json')))
    prepared=preflight_assets(assets)
    return dict(prepared.reference,native_cases=len(CASES),bootstrap_cases=len(BOOTSTRAP_CASES),
                offline_only=True,hardware_operations=0,write_admission=False)


def check(*,tests=False,install_volatile_job=None,install_patch_read_job=None,runtime_metadata_job=None):
    from camera_package_audit import audit_candidate
    from camera_menu_window import checked_job,JOB
    from camera_firmware_capture import checked_capture_assets,JOBS,ASSETS,CLAIMS
    menu,module=checked_job()
    captures={name:checked_capture_assets(name) for name in JOBS}
    require(PACKAGE.stat().st_size==757480856 and sha(PACKAGE)==PACKAGE_SHA,'Research package changed')
    require(sha(PLAIN)==PLAIN_SHA,'Bound plaintext changed')
    manifest=read(PACKAGE.parent/'manifest.json')
    require(manifest['container_sha256']==PACKAGE_SHA and manifest['plaintext_sha256']==PLAIN_SHA
            and manifest['independent_verification']['rsa_signature_verified'] is True
            and manifest['independent_verification']['blocks_verified']==739727,
            'Independent encrypted-container evidence missing')
    crc=audit_candidate(PLAIN)
    require(crc['all_passed'] is True and crc['table_count']==10 and crc['regular_CRC_rows']==115,
            'Complete local CSV CRC coverage missing')
    bootstrap=read(OUT/'bootstrap-models-01.json')
    require(bootstrap['all_passed'] is True and bootstrap['asset_count']==6 and bootstrap['case_count']==96
            and bootstrap['hardware_operations']==0 and bootstrap['original_inputs_unchanged'] is True
            and bootstrap['runner_sha256']==sha(ROOT/'tools/model_toolchain_bootstraps_offline.py'),
            'Bootstrap model evidence stale')
    modules={'menu_stock_window':hashlib.sha256(module).hexdigest()}
    modules.update({k:v['module_sha256'] for k,v in captures.items()})
    observed={}
    for asset in bootstrap['assets']:
        # Asset names are recorded by the model runner; job directory identifies
        # the precise prepared capture profile without relying on presentation text.
        name=asset['asset']
        expected_job=JOB if name=='menu_stock_window' else ASSETS/name/'bootstrap'
        require(asset['job']==str(expected_job.relative_to(ROOT)),'Modeled asset directory differs')
        require(name in modules and asset['module']['sha256']==modules[name], 'Modeled bootstrap differs')
        require(len(asset['tests'])==16 and all(x['passed'] is True for x in asset['tests']), 'Bootstrap case failed')
        observed[name]=True
    require(set(observed)==set(modules),'Missing prepared bootstrap coverage')
    nonces=[menu['nonce']]+[v['nonce'].hex() for v in captures.values()]
    require(len(set(nonces))==len(nonces),'Runtime nonce reuse across tools')
    install_volatile=(checked_install_volatile(install_volatile_job,nonces)
                      if install_volatile_job is not None else None)
    read_component=(checked_install_patch_read(install_patch_read_job,
        nonces+([install_volatile['nonce']] if install_volatile else []))
        if install_patch_read_job is not None else None)
    runtime_metadata=(checked_runtime_metadata(runtime_metadata_job)
                      if runtime_metadata_job is not None else None)
    reserved={'menu':(JOB/'physical-attempt.json').exists()}
    reserved.update({name:(CLAIMS/(v['nonce'].hex()+'.json')).exists() for name,v in captures.items()})
    runtime=('camera_toolchain.py','camera_device_lease.py','camera_operation_guard.py',
             'camera_install_journal.py','camera_local_rejection.py','camera_sd_stage.py','camera_firmware_capture.py',
             'camera_capture_session.py','camera_menu_window.py','camera_menu_session.py',
             'camera_postinstall_verify.py','camera_backup_records.py','camera_package_audit.py',
             'camera_workflow.py','camera_workflow_spec.py','camera_workflow_simulator.py','camera-workflow',
             'camera_install_volatile.py','native/install_volatile_patch.c',
             'camera_install_patch.py','camera_install_patch_session.py','camera_install_patch_plan.py',
             'camera_install_patch_read.py','camera_install_cancel.py','native/install_patch_read.c',
             'camera_install_patch_read_execution.py','camera_install_patch_read_session.py',
             'camera_install_patch_read_plan.py','camera_install_card.py','camera_install_runtime.py',
             'camera_install_runtime_metadata.py','camera_install_runtime_session.py',
             'camera_install_runtime_plan.py','camera_install_runtime_command.py','camera_install_requirements.py',
             'native/install_runtime_metadata.c')
    sources={ROOT/p for p in runtime}
    sources|=set(ROOT.glob('camera_install*.py'))
    sources|={ROOT/'tools'/n for n in ('menu_window_profile.py','build_menu_window_offline.py',
                'verify_menu_window_offline.py','emulate_menu_window_offline.py',
                'model_toolchain_bootstraps_offline.py','fl23_prewrite_guard.py','fl23_prewrite_adapter.py')}
    sources|=set((ROOT/'tools').glob('*firmware_file_capture*.py'))
    sources|=set((ROOT/'tools').glob('*install_volatile*.py'))
    sources|=set((ROOT/'tools').glob('*install_patch_read*.py'))
    sources|=set((ROOT/'tools').glob('*install_runtime_metadata*.py'))
    sources|=set((ROOT/'tests').glob('test_camera_*.py'))
    sources|=set((ROOT/'tests').glob('test_fl23_prewrite_*.py'))
    sources|={ROOT/'tests/install_model_fixture.py'}
    sources|={p for p in (ROOT/'Sony-PMCA-RE/pmca').rglob('*.py')}
    sources|=set(ROOT.glob('camera_stream*.py'))
    sources|={ROOT/'camera_inventory.py',ROOT/'ref/sony-a7m4-custom-firmware/a7m4/fat.py',
              ROOT/'ref/sony-a7m4-custom-firmware/a7m4/common.py',
              ROOT/'ref/sony-a7m4-custom-firmware/a7m4/__init__.py'}
    test_count=None
    source_hashes={str(p.relative_to(ROOT)):sha(p) for p in sorted(sources)}
    if tests:
        sys.path.insert(0,str(ROOT/'tests'))
        suite=unittest.defaultTestLoader.loadTestsFromNames(TEST_MODULES)
        result=unittest.TextTestRunner(verbosity=1).run(suite)
        require(result.wasSuccessful(),'Offline host tests failed');test_count=result.testsRun
        require(all(sha(ROOT/p)==digest for p,digest in source_hashes.items()),
                'Sources changed while tests ran; no sealed evidence produced')
    return {'schema':'camera-offline-toolchain-check/1','local_checks_passed':True,
        'host_tests_run':test_count,'test_modules':list(TEST_MODULES) if tests else [],
        'package_sha256':PACKAGE_SHA,'plaintext_sha256':PLAIN_SHA,'prepared_modules':modules,
        'runtime_nonces_distinct':True,'existing_attempt_reservations':reserved,
        'native_menu_worker_cases':29,'native_capture_worker_cases':168,'bootstrap_cases':96,
        'all_regular_CRC_rows':115,'hardware_operations_by_this_check':0,
        'CRC_rows_recomputed_from_actual_plaintext':True,
        'installation_authorized':False,'hardware_acceptance_proven':False,
        'install_volatile':install_volatile,
        'install_patch_read':read_component,
        'runtime_metadata':runtime_metadata,
        'full_SDK_atomic_or_automatic_rollback_proven':False,
        'still_required':([
            'Separate authorized install host/journal, cancellation and menu handoff implementation',
            'Current-read hardware session validation and hardware-backed cancellation',
            'Fresh same-body admission and explicit reviewed recovery disposition',
            'Actual process/cache/syscall and update lifecycle validation',
            'Postinstall captures/settings and FL2/FL3 photo/video acceptance',
            'Arbitrary true cube and sound remain separate unimplemented features'] if install_volatile or read_component else [
            'Controlled Mac/device session and RAM-window/handoff/restoration rehearsal',
            'Fresh same-body acquisition and critical-settings evidence from actual installation',
            'Actual FL2/FL3 photo/video tests; arbitrary true cube and sound remain separate unimplemented features']),
        'sources':source_hashes}


def prepare(path,*,install_volatile_job=None):
    report=check(tests=True,install_volatile_job=install_volatile_job)
    reference=ROOT/'output/backup-01/execution/run.json'
    body=read(reference)['body']['usb_serial_sha256']
    report.update(schema='camera-offline-toolchain-plan/1',group_nonce=uuid.uuid4().hex,
        reference_body_sha256=body,reference_body_record_sha256=sha(reference),model='ILCE-7M4',
        execution_approval_received=False,prepared_offline_only=True)
    path=Path(path)
    require(not path.exists(),'Choose a new local plan path')
    snapshots=path.with_suffix('.sources');snapshots.mkdir(mode=0o700)
    for name,digest in report['sources'].items():
        target=snapshots/name;target.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        with target.open('xb') as f:
            os.fchmod(f.fileno(),0o600);f.write((ROOT/name).read_bytes());f.flush();os.fsync(f.fileno())
        require(sha(target)==digest,'Snapshot changed before plan publication')
    report['source_snapshot_directory']=str(snapshots.resolve())
    save(path,report)
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('action',choices=('check','prepare'));p.add_argument('--tests',action='store_true')
    p.add_argument('--report',type=Path)
    p.add_argument('--install-volatile-job',type=Path)
    p.add_argument('--install-patch-read-job',type=Path);args=p.parse_args()
    if args.action=='prepare':
        require(args.install_patch_read_job is None,'Current-read jobs support offline check only, not a session plan')
        require(args.report is not None,'Explicit new local plan file required')
        r=prepare(args.report,install_volatile_job=args.install_volatile_job)
    else:
        r=check(tests=args.tests,install_volatile_job=args.install_volatile_job,
                install_patch_read_job=args.install_patch_read_job)
        if args.report:save(args.report,r)
    print(json.dumps({'local_checks_passed':True,'host_tests_run':r['host_tests_run'],
                      'hardware_operations_by_this_action':0,'installation_authorized':False}))
