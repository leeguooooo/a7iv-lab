"""Step-by-step camera walkthrough and isolated rehearsal controller.

steps/simulate/prepare/status/init are host-only. device executes ONE explicitly
authorized rehearsal action, never an installation. No automatic continuation,
retry, reset, firmware activation or recovery is implemented by this controller.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re

from camera_workflow_spec import STEPS, SCENARIOS

ROOT = Path(__file__).resolve().parent
DEVICE_ACTIONS = ('settings', 'stage', 'window', 'restore')
STATES = {'settings': ('PLANNED',), 'stage': ('PLANNED',),
          'window': ('SD_STAGED',), 'restore': ('RAM_AWAITING_OPERATOR_RECONNECT',)}
SHA = re.compile(r'[0-9a-f]{64}\Z')
NAME = re.compile(r'[A-Za-z0-9_-]{1,64}\Z')


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(path):
    with Path(path).open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def local_path(path, root=ROOT, *, exists=True):
    path=Path(path).absolute();root=Path(root).resolve()
    require(all(not p.is_symlink() for p in (path,*path.parents)), 'Symlink workflow path forbidden')
    require(path.resolve().is_relative_to(root/'output'), 'Workflow data must stay under project output')
    if exists:
        require(path.exists(), 'Workflow input missing')
    return path


def read_json(path):
    def pairs(rows):
        out={}
        for key,value in rows:
            require(key not in out,'Duplicate JSON field');out[key]=value
        return out
    result=json.loads(Path(path).read_text(),object_pairs_hook=pairs)
    require(isinstance(result,dict),'JSON object required')
    return result


def save_new(path, value):
    from camera_stream_execution import durable_new
    durable_new(path,value)


def checked_plan(path, expected_sha256, *, root=ROOT):
    root=Path(root).resolve();path=local_path(path,root)
    require(isinstance(expected_sha256,str) and SHA.fullmatch(expected_sha256),'Reviewed plan SHA required')
    require(digest(path)==expected_sha256,'Reviewed plan changed')
    plan=read_json(path)
    require(plan.get('schema')=='camera-offline-toolchain-plan/1'
            and plan.get('local_checks_passed') is True and plan.get('prepared_offline_only') is True
            and plan.get('model')=='ILCE-7M4','Sealed offline plan required')
    require(isinstance(plan.get('reference_body_sha256'),str)
            and SHA.fullmatch(plan['reference_body_sha256']),'Bound reference body required')
    from camera_toolchain import PACKAGE_SHA,PLAIN_SHA
    require(plan.get('package_sha256')==PACKAGE_SHA and plan.get('plaintext_sha256')==PLAIN_SHA,
            'Wrong fixed candidate')
    sources=plan.get('sources')
    required={'camera_workflow.py','camera_workflow_spec.py','camera_workflow_simulator.py',
              'camera_menu_session.py','camera_sd_stage.py','camera_install_journal.py'}
    require(isinstance(sources,dict) and required.issubset(sources),'Plan predates this workflow; prepare a new one')
    for name,sha in sources.items():
        source=(root/name).absolute()
        require(not Path(name).is_absolute() and '..' not in Path(name).parts
                and all(not p.is_symlink() for p in (source,*source.parents))
                and source.resolve().is_relative_to(root),'Unsafe source reference')
        require(isinstance(sha,str) and SHA.fullmatch(sha) and digest(source)==sha,'Sealed source changed')
    reference=root/'output/backup-01/execution/run.json'
    require(digest(reference)==plan.get('reference_body_record_sha256')
            and read_json(reference)['body']['usb_serial_sha256']==plan['reference_body_sha256'],
            'Reference camera evidence changed')
    return plan


def initialize(path, plan_path, plan_sha256, *, root=ROOT):
    """Host-only reservation. It creates a pending ledger; it is not approval."""
    from camera_device_lease import CameraDeviceLease
    from camera_install_journal import InstallJournal
    root=Path(root).resolve();path=local_path(path,root,exists=False)
    require(path.parent==root/'output/camera-workflows' and NAME.fullmatch(path.name),
            'Choose one new output/camera-workflows/<id> directory')
    plan=checked_plan(plan_path,plan_sha256,root=root)
    require(not path.exists(),'Workflow already exists; inspect status, never overwrite')
    with CameraDeviceLease('workflow-init',lock_path=root/'output/camera-device-owner.lock'):
        path.parent.mkdir(mode=0o700,parents=True,exist_ok=True);path.mkdir(mode=0o700)
        record=dict(schema='camera-guided-rehearsal/1',plan=str(Path(plan_path).absolute()),
            plan_sha256=plan_sha256,body_sha256=plan['reference_body_sha256'],model='ILCE-7M4',
            journal=str(root/'output/full-install-sessions'/path.name),installation_authorized=False,
            formal_install_entry_locked=True,hardware_operations=0)
        # Persist enough host-only context before creating a global pending
        # ledger. Failed initialization remains inspectable without deleting it.
        save_new(path/'init-intent.json',record)
        try:
            InstallJournal.create(root/'output/full-install-sessions',path.name,
                plan_sha256=plan_sha256,body_sha256=plan['reference_body_sha256'],model='ILCE-7M4')
            save_new(path/'workflow.json',record)
        except BaseException as error:
            try:save_new(path/'init-failed.json',dict(error_type=type(error).__name__,hardware_operations=0))
            except BaseException:pass
            raise
    return record


def open_workflow(path, *, root=ROOT):
    from camera_install_journal import InstallJournal
    root=Path(root).resolve();path=local_path(path,root)
    require(path.parent==root/'output/camera-workflows' and NAME.fullmatch(path.name),'Unexpected workflow location')
    record=read_json(local_path(path/'workflow.json',root))
    require(record.get('schema')=='camera-guided-rehearsal/1'
            and record.get('installation_authorized') is False
            and record.get('formal_install_entry_locked') is True,'Fixed rehearsal scope required')
    plan=checked_plan(record['plan'],record['plan_sha256'],root=root)
    expected=root/'output/full-install-sessions'/path.name
    require(record['journal']==str(expected),'Journal path changed')
    journal=InstallJournal.open(local_path(expected,root))
    binding=dict(plan_sha256=record['plan_sha256'],body_sha256=plan['reference_body_sha256'],model='ILCE-7M4')
    require(journal.binding==binding and record['body_sha256']==binding['body_sha256'],'Workflow binding changed')
    return path,record,journal


def status(path, *, root=ROOT):
    folder=local_path(path,root)
    if not (folder/'workflow.json').exists():
        from camera_install_journal import InstallJournal
        journal=Path(root).resolve()/'output/full-install-sessions'/folder.name
        require(folder.parent==Path(root).resolve()/'output/camera-workflows' and NAME.fullmatch(folder.name),
                'Unexpected workflow location')
        state='NO_LEDGER_CREATED'
        if journal.exists():state=InstallJournal.open(local_path(journal,root)).state
        return dict(state=state,workflow_record_missing=True,initialization_incomplete=True,
            device_attempt_intents_present=any((folder/(a+'-intent.json')).exists() for a in DEVICE_ACTIONS),
            formal_install_entry_locked=True,installation_authorized=False,hardware_operations_by_status=0)
    folder,record,journal=open_workflow(path,root=root)
    return dict(state=journal.state,scope='VOLATILE_RAM_REHEARSAL_ONLY',
        completed_actions=[a for a in DEVICE_ACTIONS if (folder/(a+'-result.json')).is_file()],
        formal_install_entry_locked=True,installation_authorized=False,
        elapsed_time_is_not_restoration_proof=True,hardware_operations_by_status=0)


def cancel_initialization(path, *, confirmed=False, root=ROOT):
    """Host-only cancellation of an untouched PLANNED reservation, no cleanup."""
    require(confirmed is True,'Explicit local-only cancellation required')
    from camera_device_lease import CameraDeviceLease
    from camera_install_journal import InstallJournal
    root=Path(root).resolve();folder=local_path(path,root)
    require(folder.parent==root/'output/camera-workflows' and NAME.fullmatch(folder.name),'Unexpected workflow location')
    with CameraDeviceLease('workflow-cancel-init',lock_path=root/'output/camera-device-owner.lock'):
        record=read_json(local_path(folder/'init-intent.json',root))
        plan=checked_plan(record['plan'],record['plan_sha256'],root=root)
        require(not any((folder/(a+'-intent.json')).exists() for a in DEVICE_ACTIONS),
                'Device attempt intent exists; cannot cancel initialization')
        journal_path=root/'output/full-install-sessions'/folder.name
        if journal_path.exists():
            journal=InstallJournal.open(local_path(journal_path,root))
            require(journal.binding==dict(plan_sha256=record['plan_sha256'],
                body_sha256=plan['reference_body_sha256'],model='ILCE-7M4') and journal.state=='PLANNED',
                'Only an untouched PLANNED ledger may be cancelled')
            journal.advance('CANCELLED_BEFORE_DEVICE_WRITE',details={'operation':'cancel-initialization','explicit_confirmation':True})
        result=dict(state='CANCELLED_BEFORE_DEVICE_WRITE',hardware_operations=0,files_preserved=True)
        save_new(folder/'cancelled-local.json',result)
        return result


def checked_settings(folder,record,root):
    from camera_capture_session import PDT_BYTES
    from camera_backup_records import record_map
    result=read_json(local_path(folder/'settings-result.json',root))
    binding={k:record[k] for k in ('plan_sha256','body_sha256','model')}
    require(result.get('source_is_hardware') is True and result.get('normal_body_verified') is True
            and all(result.get(k)==v for k,v in binding.items())
            and result.get('group')==str(folder/'settings'),'Fresh same-body settings acquisition required')
    before=read_json(local_path(folder/'settings/before-reference.json',root))
    require(result.get('before')==before and before.get('source_is_hardware') is True
            and before.get('acquisition_phase')=='PRE_INSTALL' and before.get('path')=='before.bk4'
            and all(before.get(k)==v for k,v in binding.items()),'Original settings reference changed')
    require(isinstance(before.get('nonce'),str) and re.fullmatch(r'[0-9a-f]{32}',before['nonce'])
            and isinstance(result.get('group_nonce'),str) and re.fullmatch(r'[0-9a-f]{32}',result['group_nonce'])
            and before.get('group_nonce')==result['group_nonce'] and before['nonce']!=result['group_nonce'],
            'Settings nonce binding changed')
    source=local_path(folder/'settings/before.bk4',root)
    require(source.stat().st_size==PDT_BYTES and digest(source)==before.get('sha256'),'Actual settings backup changed')
    record_map(source.read_bytes())
    return result


def checked_stage(folder,record,journal,root,*,result=None,require_event=True):
    from camera_toolchain import PACKAGE_SHA
    result=result if result is not None else read_json(local_path(folder/'stage-result.json',root))
    original=local_path(folder/'card-stage/completed.json',root)
    require(read_json(original)==result,'Original card stage report changed')
    require(result.get('state')=='STAGED_UNRECOGNIZED_FILE_VERIFIED_NOT_ACTIVATED'
            and result.get('source_sha256')==PACKAGE_SHA and result.get('bytes')==757480856
            and result.get('BODYDATA_DAT_created_or_replaced') is False
            and result.get('updater_invoked') is False and result.get('existing_root_update_unchanged') is True
            and result.get('camera_internal_firmware_modified') is False
            and result.get('volume_identity',{}).get('body_sha256')==record['body_sha256'],
            'Complete same-body inactive stage receipt required')
    if require_event:
        events=[e for e in journal.events if e['state']=='SD_STAGED']
        require(len(events)==1 and events[0]['details'].get('stage_report_sha256')==digest(original)
                and events[0]['details'].get('stage_result_sha256')==digest(folder/'stage-result.json'),
                'Stage evidence differs from durable journal binding')
    return result


def check_current_staged_card(result):
    """Read only; actual discovery must identify the same card before path use."""
    from camera_sd_stage import discover,snapshot_existing,staged_relative_path,digest as card_digest
    from camera_toolchain import PACKAGE_SHA
    current=discover();previous=result['volume_identity']
    require(all(previous.get(k) and current.get(k)==previous[k] for k in
                ('volume_uuid','body_sha256','filesystem','volume_bytes')),
            'Current camera/card differs from staged evidence')
    relative=staged_relative_path(result.get('target'),previous.get('mount'),PACKAGE_SHA)
    target=Path(current['mount'])/relative
    require(str(Path(previous['mount'])/relative)==result['target']
            and all(not p.is_symlink() for p in (target,*target.parents))
            and target.is_file() and target.stat().st_size==757480856
            and card_digest(target,uncached=True)==PACKAGE_SHA,'Current staged card bytes changed')
    require(snapshot_existing(Path(current['mount']))==result['existing_root_update'],
            'Existing root BODYDATA changed after staging')


def checked_window(folder,record,journal,root):
    from camera_menu_window import checked_job,asset_reference,FIELDS,FRAME,decode,ready_proof,patched_proof
    result=read_json(local_path(folder/'window-result.json',root))
    require(result==read_json(local_path(folder/'menu/session-awaiting-reconnect.json',root))
            and result.get('state')=='RAM_AWAITING_OPERATOR_RECONNECT' and result.get('source_is_hardware') is True
            and all(result.get(k)==record[k] for k in ('plan_sha256','body_sha256','model')),
            'Original hardware window handoff required')
    from camera_menu_session import _known_service_exit, _receipt_sha256
    _known_service_exit(result.get('service_events', []))
    observation=result['patch_observation']
    require(observation.get('source_is_hardware') is True
            and observation.get('state')=='PATCH_OBSERVED_AWAITING_KNOWN_EXIT_AND_NORMAL_BODY',
            'Original nested hardware observation required')
    reference,job=asset_reference();meta,_=checked_job()
    require(observation.get('nonce')==meta['nonce'] and observation.get('asset_reference')==dict(
        directory=str(job),manifest_sha256=reference.manifest_sha256,module_sha256=reference.module_sha256),
        'Original window asset/nonce binding changed')
    claim=read_json(local_path(job/'physical-attempt.json',root))
    require(claim.get('nonce')==meta['nonce'] and claim.get('source_is_hardware') is True
            and claim.get('module_sha256')==reference.module_sha256,'Original physical attempt claim required')
    nonce=bytes.fromhex(meta['nonce'])
    def original(row):
        require(isinstance(row,dict) and set(row)==set(FIELDS),'Complete original native record required')
        return decode(FRAME.pack(b'M4DWL002',nonce,*(row[n] for n in FIELDS)),nonce)
    ready,patched=original(observation['ready']),original(observation['patched'])
    ready_proof(ready,ready['loader_pid']);patched_proof(patched,ready)
    rows=[e for e in journal.events if e['state']=='RAM_AWAITING_OPERATOR_RECONNECT']
    proof=_receipt_sha256(observation)
    require(len(rows)==1 and rows[0]['details'].get('window_nonce')==meta['nonce']
            and rows[0]['details'].get('patch_observation_sha256')==proof,
            'Window proof differs from durable RAM session event')
    require(rows[0]['details'].get('pending_receipt_sha256')==_receipt_sha256(result),
            'Window handoff differs from pending RAM receipt')
    return result


def device_action(path, action, *, authorize_step=False, camera_ready=False,
                  slot1_confirmed=False, firmware_never_started=False, root=ROOT):
    """One action; all installation/activation actions remain unavailable."""
    require(action in DEVICE_ACTIONS,'This tool has no formal installation or activation action')
    require(Path(root).resolve()==ROOT.resolve(),'Device execution requires the actual sealed project root')
    require(authorize_step is True and camera_ready is True,'Explicit action approval and camera readiness required')
    require(firmware_never_started is True,'Confirm no firmware update was started')
    if action=='stage':require(slot1_confirmed is True,'Operator Slot 1 confirmation required')
    from camera_device_lease import CameraDeviceLease
    from camera_operation_guard import assert_operation_allowed
    root=Path(root).resolve()
    with CameraDeviceLease('workflow-'+action,lock_path=root/'output/camera-device-owner.lock') as lease:
        folder,record,journal=open_workflow(path,root=root)
        assert_operation_allowed(journal,allowed_states=STATES[action])
        # The settings acquisition must really be a same-plan/body hardware
        # receipt, not a simulated walkthrough or a mere file's existence.
        if action in ('stage','window'):
            checked_settings(folder,record,root)
        if action=='window':
            staged=checked_stage(folder,record,journal,root)
            check_current_staged_card(staged)
        handoff=None
        if action=='restore':
            handoff=checked_window(folder,record,journal,root)
        # Durable unique intent prevents replay, including uncertain host death.
        save_new(folder/(action+'-intent.json'),dict(action=action,plan_sha256=record['plan_sha256'],
            firmware_never_started_operator_confirmed=True,automatic_retry=False))
        attempted=False
        try:
            attempted=True
            options=dict(plan_sha256=record['plan_sha256'],journal=journal,lease=lease)
            if action=='settings':
                from camera_capture_session import capture_settings_before
                result=capture_settings_before(record['body_sha256'],folder/'settings',**options)
            elif action=='stage':
                from camera_sd_stage import stage
                journal.advance('SD_STAGE_INTENT',details={'operation':'inactive-card-stage'})
                result=stage(lease=lease,journal=journal,report_path=folder/'card-stage')
                checked_stage(folder,record,journal,root,result=result,require_event=False)
            elif action=='window':
                from camera_menu_session import run_menu_session
                evidence=folder/'menu';evidence.mkdir(mode=0o700)
                result=run_menu_session(record['body_sha256'],evidence,ram_authorized=True,**options)
            else:
                from camera_menu_session import collect_menu_restoration
                evidence=folder/'restoration';evidence.mkdir(mode=0o700)
                result=collect_menu_restoration(record['body_sha256'],evidence,handoff,
                    collection_authorized=True,firmware_never_started_confirmed=True,**options)
            save_new(folder/(action+'-result.json'),result)
            if action=='stage':
                journal.advance('SD_STAGED',details={'stage_report':str(folder/'card-stage/completed.json'),
                    'stage_report_sha256':digest(folder/'card-stage/completed.json'),
                    'stage_result_sha256':digest(folder/'stage-result.json')})
            return dict(action=action,state=journal.state,formal_install_entry_locked=True,
                        installation_authorized=False,automatic_continuation=False)
        except BaseException as error:
            if attempted:
                try:
                    journal.advance('STOPPED_UNKNOWN',details=dict(operation=action,error_type=type(error).__name__,
                        automatic_retry=False,automatic_STOP=False,automatic_reboot=False))
                except BaseException:
                    pass
            raise


def main():
    parser=argparse.ArgumentParser(description='相机分步引导；模拟不连接设备，正式安装入口锁定。')
    commands=parser.add_subparsers(dest='command',required=True)
    commands.add_parser('steps',help='显示全部17个子步骤及当前限制')
    sim=commands.add_parser('simulate',help='纯模拟熟悉流程与故障')
    sim.add_argument('--scenario',choices=SCENARIOS,default='normal')
    sim.add_argument('--interactive',action='store_true',help='逐个子步骤按回车演练')
    prep=commands.add_parser('prepare',help='离线测试并封存新计划')
    prep.add_argument('--report',type=Path,required=True)
    init=commands.add_parser('init',help='创建本地主机演练记录，不连接相机')
    init.add_argument('--workflow',type=Path,required=True);init.add_argument('--plan',type=Path,required=True)
    init.add_argument('--plan-sha256',required=True)
    inspect=commands.add_parser('status',help='只读检查现有记录')
    inspect.add_argument('--workflow',type=Path,required=True)
    cancel=commands.add_parser('cancel-init',help='仅取消从未发出设备动作的本地初始化，不删记录')
    cancel.add_argument('--workflow',type=Path,required=True)
    cancel.add_argument('--confirm-local-cancel',action='store_true')
    perform=commands.add_parser('device',help='未来实机演练：一次只执行一个明确授权的动作')
    perform.add_argument('action',choices=DEVICE_ACTIONS)
    perform.add_argument('--workflow',type=Path,required=True)
    perform.add_argument('--authorize-step',action='store_true')
    perform.add_argument('--camera-ready',action='store_true')
    perform.add_argument('--slot1-confirmed',action='store_true')
    perform.add_argument('--firmware-never-started',action='store_true')
    args=parser.parse_args()
    if args.command=='steps':
        n=0
        for step in STEPS:
            print(step['title'])
            for item in step['actions']:
                n+=1;print(f"  {n}. {item['title']}：{item['description']}")
        print('当前实操仅支持独立授权的临时演练。正式安装入口锁定。')
        return
    if args.command=='simulate':
        from camera_workflow_simulator import main as simulate_main
        simulate_main(['--scenario',args.scenario]+(['--interactive'] if args.interactive else []));return
    if args.command=='prepare':
        from camera_toolchain import prepare
        result=prepare(args.report)
        print(json.dumps(dict(report=str(args.report),sha256=digest(args.report),tests=result['host_tests_run'],camera_operations=0)))
        return
    if args.command=='init':result=initialize(args.workflow,args.plan,args.plan_sha256)
    elif args.command=='status':result=status(args.workflow)
    elif args.command=='cancel-init':result=cancel_initialization(args.workflow,confirmed=args.confirm_local_cancel)
    else:result=device_action(args.workflow,args.action,authorize_step=args.authorize_step,
        camera_ready=args.camera_ready,slot1_confirmed=args.slot1_confirmed,
        firmware_never_started=args.firmware_never_started)
    print(json.dumps(result,ensure_ascii=False,indent=2))


if __name__=='__main__':
    main()
