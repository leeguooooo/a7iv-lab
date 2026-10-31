"""One explicit formal FL23 step at a time; never press updater or power controls.

The legacy workflow remains a rehearsal. Every device action delegates to an
existing reviewed actor. Local intents are single-use; uncertainty never retries
an upload, START, rename, service exit, update, reset or reboot.
"""
from copy import deepcopy
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid

from camera_device_lease import CameraDeviceLease, DEFAULT_LOCK
from camera_install_journal import InstallJournal
from camera_install_io import JournalSnapshotPin
from camera_operation_guard import DEFAULT_SESSIONS, assert_operation_allowed
from camera_install_patch_session import _source_only_runtime, _held_lease, review_source_paths, SOURCE_ONLY_RUNTIME
from camera_install_receipts import load_reference, safe_path, sha, canonical
from camera_sd_stage import DIGEST, EXCLUSIVE_RENAME, BACKUP_COPY_ATOMIC_REPLACE, validate_activation_protocol
from camera_package_audit import PLAIN_SHA
from camera_stream_execution import durable_new

ROOT = Path(__file__).resolve().parent
SCHEMA = 'camera-install-flow/1'
CONFIG_SCHEMA = 'camera-install-flow-config/1'
STEPS = ('runtime','probe','stage','activate','patch','prepare-read','read','observe-card','admit',
         'start','complete','prepare-post','post','content','features','withdraw','prepare-epoch','cancel')
HOST_ONLY = frozenset(('prepare-read','prepare-post','prepare-epoch','admit','start','complete','content','features'))
PHASES = frozenset(('INTENT','COMPLETED','UNKNOWN','REJECTED_LOCAL','BLOCKED_READ_ONLY'))
PHYSICAL = frozenset(('runtime','probe','stage','activate','patch','read','observe-card','post','withdraw','cancel'))
FORMAL = frozenset(('admit','start','complete','content','features'))
TOOL_SOURCES = frozenset(('tools/card_backup_replace.py','tools/card_protocol_probe.py','tools/volume_capabilities.py','native/install_patch_read.c','native/install_runtime_metadata.c',
    'tools/build_install_patch_read_offline.py','tools/verify_install_patch_read_offline.py','tools/install_patch_read_profile.py','tools/emulate_install_patch_read_offline.py',
    'tools/build_install_runtime_metadata_offline.py','tools/verify_install_runtime_metadata_offline.py','tools/install_runtime_metadata_profile.py','tools/emulate_install_runtime_metadata_offline.py',
    'tools/menu_window_profile.py','tools/verify_menu_window_offline.py','tools/model_toolchain_bootstraps_offline.py','tools/emulate_stream_bootstrap.py'))
STATES = {'runtime':('PLANNED',),'probe':('PLANNED','SD_STAGED'),'stage':('PLANNED',),'activate':('SD_STAGED',),'patch':('SD_STAGED',),
    'prepare-read':('INSTALL_PATCH_AWAITING_OPERATOR_RECONNECT',),'read':('INSTALL_PATCH_AWAITING_OPERATOR_RECONNECT',),
    'observe-card':('INSTALL_PATCH_AWAITING_OPERATOR_RECONNECT',),'admit':('INSTALL_PATCH_AWAITING_OPERATOR_RECONNECT',),
    'start':('INSTALL_READY_FOR_OPERATOR_START',),'complete':('FLASH_MAY_HAVE_STARTED',),
    'prepare-post':('DEVICE_COMPLETION_REPORTED',),'post':('DEVICE_COMPLETION_REPORTED',),
    'content':('DEVICE_COMPLETION_REPORTED',),'features':('CONTENT_VERIFIED',),
    'withdraw':('SD_STAGED','INSTALL_PATCH_AWAITING_OPERATOR_RECONNECT'),
    'prepare-epoch':('INSTALL_PATCH_AWAITING_OPERATOR_RECONNECT',),
    'cancel':('PLANNED','SD_STAGED','INSTALL_PATCH_AWAITING_OPERATOR_RECONNECT')}


def require(ok, message):
    if not ok:raise ValueError(message)


def local(path, *, directory=False):
    path=safe_path(path)
    require(path.is_relative_to(ROOT/'output'),'Flow inputs and outputs must be inside workspace output')
    if directory:require(path.is_dir(),'Existing private directory required')
    return path


def reference(path):
    path=local(path);require(path.is_file(),'Regular flow artifact required')
    return dict(path=str(path),sha256=sha(path.read_bytes()))


def _load(ref):
    local(ref['path']);return load_reference(ref)[1]


def _system(physical=False):
    _source_only_runtime()
    require(sys.platform=='darwin','Production flow requires the reviewed macOS host')
    if physical:require(os.geteuid()==0,'Production camera steps require the reviewed sudo entry')


def source_paths():
    return tuple(sorted(set(review_source_paths()) | TOOL_SOURCES))


def _config_structure(config_reference, *, injected=False):
    config=_load(config_reference)
    validate_activation_protocol(config.get('card_activation_protocol', EXCLUSIVE_RENAME))
    require(config.get('schema')==CONFIG_SCHEMA and config.get('candidate_sha256')==DIGEST
        and type(config.get('model_fixture_only',False)) is bool
        and (injected or config.get('model_fixture_only',False) is False),'Formal flow config required')
    original_ref=config['original_plan_reference'];original=_load(original_ref)
    require(original_ref==config['patch']['review_reference']
        and original.get('schema')=='camera-install-patch-session-plan/1'
        and original.get('scope')=='INSTALL_PREPARATION_VOLATILE_PATCH_ONLY'
        and original.get('body_sha256')==config.get('body_sha256') and original.get('model')=='ILCE-7M4'
        and original.get('package_sha256')==DIGEST and original.get('plaintext_sha256')==PLAIN_SHA
        and original.get('local_checks_passed') is True and original.get('prepared_offline_only') is True
        and original.get('execution_approval_received') is False
        and all(original.get(k) is False for k in ('installation_authorized','hardware_admission_proven','flash_authorized')),
        'Original plan must be the exact checked preparation review, never full-install permission')
    runtime=_load(config['runtime']['review_reference'])
    require(runtime.get('asset_reference')==config['runtime']['asset_reference']
        and runtime.get('body_sha256')==config['body_sha256']
        and runtime.get('original_plan_sha256')==original_ref['sha256'],'Runtime original-plan/assets differ')
    require(original.get('asset_reference')==config['patch']['asset_reference'],'Patch assets differ from original review')
    local(config['post']['directory'],directory=True)
    require(isinstance(config['post'].get('asset_reference'),dict),'Reviewed post asset reference required')
    return config


def validate_config(config_reference, *, injected=False):
    config=_config_structure(config_reference,injected=injected)
    sources=config.get('sources');snapshots=local(config['source_snapshot_directory'],directory=True)
    require(isinstance(sources,dict) and sources and 'camera_install_flow.py' in sources,'Current flow source closure required')
    if not injected:require(set(source_paths()).issubset(sources),'Complete current host/SDK source closure required')
    for name,digest in sources.items():
        relative=Path(name)
        require(not relative.is_absolute() and '..' not in relative.parts,'Relative source binding required')
        require(sha(safe_path(ROOT/name).read_bytes())==digest==sha(safe_path(snapshots/name).read_bytes()),'Flow source or snapshot changed: '+name)
    return config


def _runtime_assets(config):
    from camera_install_runtime_command import assets_from_reference
    return assets_from_reference(config['runtime']['asset_reference'])


def _patch_assets(config):
    from camera_install_patch_plan import assets_from_directories
    ref=config['patch']['asset_reference']
    return assets_from_directories(local(ref['patch']['directory'],directory=True),local(ref['captures']['directory'],directory=True))


def _post_assets(config):
    from camera_install_post_plan import assets_from_directory
    return assets_from_directory(local(config['post']['directory'],directory=True))


def configured_nonces(config):
    runtime=config['runtime']['asset_reference'];patch=config['patch']['asset_reference'];post=config['post']['asset_reference']
    values=[runtime['p1']['nonce'],runtime['metadata']['nonce'],patch['patch']['nonce'],
        *(patch['captures'][name]['nonce'] for name in ('pre_app','pre_ufp')),*(row['nonce'] for row in post['profiles'].values())]
    require(len(values)==len(set(values)),'Configured once-only job nonces collide')
    return frozenset(values)


def _preflight(config):
    from camera_install_runtime_session import preflight_assets as runtime_check
    from camera_install_patch import preflight_assets as patch_check
    from camera_install_post_session import preflight_assets as post_check
    runtime=runtime_check(_runtime_assets(config));patch,captures=_patch_assets(config);prepared_patch=patch_check(patch,captures)
    require(runtime.reference==config['runtime']['asset_reference'] and prepared_patch.reference==config['patch']['asset_reference'], 'Current reviewed preparation assets changed')
    post=post_check(_post_assets(config));require(post.reference==config['post']['asset_reference'],'Current reviewed post assets changed')
    nonces=[runtime.reference['p1']['nonce'],runtime.reference['metadata']['nonce'],prepared_patch.reference['patch']['nonce'],
        *(config['patch']['asset_reference']['captures'][n]['nonce'] for n in ('pre_app','pre_ufp')),
        *(row['nonce'] for row in post.reference['profiles'].values())]
    require(len(set(nonces))==len(nonces),'All preparation/post native jobs must have distinct fresh nonces')


def init_flow(config_reference, output, *, injected_execution=False):
    require(type(injected_execution) is bool,'Explicit flow provenance mode required')
    config=validate_config(config_reference,injected=injected_execution)
    if not injected_execution:_system()
    folder=local(output);require(not folder.exists(),'Fresh flow output required')
    folder.mkdir(mode=0o700,parents=True);(folder/'events').mkdir(mode=0o700);(folder/'steps').mkdir(mode=0o700)
    lease_path=folder/'model-device.lock' if injected_execution else DEFAULT_LOCK
    with CameraDeviceLease('fl23-flow-init',lock_path=lease_path):
        require(validate_config(config_reference,injected=injected_execution)==config,'Flow config changed before initialization ownership')
        if not injected_execution:_preflight(config)
        root=folder/'model-sessions' if injected_execution else DEFAULT_SESSIONS
        journal=InstallJournal.create(root,'fl23-'+uuid.uuid4().hex,plan_sha256=config['original_plan_reference']['sha256'],body_sha256=config['body_sha256'],model='ILCE-7M4')
        header=dict(schema=SCHEMA,config_reference=deepcopy(config_reference),journal_session=str(journal.session_dir),
            injected_execution=injected_execution,source_is_hardware=False,installation_authorized=False,candidate_sha256=DIGEST)
        durable_new(folder/'flow.json',header)
    return status(folder)


def _producer_journal_binding(header, config, intent):
    """Check only the hash-bound ancestor recorded before a successful actor."""
    from camera_install_journal import _read_json, _canonical, _binding, _transition
    session=local(header['journal_session'],directory=True)
    require(session.parent==DEFAULT_SESSIONS,'Canonical producer journal required')
    expected=dict(body_sha256=config['body_sha256'],plan_sha256=config['original_plan_reference']['sha256'],model='ILCE-7M4')
    target=intent.get('journal_event_sha256')
    require(isinstance(target,str) and len(target)==64,'Producer intent journal ancestor required')
    history=[]
    for index in range(1,10001):
        raw,event=_read_json(session/f'{index:08d}.json')
        require(set(event)=={'schema','session_id','seq','prev_sha256','binding','state','details','event_sha256'}
                and raw==_canonical(event) and type(event['schema']) is int and event['schema']==1
                and type(event['seq']) is int and event['seq']==index and event['session_id']==session.name,
                'Producer journal ancestor shape differs')
        _binding(event['binding'])
        require(event['binding']==expected and event['prev_sha256']==(history[-1]['event_sha256'] if history else '0'*64)
                and event['event_sha256']==sha(_canonical({k:v for k,v in event.items() if k!='event_sha256'})),
                'Producer journal ancestor binding/hash differs')
        _transition(history,event['state']);history.append(event)
        if event['event_sha256']==target:return expected
    raise ValueError('Producer journal ancestor exceeded bound')


def _open(folder, *, _producer_step=None):
    require(_producer_step is None or _producer_step in ('probe','activate','withdraw'),'Bounded producer step required')
    producer_intent=None
    folder=local(folder,directory=True);header=_load(reference(folder/'flow.json'))
    require(header.get('schema')==SCHEMA and type(header.get('injected_execution')) is bool,'Flow header required')
    continuation=folder/'source-continuation.json'
    if continuation.exists() or continuation.is_symlink():
        from camera_install_flow_continuation import validate_active
        config=validate_active(folder,header)
    else:
        config=validate_config(header['config_reference'],injected=header['injected_execution'])
    events=[];previous='0'*64;active=None;attempts={};completed=set();unknown=False;blocked_reports=[]
    for index,path in enumerate(sorted((folder/'events').iterdir()),1):
        require(path.name==f'{index:08d}.json','Incomplete flow event sequence')
        event=_load(reference(path));require(event.get('prev_sha256')==previous and event.get('event_sha256')==sha(canonical({k:v for k,v in event.items() if k!='event_sha256'})),'Flow event chain changed')
        step,phase,attempt=event.get('step'),event.get('phase'),event.get('attempt')
        require(step in STEPS and phase in PHASES and type(attempt) is int and attempt>0,'Invalid flow step/phase/attempt')
        if phase=='INTENT':
            require(active is None and not unknown and step not in completed and attempt==attempts.get(step,0)+1,'Invalid or overlapping flow attempt')
            attempts[step]=attempt;active=(step,attempt)
            if step==_producer_step:producer_intent=event
        else:
            require(active==(step,attempt),'Flow result has no matching active intent')
            active=None
            if phase=='COMPLETED':completed.add(step);_load(event['receipt_reference'])
            elif phase=='UNKNOWN':unknown=True
            elif phase=='BLOCKED_READ_ONLY':
                require(step=='cancel' and header['injected_execution'] is False and event.get('journal_unchanged') is True
                    and event.get('cancellation_recorded') is False and event.get('automatic_retry') is False,'Invalid known read-only blocking phase')
                result=_load(event['receipt_reference']);require(result.get('blocked_read_only') is True,'Missing blocked observation artifact')
                blocked_reports.append(result)
            else:
                require(step in HOST_ONLY and event.get('journal_unchanged') is True and event.get('SDK_requests_attempted') is False
                    and event.get('manual_instruction_released') is False and event.get('automatic_retry') is False,'Invalid local-only rejection proof')
        events.append(event);previous=event['event_sha256']
        if step==_producer_step and phase=='COMPLETED':
            require(producer_intent is not None and header['injected_execution'] is False
                    and event.get('source_is_hardware') is True,'Real successful producer prefix required')
            return folder,header,config,events,_producer_journal_binding(header,config,producer_intent)
    require(_producer_step is None,'Required completed producer step missing')
    journal=InstallJournal.open(local(header['journal_session'],directory=True))
    require(journal.binding==dict(body_sha256=config['body_sha256'],plan_sha256=config['original_plan_reference']['sha256'],model='ILCE-7M4'),'Flow original journal binding changed')
    if not header['injected_execution']:require(journal.session_dir.parent==DEFAULT_SESSIONS,'Canonical production journal required')
    for result in blocked_reports:
        report=_validate_blocked_cancel(result['artifact_reference'],journal.binding,journal.events,journal.session_dir)
        require(report['state']==result.get('state'),'Blocked flow result differs from its complete observation')
    return folder,header,config,events,journal


def _append(folder,events,step,phase,**values):
    require(step in STEPS and phase in PHASES,'Known flow step/phase required')
    previous_attempt=max((e['attempt'] for e in events if e['step']==step),default=0)
    attempt=previous_attempt+1 if phase=='INTENT' else previous_attempt
    event=dict(step=step,phase=phase,attempt=attempt,prev_sha256=events[-1]['event_sha256'] if events else '0'*64,**values)
    event['event_sha256']=sha(canonical(event));durable_new(folder/'events'/f'{len(events)+1:08d}.json',event);events.append(event);return event


def _unresolved(events):
    resolved={(e['step'],e['attempt']) for e in events if e['phase'] in ('COMPLETED','REJECTED_LOCAL','BLOCKED_READ_ONLY')}
    return {e['step'] for e in events if e['phase']=='INTENT' and (e['step'],e['attempt']) not in resolved}


def status(flow_dir):
    _,header,_,events,journal=_open(flow_dir)
    completed={event['step'] for event in events if event['phase']=='COMPLETED'}
    unknown=_unresolved(events)
    return dict(state=journal.state,journal_session=str(journal.session_dir),completed_steps=sorted(completed),
        unresolved_steps=sorted(unknown),blocked=bool(unknown) or journal.state=='STOPPED_UNKNOWN',
        injected_execution=header['injected_execution'],installation_proven=False,automatic_retry=False,
        locally_rejected_steps=sorted({e['step'] for e in events if e['phase']=='REJECTED_LOCAL'}-completed),
        blocked_read_only_steps=sorted({e['step'] for e in events if e['phase']=='BLOCKED_READ_ONLY'}-completed),
        cancellation_recorded=journal.state in ('INSTALL_PREPARATION_CANCELLED','CANCELLED_BEFORE_DEVICE_WRITE'))


def _artifact(events,step):
    matches=[event for event in events if event['step']==step and event['phase']=='COMPLETED']
    require(len(matches)==1,'Required completed flow step missing: '+step)
    result=_load(matches[0]['receipt_reference'])
    ref=result['artifact_reference'];_load(ref);return ref


def _read_assets(prepared):
    from camera_install_patch_read_execution import InstallPatchReadAssets
    return InstallPatchReadAssets(Path(prepared['directory']),*(prepared[k] for k in
        ('manifest_sha256','module_sha256','native_model_sha256','bootstrap_model_sha256','target_spec_sha256')))


def _tool(script,*arguments):
    require(script in ('build_install_patch_read_offline.py','emulate_install_patch_read_offline.py',
        'build_install_runtime_metadata_offline.py','emulate_install_runtime_metadata_offline.py'),'Fixed offline generator required')
    _source_only_runtime()
    command=[sys.executable,'-B','-E','-s','-X','pycache_prefix='+str(ROOT/SOURCE_ONLY_RUNTIME['pycache_prefix']),str(ROOT/'tools'/script),*map(str,arguments)]
    subprocess.run(command,check=True,timeout=600)


def _save_canonical(path, value):
    path=local(path);raw=canonical(value)
    with path.open('xb') as stream:
        os.fchmod(stream.fileno(),0o600)
        require(stream.write(raw)==len(raw),'Short canonical verification write')
        stream.flush();os.fsync(stream.fileno())
    fd=os.open(path.parent,os.O_RDONLY)
    try:os.fsync(fd)
    finally:os.close(fd)
    require(path.read_bytes()==raw,'Canonical verification readback differs')


def _prepare_read(folder,config,pending):
    from tools.verify_install_patch_read_offline import verify
    from camera_install_patch_read_execution import InstallPatchReadAssets,preflight_assets
    from camera_install_patch_read_plan import seal
    job=folder/'job';_tool('build_install_patch_read_offline.py','--output',job,'--pending-receipt',pending['path'],'--body-sha256',config['body_sha256'],'--plan-sha256',config['original_plan_reference']['sha256'])
    durable_new(job/'verification.json',verify(job));_tool('emulate_install_patch_read_offline.py','--job',job,'--report',job/'native-model-report.json','--bootstrap-report',job/'bootstrap-model-report.json')
    spec=json.loads((job/'target-spec.json').read_bytes())
    assets=InstallPatchReadAssets(job,*(reference(job/name)['sha256'] for name in ('manifest.json','libJit.so','native-model-report.json','bootstrap-model-report.json')),__import__('camera_install_patch_read').spec_sha256(spec))
    require(json.loads((job/'manifest.json').read_bytes())['nonce'] not in configured_nonces(config), 'Generated read nonce collides with a configured job')
    review=seal(folder/'review',assets=assets,pending_reference=pending,expected_body_sha256=config['body_sha256'],plan_sha256=config['original_plan_reference']['sha256'])
    prepared=preflight_assets(assets,pending_reference=pending,expected_body_sha256=config['body_sha256'],plan_sha256=config['original_plan_reference']['sha256'])
    return dict(asset_reference=prepared.reference,review_reference=dict(path=review['review_path'],sha256=review['review_sha256']))


def _validate_blocked_cancel(ref,binding,history,session_dir,expected_lease=None):
    from camera_install_receipts import source_declaration,validate_completed_current_read
    import camera_install_cancel_session as cancel
    report=_load(ref)
    require(report.get('schema')==cancel.SCHEMA and all(report.get(k)==v for k,v in binding.items())
        and report.get('session_id')==Path(session_dir).name and source_declaration(report) is True
        and report.get('injected_execution') is False and report.get('cancellation_recorded') is False
        and report.get('no_FLASH_history') is True and report.get('separately_authorized_cleanup_required') is True
        and all(report.get(k) is False for k in cancel.FALSE_CLAIMS),'Trusted completed read-only block required')
    positions=[i for i,e in enumerate(history) if e['state']=='INSTALL_PATCH_AWAITING_OPERATOR_RECONNECT' and e['event_sha256']==report.get('pending_event_sha256')]
    require(len(positions)==1,'Original pending observation ancestor required');prefix=history[:positions[0]+1]
    require(report.get('history_sha256')==sha(canonical(prefix)),'Blocked observation history differs')
    if expected_lease is not None:require(report.get('lease_identity')==expected_lease,'Blocked observation changed lease')
    cancel._history(binding,prefix,session_dir,report['pending_reference'],report['stage_reference'])
    if report.get('state')=='CANCELLATION_BLOCKED_CURRENT_OBSERVATION':
        require(report.get('scope')==cancel.SCOPE and report.get('producer_kind')==cancel.DEFAULT_PRODUCER
            and report.get('both_targets_currently_original') is False,'Known non-original read block required')
        completed=validate_completed_current_read(report['completed_read_reference'],pending_reference=report['pending_reference'],binding=binding,history=prefix,session_dir=session_dir)
        require(completed['source_is_hardware'] is True and completed['proof']['observation']!='ORIGINAL'
            and report.get('current_read_proof')==completed['proof'] and report.get('completed_read_payload_sha256')==sha(canonical(completed['receipt'])),'Complete raw current observation required')
    elif report.get('state')=='CANCELLATION_BLOCKED_SAME_AP_BOOT_EPOCH':
        from camera_install_epoch_session import validate_completed_pending_epoch
        require(report.get('scope')==cancel.EPOCH_CANCEL_SCOPE and report.get('producer_kind')=='DEFAULT_OWNED_PENDING_EPOCH_AND_INACTIVE_CARD'
            and report.get('AP_boot_epoch_change_observed') is False and report.get('previous_AP_process_contexts_ended') is False,'Known same-epoch block required')
        completed=validate_completed_pending_epoch(report['completed_epoch_reference'],pending_reference=report['pending_reference'],initial_runtime_reference=report['initial_runtime_reference'],withdrawal_reference=report['withdrawal_reference'],binding=binding,history=prefix,session_dir=session_dir)
        require(completed['source_is_hardware'] is True and completed['boot_id_differs'] is False
            and report.get('initial_boot_id')==completed['initial_boot_id'] and report.get('current_boot_id')==completed['current_boot_id']
            and report.get('completed_epoch_payload_sha256')==sha(canonical(completed['receipt'])),'Complete raw AP epoch observation required')
    else:raise ValueError('Only two known completed read-only cancellation blocks are recoverable')
    require(completed['receipt'].get('lease_identity')==report.get('lease_identity'),'Blocked native receipt ownership differs')
    return report


def _prepare_epoch(folder,config,events,journal):
    from camera_install_epoch_plan import seal
    from camera_install_runtime_metadata import MetadataAssets
    from tools.verify_install_runtime_metadata_offline import verify
    job=folder/'job';_tool('build_install_runtime_metadata_offline.py','--output',job)
    _save_canonical(job/'verification.json',verify(job));_tool('emulate_install_runtime_metadata_offline.py','--job',job)
    require(json.loads((job/'manifest.json').read_bytes())['nonce'] not in configured_nonces(config),'Generated epoch nonce collides with a configured job')
    assets=MetadataAssets(job,*(reference(job/name)['sha256'] for name in ('manifest.json','libJit.so','native-model-report.json','bootstrap-model-report.json')))
    result=seal(folder/'review',assets=assets,body_sha256=config['body_sha256'],plan_sha256=config['original_plan_reference']['sha256'],pending_reference=_artifact(events,'patch'),initial_runtime_reference=_artifact(events,'runtime'),withdrawal_reference=_artifact(events,'withdraw'),journal=journal)
    durable_new(folder/'epoch-preparation.json',dict(result,metadata_assets={k:str(v) if isinstance(v,Path) else v for k,v in vars(assets).items()}))
    return dict(artifact_reference=reference(folder/'epoch-preparation.json'))


def _dispatch(step,folder,config,events,journal,lease,operator,*,before_journal_write=None):
    def recording():
        if before_journal_write is not None:before_journal_write()
    body,plan=config['body_sha256'],config['original_plan_reference']['sha256']
    common=dict(journal=journal,lease=lease)
    if step=='runtime':
        from camera_install_runtime_session import run_runtime_session
        review=config['runtime']['review_reference'];values=_load(review)
        run_runtime_session(body,folder,plan_sha256=plan,review_path=review['path'],review_sha256=review['sha256'],assets=_runtime_assets(config),required_partition_sizes=values['required_partition_sizes'],runtime_read_authorized=True,**common)
        return dict(artifact_reference=reference(folder/'runtime-session-exit.json'))
    if step=='probe':
        from camera_sd_stage import discover
        from tools.card_protocol_probe import probe
        _artifact(events,'runtime')
        require(config.get('card_activation_protocol')==BACKUP_COPY_ATOMIC_REPLACE,
                'Scratch probe is only for the explicitly selected replacement protocol')
        require(all(operator.get(key) is True for key in ('scratch_authorized','single_writer_acknowledged','slot1_confirmed')),
                'Explicit scratch, single-writer and Slot 1 approval required')
        volume=discover();require(volume['body_sha256']==body,'Probe camera differs from flow')
        ref=probe(volume['mount'],folder/'probe-run',expected_card_identity=volume,identity_reader=discover,
            scratch_authorized=True,single_writer_acknowledged=True)
        return dict(artifact_reference=ref)
    if step=='stage':
        import camera_sd_stage as sd
        _artifact(events,'runtime')
        if config.get('card_activation_protocol')==BACKUP_COPY_ATOMIC_REPLACE:_artifact(events,'probe')
        recording();journal.advance('SD_STAGE_INTENT',details=dict(operation='formal-flow-stage',config_reference=config['original_plan_reference']))
        require(sd.discover()['body_sha256']==body,'Staging camera differs from flow body')
        sd.stage(report_path=folder,**common);ref=reference(folder/'completed.json')
        recording();journal.advance('SD_STAGED',details=dict(stage_report=ref['path'],stage_report_sha256=ref['sha256']))
        return dict(artifact_reference=ref)
    if step=='activate':
        from camera_sd_stage import activate_staged
        require(operator.get('slot1_confirmed') is True,'Explicit Slot 1 observation required')
        protocol=config.get('card_activation_protocol',EXCLUSIVE_RENAME)
        require(protocol != BACKUP_COPY_ATOMIC_REPLACE or operator.get('single_writer_acknowledged') is True,
                'Explicit same-card single-writer acknowledgement required')
        probe_reference=_artifact(events,'probe') if protocol==BACKUP_COPY_ATOMIC_REPLACE else None
        stage=_artifact(events,'stage');activate_staged(activation_authorized=True,slot1_confirmed=True,
            report_path=Path(stage['path']).parent,protocol=protocol,
            single_writer_acknowledged=operator.get('single_writer_acknowledged') is True,
            compatibility_probe_reference=probe_reference,flow_directory=folder.parents[1],**common)
        return dict(artifact_reference=reference(Path(stage['path']).parent/'activated-preview-only.json'))
    if step=='patch':
        from camera_install_patch_session import run_install_patch_session
        _artifact(events,'activate');require(operator.get('patches_remain_acknowledged') is True,'Persistent volatile-patch acknowledgement required')
        assets,captures=_patch_assets(config)
        run_install_patch_session(body,folder,plan_sha256=plan,review_path=config['patch']['review_reference']['path'],assets=assets,capture_assets=captures,
            volatile_patch_authorized=True,formal_preparation_authorized=True,patches_remain_acknowledged=True,**common)
        return dict(artifact_reference=reference(folder/'install-patch-awaiting-reconnect.json'))
    if step=='prepare-read':
        prepared=_prepare_read(folder,config,_artifact(events,'patch'));durable_new(folder/'read-preparation.json',prepared)
        return dict(artifact_reference=reference(folder/'read-preparation.json'))
    if step=='read':
        from camera_install_patch_read_session import run_current_read_session
        prepared=_load(_artifact(events,'prepare-read'));review=prepared['review_reference']
        run_current_read_session(body,folder,plan_sha256=plan,pending_reference=_artifact(events,'patch'),review_path=review['path'],review_sha256=review['sha256'],assets=_read_assets(prepared['asset_reference']),read_authorized=True,**common)
        return dict(artifact_reference=reference(folder/'current-read-session-exit.json'))
    if step=='observe-card':
        from camera_install_card import observe_active_card
        value=observe_active_card(_artifact(events,'stage'),_artifact(events,'activate'),body_sha256=body,card_read_authorized=True,**common)
        durable_new(folder/'active-card.json',value);return dict(artifact_reference=reference(folder/'active-card.json'))
    if step=='admit':
        from camera_install_admission import seal_admission
        refs=operator.get('references');require(isinstance(refs,dict),'Explicit complete admission references required')
        for key,name in (('runtime','runtime'),('pending','patch'),('current_read','read'),('card','observe-card')):
            require(refs.get(key)==_artifact(events,name),'Admission uses another completed '+key)
        ref=seal_admission(folder/'admission.json',binding=journal.binding,history=journal.events,session_dir=journal.session_dir,references=refs)
        recording();journal.record_install_admission(ref['path']);return dict(artifact_reference=ref)
    if step=='start':
        from camera_install_admission import seal_start_intent
        ref=seal_start_intent(folder/'start-intent.json',admission_reference=_artifact(events,'admit'),binding=journal.binding,history=journal.events,session_dir=journal.session_dir)
        recording();journal.record_flash_may_have_started(ref['path'])
        return dict(artifact_reference=ref,manual_instruction='Only now follow the separately approved final on-camera Update confirmation. No host updater or power command was sent.')
    if step=='complete':
        from camera_install_completion import seal_completion
        ref=seal_completion(folder/'device-completion.json',binding=journal.binding,history=journal.events,session_dir=journal.session_dir,observations=operator)
        recording();journal.record_device_completion(ref['path']);return dict(artifact_reference=ref)
    if step=='prepare-post':
        from camera_install_post_plan import seal
        result=seal(folder/'review',assets=_post_assets(config),before_group=Path(_artifact(events,'runtime')['path']).parent,
            original_plan_reference=config['original_plan_reference'],completion_reference=_artifact(events,'complete'),body_sha256=body)
        durable_new(folder/'post-preparation.json',result);return dict(artifact_reference=reference(folder/'post-preparation.json'))
    if step=='post':
        from camera_install_post_session import run_post_session
        prepared=_load(_artifact(events,'prepare-post'))
        runtime_group=Path(_artifact(events,'runtime')['path']).parent
        run_post_session(body,runtime_group,plan_sha256=plan,review_path=prepared['review_path'],review_sha256=prepared['review_sha256'],completion_reference=_artifact(events,'complete'),assets=_post_assets(config),post_capture_authorized=True,**common)
        return dict(artifact_reference=reference(runtime_group/'verification.json'))
    if step=='content':
        from camera_postinstall_verify import verify_capture_run
        ref=_artifact(events,'post');saved=_load(ref);group=Path(ref['path']).parent;descriptor=json.loads((group/'group.json').read_bytes())
        verified=verify_capture_run(group/'capture-run.json',plan_sha256=plan,body_sha256=body,model='ILCE-7M4',group_nonce=descriptor['group_nonce'],source_is_hardware=True)
        require(saved==verified and saved.get('source_is_hardware') is True and saved.get('all_passed') is True,'Actual complete content verification required')
        recording();journal.record_content_verified(ref['path']);return dict(artifact_reference=ref)
    if step=='features':
        from camera_install_features import record_functional_acceptance
        result=record_functional_acceptance(folder/'functional-acceptance.json',journal=journal,content_reference=_artifact(events,'content'),completion_reference=_artifact(events,'complete'),
            candidate_sha256=DIGEST,operator_report=operator['operator_report'],media_references=operator['media_references'])
        return dict(artifact_reference=dict(path=result['path'],sha256=result['sha256']))
    if step=='withdraw':
        from camera_install_card_withdraw import withdraw_active_card,withdraw_staged_card
        require(all(operator.get(k) is True for k in ('operator_never_started_confirmed','operator_health_confirmed')),'Explicit healthy/never-started withdrawal statements required')
        args=dict(body_sha256=body,plan_sha256=plan,withdrawal_authorized=True,operator_never_started_confirmed=True,operator_health_confirmed=True,
            single_writer_acknowledged=operator.get('single_writer_acknowledged') is True,
            compatibility_probe_reference=_artifact(events,'probe') if config.get('card_activation_protocol')==BACKUP_COPY_ATOMIC_REPLACE else None,
            flow_directory=folder.parents[1],**common)
        if journal.state=='SD_STAGED':withdraw_staged_card(_artifact(events,'stage'),_artifact(events,'activate'),folder,**args)
        else:withdraw_active_card(_artifact(events,'stage'),_artifact(events,'activate'),folder,pending_reference=_artifact(events,'patch'),**args)
        return dict(artifact_reference=reference(folder/'withdrawal-completed.json'))
    if step=='prepare-epoch':return _prepare_epoch(folder,config,events,journal)
    if step=='cancel':
        require(operator.get('operator_never_started_confirmed') is True and operator.get('operator_health_confirmed') is True,'Explicit never-started healthy cancellation required')
        if journal.state=='PLANNED':
            recording();journal.advance('CANCELLED_BEFORE_DEVICE_WRITE',details=dict(reason='formal_flow_cancelled_before_any_card_or_RAM_step'))
            durable_new(folder/'cancelled.json',dict(state=journal.state,installation_authorized=False));return dict(artifact_reference=reference(folder/'cancelled.json'),state=journal.state,cancellation_recorded=True)
        if journal.state=='SD_STAGED':
            if any(e['step']=='activate' and e['phase']=='COMPLETED' for e in events):_artifact(events,'withdraw')
            from camera_install_cancel import observe_inactive_card
            from camera_sd_stage import discover
            saved_identity=_held_lease(lease);saved_history=deepcopy(journal.events)
            def pinned_discover():
                require(_held_lease(lease)==saved_identity and InstallJournal.open(journal.session_dir).events==saved_history==journal.events,'Pre-RAM cancellation context changed')
                value=discover()
                require(_held_lease(lease)==saved_identity and InstallJournal.open(journal.session_dir).events==saved_history==journal.events,'Pre-RAM cancellation context changed during discovery')
                return value
            value=observe_inactive_card(_artifact(events,'stage'),body_sha256=body,discover=pinned_discover)
            durable_new(folder/'inactive-card.json',value)
            recording();journal.advance('CANCELLED_BEFORE_DEVICE_WRITE',details=dict(reason='formal_flow_card_inactive_before_RAM',inactive_card_reference=reference(folder/'inactive-card.json')))
            durable_new(folder/'cancelled.json',dict(state=journal.state,installation_authorized=False));return dict(artifact_reference=reference(folder/'cancelled.json'),state=journal.state,cancellation_recorded=True)
        strategy=operator.get('strategy');_artifact(events,'withdraw');cancel_history=deepcopy(journal.events);cancel_identity=_held_lease(lease)
        if strategy=='current_original':
            from camera_install_cancel_session import run_cancellation_session
            prepare_dir=folder/'fresh-read-preparation';prepare_dir.mkdir(mode=0o700);prepared=_prepare_read(prepare_dir,config,_artifact(events,'patch'));review=prepared['review_reference']
            capture=folder/'cancel-read';capture.mkdir(mode=0o700)
            result=run_cancellation_session(body,capture,plan_sha256=plan,pending_reference=_artifact(events,'patch'),stage_reference=_artifact(events,'stage'),
                read_assets=_read_assets(prepared['asset_reference']),read_review_path=review['path'],read_review_sha256=review['sha256'],
                cancellation_authorized=True,card_read_authorized=True,operator_health_confirmed=True,operator_never_started_confirmed=True,**common)
        elif strategy=='AP_epoch':
            from camera_install_cancel_session import run_epoch_cancellation_session
            from camera_install_runtime_metadata import MetadataAssets
            if any(e['step']=='cancel' and e['phase']=='BLOCKED_READ_ONLY' and _load(_load(e['receipt_reference'])['artifact_reference'])['state']=='CANCELLATION_BLOCKED_SAME_AP_BOOT_EPOCH' for e in events):
                fresh=folder/'fresh-epoch-preparation';fresh.mkdir(mode=0o700);prepared=_load(_prepare_epoch(fresh,config,events,journal)['artifact_reference'])
            else:prepared=_load(_artifact(events,'prepare-epoch'))
            assets=MetadataAssets(**{**prepared['metadata_assets'],'job_dir':Path(prepared['metadata_assets']['job_dir'])})
            require(operator.get('manual_AP_reboot_confirmed') is True and operator.get('withdrawal_preceded_manual_AP_reboot_confirmed') is True,'Explicit withdrawal-before-manual-AP-reboot order required')
            session=folder/'AP-epoch-session';session.mkdir(mode=0o700)
            result=run_epoch_cancellation_session(body,session,plan_sha256=plan,pending_reference=_artifact(events,'patch'),stage_reference=_artifact(events,'stage'),
                initial_runtime_reference=_artifact(events,'runtime'),withdrawal_reference=_artifact(events,'withdraw'),epoch_assets=assets,epoch_review_path=prepared['review_path'],epoch_review_sha256=prepared['review_sha256'],
                cancellation_authorized=True,card_read_authorized=True,operator_health_confirmed=True,operator_never_started_confirmed=True,
                manual_AP_reboot_confirmed=True,withdrawal_preceded_manual_AP_reboot_confirmed=True,**common)
        else:raise ValueError('Explicit current_original or AP_epoch cancellation strategy required')
        require(_held_lease(lease)==cancel_identity,'Cancel helper changed lease')
        if result.get('state') in ('CANCELLATION_BLOCKED_CURRENT_OBSERVATION','CANCELLATION_BLOCKED_SAME_AP_BOOT_EPOCH'):
            require(InstallJournal.open(journal.session_dir).events==cancel_history==journal.events and journal.state=='INSTALL_PATCH_AWAITING_OPERATOR_RECONNECT','Read-only blocked helper changed pending history')
            saved=(capture if strategy=='current_original' else session)/'cancellation-blocked.json';ref=reference(saved)
            require(_load(ref)==result,'Blocked helper return differs from its saved artifact')
            _validate_blocked_cancel(ref,journal.binding,cancel_history,journal.session_dir,cancel_identity)
            return dict(artifact_reference=ref,state=result['state'],blocked_read_only=True,cancellation_recorded=False)
        require(result.get('cancellation_recorded') is True and journal.state=='INSTALL_PREPARATION_CANCELLED'
            and InstallJournal.open(journal.session_dir).events==journal.events,'Cancel helper did not record a real terminal cancellation')
        durable_new(folder/'cancelled.json',result);return dict(artifact_reference=reference(folder/'cancelled.json'),state=journal.state,cancellation_recorded=True)
    raise ValueError('Unknown formal flow step')


def run_step(flow_dir, step, *, step_authorized=False, camera_ready=False, operator_reference=None, step_injector=None):
    require(step in STEPS and step_authorized is True,'One explicit step consent required')
    require(step_injector is None or callable(step_injector),'Callable whole-step injection required')
    folder,header,config,events,journal=_open(flow_dir);injected=header['injected_execution']
    require((step_injector is not None)==injected,'Injected flows cannot fall through to production actors')
    require(not injected or step not in FORMAL,'Injected flow cannot record formal admission/start/completion/content/acceptance')
    require(not _unresolved(events), 'Unresolved flow attempt; no automatic retry')
    require(not any(e['step']==step and e['phase']=='COMPLETED' for e in events),'Single-use step already completed')
    require(journal.state in STATES[step],'Journal state does not permit this step')
    require(step not in ('admit','start','activate','patch','observe-card') or not any(e['step']=='withdraw' and e['phase']=='COMPLETED' for e in events),
        'Withdrawn candidate invalidates the previous activation/card/read admission path')
    physical=step in PHYSICAL and not (step=='cancel' and journal.state=='PLANNED')
    require(not physical or camera_ready is True,'Explicit connected-camera readiness required')
    if not injected:_system(physical)
    operator={} if operator_reference is None else _load(operator_reference)
    continuation=reference(folder/'source-continuation.json') if (folder/'source-continuation.json').exists() else None
    def source_context():
        current_ref=reference(folder/'source-continuation.json') if (folder/'source-continuation.json').exists() else None
        require(current_ref==continuation,'Source continuation changed during operation')
        if continuation is not None:
            from camera_install_flow_continuation import authorize_step
            authorize_step(folder,step,operator)
    source_context()
    lease_path=folder/'model-device.lock' if injected else DEFAULT_LOCK
    with CameraDeviceLease('fl23-flow-'+step,lock_path=lease_path) as lease:
        # Repeat local checks under global ownership, before intent or lower I/O.
        _,again,current,current_events,current_journal=_open(folder)
        require(again==header and current==config and current_events==events and current_journal.events==journal.events,'Flow or journal changed before step ownership')
        source_context()
        assert_operation_allowed(journal,allowed_states=STATES[step]);identity=_held_lease(lease)
        previous_history=deepcopy(journal.events);journal_write_attempted=False
        local_pin=JournalSnapshotPin(journal,lease) if step in HOST_ONLY and not injected else None
        def recording():
            nonlocal journal_write_attempted
            require(_held_lease(lease)==identity and InstallJournal.open(journal.session_dir).events==journal.events,'Flow ownership/history changed before journal record')
            source_context()
            journal_write_attempted=True
        attempt=max((e['attempt'] for e in events if e['step']==step),default=0)+1
        target=folder/'steps'/(step if attempt==1 else f'{step}-attempt-{attempt:04d}')
        try:
            _append(folder,events,step,'INTENT',journal_event_sha256=journal.events[-1]['event_sha256'],lease_identity=identity,source_is_hardware=False,automatic_retry=False,
                    **(dict(source_continuation_reference=continuation) if continuation is not None else {}))
        except BaseException:
            if local_pin is not None:
                try:local_pin.close()
                except OSError:pass
            raise
        try:
            if step!='stage':target.mkdir(mode=0o700)
            source_context()
            if injected:
                result=step_injector(step,dict(config=deepcopy(config),journal=journal,evidence=target,operator=deepcopy(operator)))
                require(isinstance(result,dict) and result.get('source_is_hardware') is False,'Injected actor must explicitly remain nonhardware')
                require(all(result.get(k,False) is False for k in ('installation_authorized','write_admission','ready_for_confirmation','firmware_installation_proven')),'Injected actor cannot grant permission')
                if not target.exists():target.mkdir(mode=0o700)
            else:result=_dispatch(step,target,config,events,journal,lease,operator,before_journal_write=recording)
            require(_held_lease(lease)==identity,'Flow lease changed before receipt persistence')
            blocked=result.get('blocked_read_only') is True
            if blocked:
                require(step=='cancel' and not injected and not journal_write_attempted and journal.state=='INSTALL_PATCH_AWAITING_OPERATOR_RECONNECT'
                    and InstallJournal.open(journal.session_dir).events==previous_history==journal.events,'Only an unchanged trusted pending read can be nonterminal blocked')
                _validate_blocked_cancel(result['artifact_reference'],journal.binding,previous_history,journal.session_dir,identity)
            if step=='cancel' and not injected and not blocked:
                require(result.get('cancellation_recorded') is True and journal.state in ('INSTALL_PREPARATION_CANCELLED','CANCELLED_BEFORE_DEVICE_WRITE'),'Cancellation is not terminal')
            source_context()
            receipt=target/'flow-step-result.json';durable_new(receipt,result)
            if local_pin is not None:local_pin.close();local_pin=None
            _append(folder,events,step,'BLOCKED_READ_ONLY' if blocked else 'COMPLETED',receipt_reference=reference(receipt),source_is_hardware=not injected and physical,
                **(dict(journal_unchanged=True,cancellation_recorded=False,automatic_retry=False) if blocked else {}))
        except BaseException as error:
            rejected_local=False
            if local_pin is not None and not journal_write_attempted:
                try:
                    local_pin.check()
                    require(InstallJournal.open(journal.session_dir).events==previous_history==journal.events,'Journal changed after local failure')
                    require(_open(folder)[2]==config,'Source or assets changed after local failure')
                    local_pin.close();local_pin=None;rejected_local=True
                except BaseException:pass
            _append(folder,events,step,'REJECTED_LOCAL' if rejected_local else 'UNKNOWN',error_type=type(error).__name__,
                automatic_retry=False,automatic_STOP=False,automatic_reboot=False,
                **(dict(journal_unchanged=True,SDK_requests_attempted=False,manual_instruction_released=False) if rejected_local else {}))
            raise
        finally:
            if local_pin is not None:
                try:local_pin.close()
                except OSError:pass
    result_status=status(folder)
    if step=='start' and not injected:result_status['manual_instruction']=result['manual_instruction']
    return result_status


def main():
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='command',required=True)
    init=sub.add_parser('init');init.add_argument('--config',required=True);init.add_argument('--config-sha256',required=True);init.add_argument('--output',required=True)
    show=sub.add_parser('status');show.add_argument('--flow',required=True)
    step=sub.add_parser('step');step.add_argument('--flow',required=True);step.add_argument('step',choices=STEPS);step.add_argument('--step-authorized',action='store_true');step.add_argument('--camera-ready',action='store_true');step.add_argument('--operator-artifact');step.add_argument('--operator-sha256')
    args=parser.parse_args();_source_only_runtime()
    if args.command=='init':result=init_flow(dict(path=str(local(args.config)),sha256=args.config_sha256),args.output)
    elif args.command=='status':result=status(args.flow)
    else:
        require((args.operator_artifact is None)==(args.operator_sha256 is None),'Complete operator artifact reference required')
        operator=None if args.operator_artifact is None else dict(path=str(local(args.operator_artifact)),sha256=args.operator_sha256)
        result=run_step(args.flow,args.step,step_authorized=args.step_authorized,camera_ready=args.camera_ready,operator_reference=operator)
    print(json.dumps(result,indent=2))


if __name__=='__main__':main()
