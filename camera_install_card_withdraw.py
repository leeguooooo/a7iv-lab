"""Explicitly withdraw an active card candidate without touching camera RAM.

The selected file protocol preserves uncertain intermediate states without retry.
No failure path rolls back, retries a rename, reboots or clears a journal.
"""
from contextlib import ExitStack
from copy import deepcopy
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import stat

import camera_install_cancel as card
from camera_sd_stage import EXCLUSIVE_RENAME, BACKUP_COPY_ATOMIC_REPLACE, validate_activation_receipt_protocol
from camera_device_lease import DEFAULT_LOCK
from camera_install_cancel_session import _history
from camera_install_journal import InstallJournal
from camera_install_patch_session import _held_lease, _source_only_runtime, canonical_sha256
from camera_operation_guard import DEFAULT_SESSIONS, assert_operation_allowed
from camera_stream_execution import durable_new

PENDING='INSTALL_PATCH_AWAITING_OPERATOR_RECONNECT'

@dataclass(frozen=True)
class _PendingContext:
    reference: dict

@dataclass(frozen=True)
class _StagedContext:
    pass


def require(ok,message):
    if not ok:raise ValueError(message)


def validate_completed_pending(reference,**kwargs):
    from camera_install_receipts import validate_completed_pending as validate
    return validate(reference,**kwargs)


def _rename_exclusive_at(source,target,*,source_dir_fd,target_dir_fd):
    """Darwin renameatx_np with RENAME_EXCL; both directories stay open."""
    import ctypes
    import sys
    require(sys.platform=='darwin','Darwin descriptor-relative exclusive rename required')
    libc=ctypes.CDLL('/usr/lib/libSystem.B.dylib',use_errno=True)
    rename=libc.renameatx_np
    rename.argtypes=(ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint)
    rename.restype=ctypes.c_int
    if rename(source_dir_fd,os.fsencode(source),target_dir_fd,os.fsencode(target),4):
        number=ctypes.get_errno();raise OSError(number,os.strerror(number),str(target))


def _inode(value):return value.st_dev,value.st_ino


def _data_identity(value):return value.st_dev,value.st_ino,value.st_size,value.st_mtime_ns

def _reference(path):
    path=card._safe_path(path)
    return dict(path=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest())


def _withdraw_card(stage_reference,activation_reference,evidence,*,body_sha256,plan_sha256,
        context_kind,lease,journal,withdrawal_authorized=False,operator_never_started_confirmed=False,
        operator_health_confirmed=False,discover=None,rename_fn=None, replacement_fn=None,
        single_writer_acknowledged=False, compatibility_probe_reference=None, flow_directory=None):
    """Retain the exact candidate inactive and observe the original root file.

    Explicit authorization covers card files only. Backup replacement copies the
    candidate before restoring the original. Healthy/never-started
    confirmations are operator declarations, not hardware or flash proofs.
    Injected discovery and rename must be paired and always label evidence false.
    """
    folder=card._safe_path(evidence);phase='LOCAL_PREFLIGHT';rename_attempted=False
    try:
        require(withdrawal_authorized is True and operator_never_started_confirmed is True
                and operator_health_confirmed is True,'Explicit withdrawal, healthy and never-started confirmations required')
        identity=_held_lease(lease)
        require(isinstance(journal,InstallJournal),'Original pending preparation journal required')
        history,binding=journal.events,journal.binding
        require(binding==dict(body_sha256=body_sha256,plan_sha256=plan_sha256,model='ILCE-7M4'),'Withdrawal body/plan differs')
        pending_reference=context_kind.reference if isinstance(context_kind,_PendingContext) else None
        pending=_check_context_kind(context_kind,binding,history,journal.session_dir,stage_reference)
        allowed_state=PENDING if isinstance(context_kind,_PendingContext) else 'SD_STAGED'
        _,stage_raw,stage=card._json_reference(stage_reference)
        _,activation_raw,activation=card._json_reference(activation_reference)
        protocol=validate_activation_receipt_protocol(activation,activation_reference)
        replacing=protocol==BACKUP_COPY_ATOMIC_REPLACE
        if replacing:
            require(single_writer_acknowledged is True,'Explicit same-card single-writer withdrawal acknowledgement required')
            require(rename_fn is None and (discover is None)==(replacement_fn is None)
                    and (discover is None or (callable(discover) and callable(replacement_fn))),
                    'Replacement discovery and inverse actor must be paired')
        else:
            require(replacement_fn is None and (discover is None)==(rename_fn is None),
                    'Discovery and rename must both be injected or both default')
            require(discover is None or (callable(discover) and callable(rename_fn)),'Callable paired card operations required')
        injected=discover is not None

        require(stage.get('state')=='STAGED_UNRECOGNIZED_FILE_VERIFIED_NOT_ACTIVATED'
                and stage.get('source_sha256')==card.CANDIDATE_SHA256 and stage.get('bytes')==card.CANDIDATE_BYTES
                and stage.get('existing_root_update_unchanged') is True
                and all(stage.get(k) is False for k in ('BODYDATA_DAT_created_or_replaced','camera_internal_firmware_modified','updater_invoked')),
                'Complete original stage receipt required')
        old=card._identity(stage.get('volume_identity'),body_sha256)
        relative=card.staged_relative_path(stage.get('target'),old['mount'],card.CANDIDATE_SHA256)
        activated=card._identity(activation.get('volume_identity'),body_sha256)
        original=stage.get('existing_root_update')
        require(isinstance(original,dict) and type(original.get('exists')) is bool,'Complete original root baseline required')
        require(all(old[k]==activated[k] for k in card.STABLE_KEYS)
                and activation.get('state')=='ACTIVATED_PREVIEW_ONLY'
                and activation.get('source_sha256')==card.CANDIDATE_SHA256 and activation.get('bytes')==card.CANDIDATE_BYTES
                and activation.get('slot1_manually_confirmed') is True
                and activation.get('original_root_update')==original
                and activation.get('target')==str(Path(activated['mount'])/'BODYDATA.DAT')
                and activation.get('backup')==str(Path(activated['mount'])/relative.parent/'original-BODYDATA.DAT')
                and all(activation.get(k) is False for k in ('updater_invoked','installation_authorized','camera_internal_firmware_modified')),
                'Bound filename-only activation receipt required')
        if original['exists']:
            require(set(original)=={'exists','bytes','sha256'} and type(original['bytes']) is int and original['bytes']>=0
                    and isinstance(original['sha256'],str) and len(original['sha256'])==64
                    and original['sha256']!=card.CANDIDATE_SHA256,'Distinct complete original root snapshot required')
        else:require(original=={'exists':False},'Exact absent original baseline required')
        if not injected:
            require(Path(lease.path).absolute()==DEFAULT_LOCK.absolute()
                    and journal.session_dir.parent.absolute()==DEFAULT_SESSIONS.absolute()
                    and (isinstance(context_kind,_StagedContext) or pending['source_is_hardware'] is True),
                    'Default withdrawal requires canonical trusted context')
            _source_only_runtime()
            from camera_sd_stage import discover as actual_discover
            discover=actual_discover
            if replacing:
                from tools.card_backup_replace import withdraw_with_backup
                replacement_fn=withdraw_with_backup
            else:rename_fn=_rename_exclusive_at
        require(folder.is_dir() and not any(folder.iterdir()),'Fresh empty withdrawal evidence directory required')
        def context():
            require(_held_lease(lease)==identity,'Withdrawal lease identity changed')
            require(InstallJournal.open(journal.session_dir).events==history and journal.events==history,'Withdrawal history changed')
            assert_operation_allowed(journal,allowed_states=(allowed_state,))
            if journal.session_dir.parent.resolve()!=DEFAULT_SESSIONS.resolve():assert_operation_allowed(sessions_root=DEFAULT_SESSIONS)
            require(card._json_reference(stage_reference)[1]==stage_raw
                    and card._json_reference(activation_reference)[1]==activation_raw,'Stage or activation receipt changed')
            _check_context_kind(context_kind,binding,history,journal.session_dir,stage_reference)
            if not injected:_source_only_runtime()
        context();pinned=card._identity(dict(discover()),body_sha256)
        require(all(old[k]==pinned[k] for k in card.STABLE_KEYS),'Withdrawal card differs from staged card')
        if replacing:
            from tools.card_protocol_probe import validate_probe
            validate_probe(compatibility_probe_reference,pinned,flow_directory=flow_directory)
            require(original['exists'] is True,'Replacement withdrawal requires an original backup')
        mount=card._safe_path(pinned['mount']);candidate=card._safe_path(mount/relative)
        root=card._safe_path(mount/'BODYDATA.DAT');backup=card._safe_path(candidate.parent/'original-BODYDATA.DAT')
        require(mount.is_dir() and candidate.parent.is_dir() and not candidate.exists() and not candidate.is_symlink(),
                'Inactive candidate destination must remain absent')
        observations=[pinned];renames=[]
        with ExitStack() as stack:
            flags=os.O_RDONLY|getattr(os,'O_DIRECTORY',0)|getattr(os,'O_NOFOLLOW',0)
            mount_fd=os.open(mount,flags);stack.callback(os.close,mount_fd)
            staging_fd=os.open(relative.parts[0],flags,dir_fd=mount_fd);stack.callback(os.close,staging_fd)
            leaf_fd=os.open(relative.parts[1],flags,dir_fd=staging_fd);stack.callback(os.close,leaf_fd)
            dirs=((mount,mount_fd),(mount/relative.parts[0],staging_fd),(candidate.parent,leaf_fd))
            directory_ids=[_inode(os.fstat(fd)) for _,fd in dirs]
            require(all(dev==directory_ids[0][0] for dev,_ in directory_ids),'Same-volume pinned directories required')
            def unchanged():
                context();current=card._identity(dict(discover()),body_sha256);observations.append(current)
                require(current==pinned,'Withdrawal card handles changed')
                for (path,fd),identity_at_open in zip(dirs,directory_ids):
                    require(not path.is_symlink() and _inode(path.stat())==_inode(os.fstat(fd))==identity_at_open,
                            'Withdrawal directory identity changed')
            def entry(name,fd):
                value=os.stat(name,dir_fd=fd,follow_symlinks=False)
                require(stat.S_ISREG(value.st_mode),'Regular pinned card entry required')
                return value
            def absent(name,fd):
                try:os.stat(name,dir_fd=fd,follow_symlinks=False)
                except FileNotFoundError:return
                raise ValueError('Exclusive rename destination appeared')
            def readback(path,size,digest):
                value=card._hash_open_file(path,stack,size,mount,mount_fd)
                require(value['bytes']==size and value['sha256']==digest,'Withdrawal full readback differs')
                fd=value.pop('_descriptor');require(os.fstat(fd).st_dev==directory_ids[0][0],'Same-volume card file required')
                return value,fd
            unchanged();before_candidate,candidate_fd=readback(root,card.CANDIDATE_BYTES,card.CANDIDATE_SHA256)
            candidate_identity=_data_identity(os.fstat(candidate_fd))
            original_fd=None
            if original['exists']:
                before_original,original_fd=readback(backup,original['bytes'],original['sha256'])
                original_identity=_data_identity(os.fstat(original_fd))
            else:absent(backup.name,leaf_fd);before_original=dict(path=str(backup),exists=False)
            unchanged();absent(candidate.name,leaf_fd)
            intent=dict(schema='camera-install-card-withdrawal/1',state='CARD_WITHDRAWAL_INTENT',**binding,
                session_id=journal.session_dir.name,pending_reference=deepcopy(pending_reference),stage_reference=deepcopy(stage_reference),
                withdrawal_scope='PENDING_INSTALL_PREPARATION' if isinstance(context_kind,_PendingContext) else 'STAGED_BEFORE_RAM',
                activation_reference=deepcopy(activation_reference),activation_protocol=protocol,
                single_writer_acknowledged=replacing,compatibility_probe_reference=compatibility_probe_reference,history_sha256=canonical_sha256(history),lease_identity=identity,
                volume_identity=pinned,candidate_before=before_candidate,original_before=before_original,
                withdrawal_authorized=True,operator_never_started_confirmed=True,operator_health_confirmed=True,
                source_is_hardware=not injected,injected_execution=injected,
                producer_kind='INJECTED_CARD_WITHDRAWAL' if injected else 'DEFAULT_PINNED_CARD_WITHDRAWAL',
                provenance='DECLARED_COLLECTOR_NOT_CRYPTO_ATTESTED',automatic_retry=False,automatic_rollback=False,updater_invoked=False)
            durable_new(folder/'before-first-rename.json',intent)
            intent_reference=_reference(folder/'before-first-rename.json');original_intent_reference=None
            unchanged();absent(candidate.name,leaf_fd)
            require(_data_identity(entry(root.name,mount_fd))==_data_identity(os.fstat(candidate_fd))==candidate_identity, 'Active candidate inode changed')
            replacement_reference=None
            if replacing:
                from tools.card_backup_replace import Assurance, FileExpectation, WithdrawalPlan
                from tools.card_protocol_probe import identity as protocol_identity, validate_transaction
                phase='BACKUP_COPY_RESTORE_MAY_HAVE_OCCURRED';rename_attempted=True
                def inverse_identity():
                    unchanged()
                    return protocol_identity(pinned)
                restored=replacement_fn(WithdrawalPlan(
                    FileExpectation(root,card.CANDIDATE_BYTES,card.CANDIDATE_SHA256),
                    FileExpectation(backup,original['bytes'],original['sha256']),candidate),
                    folder/'replacement-evidence',expected_card_identity=protocol_identity(pinned),identity_reader=inverse_identity,
                    assurance=Assurance.SINGLE_WRITER_BACKUP_RESTORE,single_writer_acknowledged=True)
                require(restored.get('state')=='COMPLETED','Completed inverse replacement required')
                replacement_reference=_reference(folder/'replacement-evidence/completed.json')
                validate_transaction(replacement_reference,operation='WITHDRAW',card_identity=pinned,
                    source=backup,target=root,preserved=candidate,source_sha256=original['sha256'],
                    previous_target_sha256=card.CANDIDATE_SHA256,
                    intent_reference=_reference(folder/'replacement-evidence/replace-intent.json'))
                original_intent_reference=_reference(folder/'replacement-evidence/replace-intent.json')
                renames.append(dict(source=str(backup),target=str(root)))
                unchanged();absent(backup.name,leaf_fd)
                candidate_after,_=readback(candidate,card.CANDIDATE_BYTES,card.CANDIDATE_SHA256)
                original_after,_=readback(root,original['bytes'],original['sha256'])
            else:
                phase='CANDIDATE_WITHDRAW_RENAME_MAY_HAVE_OCCURRED';rename_attempted=True
                rename_fn(root.name,candidate.name,source_dir_fd=mount_fd,target_dir_fd=leaf_fd)
                renames.append(dict(source=str(root),target=str(candidate)));os.fsync(mount_fd);os.fsync(leaf_fd)
                unchanged();absent(root.name,mount_fd)
                require(_data_identity(entry(candidate.name,leaf_fd))==_data_identity(os.fstat(candidate_fd))==candidate_identity, 'Withdrawn candidate inode differs')
                candidate_after,_=readback(candidate,card.CANDIDATE_BYTES,card.CANDIDATE_SHA256)
                if original['exists']:
                    unchanged();require(_data_identity(entry(backup.name,leaf_fd))==_data_identity(os.fstat(original_fd))==original_identity,'Original backup inode changed')
                    readback(backup,original['bytes'],original['sha256'])
                    durable_new(folder/'before-original-root-rename.json',dict(intent,candidate_after=candidate_after,renames=deepcopy(renames)))
                    original_intent_reference=_reference(folder/'before-original-root-rename.json')
                    unchanged();absent(root.name,mount_fd)
                    require(_data_identity(entry(backup.name,leaf_fd))==_data_identity(os.fstat(original_fd))==original_identity,'Original backup changed before rename')
                    phase='ORIGINAL_ROOT_RENAME_MAY_HAVE_OCCURRED'
                    rename_fn(backup.name,root.name,source_dir_fd=leaf_fd,target_dir_fd=mount_fd)
                    renames.append(dict(source=str(backup),target=str(root)));os.fsync(leaf_fd);os.fsync(mount_fd)
                    unchanged();absent(backup.name,leaf_fd)
                    require(_data_identity(entry(root.name,mount_fd))==_data_identity(os.fstat(original_fd))==original_identity,'Original root inode differs')
                    original_after,_=readback(root,original['bytes'],original['sha256'])
                else:original_after=dict(path=str(root),exists=False)
            unchanged()
            if not replacing:require(_data_identity(entry(candidate.name,leaf_fd))==_data_identity(os.fstat(candidate_fd))==candidate_identity,'Retained candidate changed')
            candidate_after,_=readback(candidate,card.CANDIDATE_BYTES,card.CANDIDATE_SHA256)
            unchanged()
            if not original['exists']:absent(root.name,mount_fd);absent(backup.name,leaf_fd)
            result=intent|dict(state='CARD_CANDIDATE_WITHDRAWN_ORIGINAL_ROOT_OBSERVED',candidate_after=candidate_after,
                original_after=original_after,intent_reference=intent_reference,
                original_root_intent_reference=original_intent_reference,renames=deepcopy(renames),identity_observations=deepcopy(observations),
                replacement_reference=replacement_reference,candidate_copy_created=replacing,
                card_contents_modified=replacing,card_names_modified=True,installation_authorized=False,
                RAM_restoration_proven=False,original_mm_continuity_proven=False,cancellation_recorded=False,
                automatic_reboot=False,future_card_state_proven=False)
            path=folder/'withdrawal-completed.json'
            durable_new(path,result)
            _,_,saved=card._json_reference(dict(path=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
            require(saved==result,'Durable withdrawal receipt changed')
            unchanged()
            return result
    except BaseException as error:
        try:
            if folder.is_dir():durable_new(folder/'withdrawal-unknown.json',dict(state='CARD_WITHDRAWAL_UNKNOWN',phase=phase,
                error_type=type(error).__name__,rename_may_have_occurred=rename_attempted,
                automatic_retry=False,automatic_rollback=False,automatic_reboot=False,cancellation_recorded=False))
        except BaseException:pass
        raise


def _validate_withdrawal_receipt(reference,*,binding,history,session_dir,context_kind,stage_reference):
    """Validate historical withdrawal records without touching the card or camera."""
    from camera_install_receipts import source_declaration,validate_history
    validate_history(binding,history,session_dir)
    _,_,report=card._json_reference(reference)
    pending_reference=context_kind.reference if isinstance(context_kind,_PendingContext) else None
    _check_context_kind(context_kind,binding,history,session_dir,stage_reference)
    require(report.get('schema')=='camera-install-card-withdrawal/1'
            and report.get('state')=='CARD_CANDIDATE_WITHDRAWN_ORIGINAL_ROOT_OBSERVED'
            and all(report.get(k)==v for k,v in binding.items())
            and report.get('session_id')==Path(session_dir).name
            and report.get('pending_reference')==pending_reference and report.get('stage_reference')==stage_reference
            and report.get('history_sha256')==canonical_sha256(history)
            and report.get('withdrawal_scope')==('PENDING_INSTALL_PREPARATION' if isinstance(context_kind,_PendingContext) else 'STAGED_BEFORE_RAM'),
            'Withdrawal receipt/history binding differs')
    unknown=Path(reference['path']).parent/'withdrawal-unknown.json'
    require(not unknown.exists() and not unknown.is_symlink(),'Contradictory unknown withdrawal evidence')
    replacing=report.get('activation_protocol',EXCLUSIVE_RENAME)==BACKUP_COPY_ATOMIC_REPLACE
    source=source_declaration(report)
    require(type(report.get('injected_execution')) is bool
            and report.get('producer_kind')==('INJECTED_CARD_WITHDRAWAL' if report['injected_execution'] else 'DEFAULT_PINNED_CARD_WITHDRAWAL')
            and source is (not report['injected_execution'])
            and all(report.get(k) is True for k in ('withdrawal_authorized','operator_never_started_confirmed','operator_health_confirmed','card_names_modified'))
            and all(report.get(k) is False for k in ('automatic_retry','automatic_rollback','updater_invoked',
                'installation_authorized','RAM_restoration_proven','original_mm_continuity_proven',
                'cancellation_recorded','automatic_reboot','future_card_state_proven')),'Withdrawal-only producer declarations differ')
    require(report.get('card_contents_modified') is replacing
            and (report.get('candidate_copy_created',False) is replacing), 'Withdrawal copy contract differs')
    _,_,stage=card._json_reference(stage_reference)
    _,_,activation=card._json_reference(report.get('activation_reference'))
    protocol=validate_activation_receipt_protocol(activation,report['activation_reference'])
    require(report.get('activation_protocol',EXCLUSIVE_RENAME)==protocol, 'Withdrawal protocol differs from activation')
    if replacing:
        from tools.card_protocol_probe import validate_probe
        require(report.get('single_writer_acknowledged') is True, 'Single-writer withdrawal evidence required')
        validate_probe(report.get('compatibility_probe_reference'),report['volume_identity'],
            flow_directory=Path(reference['path']).parents[2])
        from tools.card_protocol_probe import _flow_producer
        _flow_producer(reference,'withdraw',Path(reference['path']).parents[2],report['volume_identity'])
    old=card._identity(stage.get('volume_identity'),binding['body_sha256'])
    activated=card._identity(activation.get('volume_identity'),binding['body_sha256'])
    require(all(old[k]==activated[k] for k in card.STABLE_KEYS)
        and activation.get('slot1_manually_confirmed') is True
        and all(activation.get(k) is False for k in ('updater_invoked','installation_authorized','camera_internal_firmware_modified')),
        'Historical filename-only activation identity differs')
    current=card._identity(dict(report.get('volume_identity',{}),body_matched=True),binding['body_sha256'])
    require(all(old[k]==current[k] for k in card.STABLE_KEYS),'Historical withdrawal card identity differs')
    require(isinstance(report.get('identity_observations'),list) and len(report['identity_observations'])>=4
            and all(value==current for value in report['identity_observations']),'Historical pinned card observations required')
    relative=card.staged_relative_path(stage.get('target'),old['mount'],card.CANDIDATE_SHA256)
    root=Path(current['mount'])/'BODYDATA.DAT';candidate=Path(current['mount'])/relative
    backup=candidate.parent/'original-BODYDATA.DAT'
    require(activation.get('target')==str(Path(activated['mount'])/'BODYDATA.DAT')
        and activation.get('backup')==str(Path(activated['mount'])/relative.parent/'original-BODYDATA.DAT'),
        'Historical activation paths differ from staged location')
    before=report.get('candidate_before',{});after=report.get('candidate_after',{})
    require(before.get('path')==str(root) and after.get('path')==str(candidate)
            and all(value.get('sha256')==card.CANDIDATE_SHA256 and value.get('bytes')==card.CANDIDATE_BYTES
                and isinstance(value.get('descriptor_identity'),list) and len(value['descriptor_identity'])==5
                for value in (before,after))
            and (replacing or before['descriptor_identity'][:4]==after['descriptor_identity'][:4]),
            'Historical candidate full readback differs')
    original=stage.get('existing_root_update');before_original=report.get('original_before',{});after_original=report.get('original_after',{})
    require(isinstance(original,dict) and activation.get('original_root_update')==original
            and activation.get('state')=='ACTIVATED_PREVIEW_ONLY'
            and activation.get('source_sha256')==card.CANDIDATE_SHA256 and activation.get('bytes')==card.CANDIDATE_BYTES
            and before_original.get('path')==str(backup) and after_original.get('path')==str(root),
            'Historical original/activation baseline differs')
    expected=[] if replacing else [dict(source=str(root),target=str(candidate))]
    if original.get('exists') is True:
        require(set(original)=={'exists','bytes','sha256'} and original['sha256']!=card.CANDIDATE_SHA256
                and all(value.get('bytes')==original['bytes'] and value.get('sha256')==original['sha256']
                    for value in (before_original,after_original))
                and before_original.get('descriptor_identity',[])[:4]==after_original.get('descriptor_identity',[])[:4],
                'Historical original full readback differs')
        expected.append(dict(source=str(backup),target=str(root)))
    else:require(original=={'exists':False} and before_original.get('exists') is after_original.get('exists') is False,
                 'Historical absent original baseline differs')
    require(report.get('renames')==expected,'Exactly bounded reverse renames required')
    if replacing:
        from tools.card_protocol_probe import validate_transaction
        require(original['exists'] is True, 'Inverse replacement original baseline required')
        validate_transaction(report.get('replacement_reference'),operation='WITHDRAW',card_identity=report['volume_identity'],
            source=backup,target=root,preserved=candidate,source_sha256=original['sha256'],
            previous_target_sha256=card.CANDIDATE_SHA256,intent_reference=report.get('original_root_intent_reference'))
    else:require(report.get('replacement_reference') is None,'Exclusive withdrawal cannot borrow replacement proof')
    _,_,intent=card._json_reference(report.get('intent_reference'))
    expected_intent=deepcopy(report)
    for name in ('candidate_after','original_after','intent_reference','original_root_intent_reference','renames',
        'identity_observations','replacement_reference','candidate_copy_created','card_contents_modified','card_names_modified','installation_authorized',
        'RAM_restoration_proven','original_mm_continuity_proven','cancellation_recorded','automatic_reboot','future_card_state_proven'):
        expected_intent.pop(name,None)
    expected_intent['state']='CARD_WITHDRAWAL_INTENT'
    require(intent==expected_intent,'Durable pre-rename intent differs from completed withdrawal')
    if original['exists'] and not replacing:
        _,_,second=card._json_reference(report.get('original_root_intent_reference'))
        require(second==dict(intent,candidate_after=after,renames=expected[:1]),'Durable second-rename intent differs')
    elif not replacing:require(report.get('original_root_intent_reference') is None,'Unexpected second rename intent')
    return dict(receipt=report,reference=deepcopy(reference),source_is_hardware=source,
                provenance='DECLARED_COLLECTOR_NOT_CRYPTO_ATTESTED')


def _check_context_kind(context_kind,binding,history,session_dir,stage_reference):
    if isinstance(context_kind,_PendingContext):
        _history(binding,history,session_dir,context_kind.reference,stage_reference)
        return validate_completed_pending(context_kind.reference,binding=binding,history=history,session_dir=session_dir)
    require(isinstance(context_kind,_StagedContext),'Explicit withdrawal context type required')
    require(history and history[-1]['state']=='SD_STAGED' and history[-1]['session_id']==Path(session_dir).name
        and all(e['binding']==binding for e in history) and binding['model']=='ILCE-7M4'
        and not any(e['state'] in ('RAM_MAY_BE_ACTIVE','INSTALL_PATCH_MAY_BE_ACTIVE','FLASH_MAY_HAVE_STARTED',
            'RAM_AWAITING_OPERATOR_RECONNECT','INSTALL_PATCH_AWAITING_OPERATOR_RECONNECT') for e in history),
        'Exact SD_STAGED before-RAM history required')
    stages=[e for e in history if e['state']=='SD_STAGED']
    require(len(stages)==1 and stages[0]['details'].get('stage_report')==stage_reference['path']
        and stages[0]['details'].get('stage_report_sha256')==stage_reference['sha256'],'Original staged artifact binding differs')
    return None


def withdraw_active_card(stage_reference,activation_reference,evidence,*,body_sha256,plan_sha256,pending_reference,
        lease,journal,withdrawal_authorized=False,operator_never_started_confirmed=False,
        operator_health_confirmed=False,discover=None,rename_fn=None, replacement_fn=None,
        single_writer_acknowledged=False, compatibility_probe_reference=None, flow_directory=None):
    return _withdraw_card(stage_reference,activation_reference,evidence,body_sha256=body_sha256,plan_sha256=plan_sha256,
        context_kind=_PendingContext(pending_reference),lease=lease,journal=journal,
        withdrawal_authorized=withdrawal_authorized,operator_never_started_confirmed=operator_never_started_confirmed,
        operator_health_confirmed=operator_health_confirmed,discover=discover,rename_fn=rename_fn,replacement_fn=replacement_fn,
        single_writer_acknowledged=single_writer_acknowledged,compatibility_probe_reference=compatibility_probe_reference,flow_directory=flow_directory)


def withdraw_staged_card(stage_reference,activation_reference,evidence,*,body_sha256,plan_sha256,lease,journal,
        withdrawal_authorized=False,operator_never_started_confirmed=False,operator_health_confirmed=False,
        discover=None,rename_fn=None,replacement_fn=None, single_writer_acknowledged=False,
        compatibility_probe_reference=None,flow_directory=None):
    """Withdraw only a known SD_STAGED activation before any possible RAM/FLASH write."""
    return _withdraw_card(stage_reference,activation_reference,evidence,body_sha256=body_sha256,plan_sha256=plan_sha256,
        context_kind=_StagedContext(),lease=lease,journal=journal,withdrawal_authorized=withdrawal_authorized,
        operator_never_started_confirmed=operator_never_started_confirmed,operator_health_confirmed=operator_health_confirmed,
        discover=discover,rename_fn=rename_fn,replacement_fn=replacement_fn,
        single_writer_acknowledged=single_writer_acknowledged,compatibility_probe_reference=compatibility_probe_reference,flow_directory=flow_directory)


def validate_withdrawal_receipt(reference,*,binding,history,session_dir,pending_reference,stage_reference):
    return _validate_withdrawal_receipt(reference,binding=binding,history=history,session_dir=session_dir,
        context_kind=_PendingContext(pending_reference),stage_reference=stage_reference)


def validate_staged_withdrawal_receipt(reference,*,binding,history,session_dir,stage_reference):
    return _validate_withdrawal_receipt(reference,binding=binding,history=history,session_dir=session_dir,
        context_kind=_StagedContext(),stage_reference=stage_reference)
