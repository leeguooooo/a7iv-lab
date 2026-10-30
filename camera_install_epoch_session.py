"""Observe a pending preparation's AP boot epoch; never reboot or restore it."""
from copy import deepcopy
import hashlib
from pathlib import Path
import time

import camera_install_runtime_metadata as metadata
from camera_device_lease import DEFAULT_LOCK
from camera_install_journal import InstallJournal
from camera_install_io import JournalSnapshotPin
from camera_install_patch_session import (_held_lease,_source_only_runtime,_safe_path,_json,_known_stop,
    canonical_sha256,SOURCE_ONLY_RUNTIME,review_source_paths as preparation_sources)
from camera_install_runtime_session import _PinnedDriver
from camera_operation_guard import DEFAULT_SESSIONS
from camera_stream_execution import durable_new

ROOT=Path(__file__).resolve().parent
SCOPE=metadata.EPOCH_SCOPE
REVIEW_SCHEMA='camera-install-pending-epoch-session-plan/1'
RECEIPT_SCHEMA='camera-install-pending-epoch-session-receipt/1'
FALSE_CLAIMS=('installation_authorized','hardware_admission_proven','RAM_restoration_proven',
    'original_mm_continuity_proven','cancellation_recorded','CP_coldboot_proven','NOR_state_proven',
    'full_camera_coldboot_proven','automatic_reboot','automatic_restore','ready_for_confirmation')


def require(ok,message):
    if not ok:raise ValueError(message)


def review_source_paths(prepared):
    return tuple(sorted(set(preparation_sources(prepared))|{'camera_install_epoch_session.py',
        'camera_install_epoch_plan.py','camera_install_card_withdraw.py','camera_install_io.py',
        'camera_install_runtime_metadata.py'}))


def source_summary(pending_reference,initial_runtime_reference,withdrawal_reference,binding,history,session_dir):
    return metadata._pending_epoch_sources(pending_reference,initial_runtime_reference,withdrawal_reference,
        binding=binding,history=history,session_dir=session_dir)


def validate_review(path,digest,prepared,*,binding,pending_reference,initial_runtime_reference,
        withdrawal_reference,summary,history,session_dir):
    raw,review=_json(path)
    require(hashlib.sha256(raw).hexdigest()==digest,'Pending epoch review changed')
    require(review.get('schema')==REVIEW_SCHEMA and review.get('scope')==SCOPE
        and all(review.get(k)==v for k,v in binding.items()) and review.get('session_id')==Path(session_dir).name
        and review.get('pending_reference')==pending_reference and review.get('initial_runtime_reference')==initial_runtime_reference
        and review.get('withdrawal_reference')==withdrawal_reference and review.get('asset_reference')==prepared.reference
        and review.get('source_summary')==summary and review.get('history_sha256')==canonical_sha256(history)
        and review.get('source_only_runtime')==SOURCE_ONLY_RUNTIME
        and all(type(review['source_only_runtime'].get(k)) is bool for k in
            ('dont_write_bytecode','ignore_environment','no_user_site','prefix_must_not_exist'))
        and review.get('execution_approval_received') is False and type(review.get('hardware_operations')) is int
        and review['hardware_operations']==0 and all(review.get(k) is False for k in FALSE_CLAIMS),
        'Exact pending AP-epoch review binding required')
    sources=review.get('sources')
    require(isinstance(sources,dict) and set(review_source_paths(prepared)).issubset(sources)
        and all(sources.get(k)==v for k,v in prepared.manifest['sources'].items()),'Full epoch source closure required')
    snapshots=Path(path).absolute().parent/'sources'
    require(review.get('source_snapshot_directory')==str(snapshots),'Bound epoch source snapshots required')
    _safe_path(snapshots,directory=True)
    for name,expected in sources.items():
        relative=Path(name)
        require(not relative.is_absolute() and '..' not in relative.parts,'Relative epoch source path required')
        require(hashlib.sha256(_safe_path(ROOT/name).read_bytes()).hexdigest()==expected
            and hashlib.sha256(_safe_path(snapshots/name).read_bytes()).hexdigest()==expected,'Epoch source/snapshot changed: '+name)
    return dict(path=str(Path(path).absolute()),sha256=digest,payload_sha256=canonical_sha256(review))


def run_pending_epoch_session(body_sha256,evidence,*,plan_sha256,pending_reference,initial_runtime_reference,
        withdrawal_reference,review_path,review_sha256,assets,journal,lease,epoch_read_authorized=False,
        operator_never_started_confirmed=False,manual_AP_reboot_confirmed=False,
        withdrawal_preceded_manual_AP_reboot_confirmed=False,
        run_session=None,capture_fn=None,preflight_fn=None,reserve_fn=None,clock=time.monotonic,sleep=time.sleep):
    folder=Path(evidence).absolute();attempted=False;reservation_attempted=False;pin=None;original_driver=None;device_owned=None;proxy=None
    try:
        require(epoch_read_authorized is True and operator_never_started_confirmed is True
            and manual_AP_reboot_confirmed is True and withdrawal_preceded_manual_AP_reboot_confirmed is True,'Explicit epoch read, never-FLASH and manual AP reboot confirmations required')
        require((run_session is None)==(capture_fn is None),'Session and epoch collector must both be injected or default')
        require(run_session is None or (callable(run_session) and callable(capture_fn)),'Callable paired epoch transports required')
        injected=run_session is not None
        require((preflight_fn is None and reserve_fn is None) or injected,'Local hook injection requires injected transports')
        require(all(fn is None or callable(fn) for fn in (preflight_fn,reserve_fn)),'Callable epoch local hooks required')
        require(isinstance(journal,InstallJournal),'Original pending journal required')
        binding=dict(body_sha256=body_sha256,plan_sha256=plan_sha256,model='ILCE-7M4')
        require(journal.binding==binding,'Epoch body/original plan binding differs')
        identity,history=_held_lease(lease),journal.events
        if not injected:
            require(Path(lease.path).absolute()==DEFAULT_LOCK.absolute()
                and journal.session_dir.parent.absolute()==DEFAULT_SESSIONS.absolute(),'Default epoch needs canonical held lease/journal')
            _source_only_runtime()
        folder=_safe_path(folder,directory=True);require(not any(folder.iterdir()),'Fresh empty epoch evidence directory required')
        summary=source_summary(pending_reference,initial_runtime_reference,withdrawal_reference,binding,history,journal.session_dir)
        require(injected or summary['sources_declared_hardware'] is True,'Default epoch requires trusted immutable original evidence')
        preflight=metadata.preflight_assets if preflight_fn is None else preflight_fn
        prepared=preflight(assets)
        reviewed=validate_review(review_path,review_sha256,prepared,binding=binding,pending_reference=pending_reference,
            initial_runtime_reference=initial_runtime_reference,withdrawal_reference=withdrawal_reference,
            summary=summary,history=history,session_dir=journal.session_dir)
        pin=JournalSnapshotPin(journal,lease)
        def context():
            pin.check()
            require(metadata._pending_epoch_context(lease,journal,body_sha256,plan_sha256,
                pending_reference=pending_reference,initial_runtime_reference=initial_runtime_reference,
                withdrawal_reference=withdrawal_reference,operator_never_started_confirmed=True,summary=summary)['lease_identity']==identity,
                'Original epoch context changed')
        def guard():
            context()
            require(validate_review(review_path,review_sha256,prepared,binding=binding,pending_reference=pending_reference,
                initial_runtime_reference=initial_runtime_reference,withdrawal_reference=withdrawal_reference,
                summary=summary,history=history,session_dir=journal.session_dir)==reviewed,'Epoch review changed')
            if not injected:_source_only_runtime()
        guard()
        reserve=metadata.reserve_pending_epoch_assets if reserve_fn is None else reserve_fn
        reservation_attempted=True
        reservation=reserve(prepared,folder,lease=lease,journal=journal,body_sha256=body_sha256,plan_sha256=plan_sha256,
            pending_reference=pending_reference,initial_runtime_reference=initial_runtime_reference,
            withdrawal_reference=withdrawal_reference,operator_never_started_confirmed=True)
        guard()
        rechecked=preflight(assets) if injected else metadata.preflight_assets(assets,owned_reservation=reservation)
        require(rechecked==prepared,'Epoch assets changed after reservation')
        if not injected:
            from camera_stream_usb_session import run_normal_session
            run_session,capture_fn=run_normal_session,metadata.capture_pending_epoch_authenticated
        events=[];calls=0;accepted=None;terminal_ref=None;stage='PENDING_EPOCH_SERVICE_ENTRY_MAY_HAVE_STARTED'
        def work(device):
            nonlocal calls,accepted,terminal_ref,original_driver,device_owned,proxy
            calls+=1;require(calls==1,'Epoch callback cannot be replayed');guard()
            require(any(e.get('model')=='ILCE-7M4' and e.get('body_matched') is True for e in events),
                    'Fresh normal-body match before epoch collection required')
            if hasattr(device,'driver'):
                device_owned=device;original_driver=device.driver;proxy=_PinnedDriver(original_driver,pin.check);device.driver=proxy
            else:require(injected,'Default epoch device driver required')
            observed=capture_fn(device,folder,assets=assets,reservation=reservation,lease=lease,journal=journal,
                body_sha256=body_sha256,plan_sha256=plan_sha256,pending_reference=pending_reference,
                initial_runtime_reference=initial_runtime_reference,withdrawal_reference=withdrawal_reference,
                operator_never_started_confirmed=True,metadata_read_authorized=True,source_is_hardware=not injected,clock=clock,sleep=sleep)
            guard()
            raw,saved=_json(folder/'metadata-receipt.json')
            require(saved==observed and type(observed.get('source_is_hardware')) is bool
                and observed['source_is_hardware'] is (not injected),'Owned metadata source or durable receipt differs')
            proof=metadata.validate_receipt(observed,reference=prepared.reference,reservation=reservation)
            require(proof['metadata_version']==metadata.VERSION,'Epoch metadata V2 required')
            accepted=deepcopy(observed)
            terminal=dict(schema=RECEIPT_SCHEMA,state='PENDING_EPOCH_TERMINAL_DURABLE_BEFORE_STOP',scope=SCOPE,
                **binding,session_id=journal.session_dir.name,pending_reference=deepcopy(pending_reference),
                initial_runtime_reference=deepcopy(initial_runtime_reference),withdrawal_reference=deepcopy(withdrawal_reference),
                pending_event_sha256=history[-1]['event_sha256'],history_sha256=canonical_sha256(history),lease_identity=identity,
                source_summary=deepcopy(summary),current_review=reviewed,asset_reference=prepared.reference,reservation=reservation,
                metadata_receipt=accepted,metadata_proof=proof,metadata_artifact=dict(path=str(folder/'metadata-receipt.json'),sha256=hashlib.sha256(raw).hexdigest()),
                initial_boot_id=summary['initial_boot_id'],current_boot_id=proof['boot_id'],boot_id_differs=summary['initial_boot_id']!=proof['boot_id'],
                source_is_hardware=not injected,injected_execution=injected,normal_body_matched=True,
                operator_never_started_confirmed=True,manual_AP_reboot_confirmed=True,
                withdrawal_preceded_manual_AP_reboot_confirmed=True,reboot_order_is_operator_statement=True,service_exit_completed=False,
                **dict.fromkeys(FALSE_CLAIMS,False))
            path=folder/'pending-epoch-terminal.json';durable_new(path,terminal)
            terminal_raw,persisted=_json(path);require(persisted==terminal,'Durable epoch terminal changed')
            terminal_ref=dict(path=str(path),sha256=hashlib.sha256(terminal_raw).hexdigest(),payload_sha256=canonical_sha256(terminal))
            guard();return deepcopy(accepted)
        def stage_changed(value):
            nonlocal stage
            stage=value
        attempted=True
        returned=run_session(body_sha256,work,record_event=events.append,set_stage=stage_changed)
        guard();require(calls==1 and returned==accepted and terminal_ref is not None,'Original one-shot epoch result required')
        _known_stop(events)
        raw,terminal=_json(terminal_ref['path'])
        require(hashlib.sha256(raw).hexdigest()==terminal_ref['sha256'] and canonical_sha256(terminal)==terminal_ref['payload_sha256'],
                'Pre-STOP epoch terminal changed')
        metadata_raw,saved=_json(terminal['metadata_artifact']['path'])
        require(hashlib.sha256(metadata_raw).hexdigest()==terminal['metadata_artifact']['sha256'] and saved==accepted,
                'Full raw epoch metadata changed before completed exit')
        result=terminal|dict(state='PENDING_EPOCH_KNOWN_SERVICE_EXIT',terminal_artifact=terminal_ref,
            service_events=deepcopy(events),service_exit_completed=True,original_journal_unchanged=True)
        path=folder/'pending-epoch-session-exit.json';durable_new(path,result)
        require(_json(path)[1]==result,'Epoch exit receipt changed');guard();return result
    except BaseException as error:
        try:
            if folder.is_dir():durable_new(folder/'pending-epoch-unknown.json',dict(schema=RECEIPT_SCHEMA,
                state='PENDING_EPOCH_UNKNOWN' if attempted else 'LOCAL_EPOCH_REJECTED',error_type=type(error).__name__,
                authentication_may_have_started=attempted,claims_may_be_reserved=reservation_attempted,automatic_STOP=False,automatic_retry=False,
                **dict.fromkeys(FALSE_CLAIMS,False)))
        except BaseException:pass
        raise
    finally:
        if device_owned is not None and device_owned.driver is proxy:device_owned.driver=original_driver
        if pin is not None:pin.close()


def validate_completed_pending_epoch(reference,*,pending_reference,initial_runtime_reference,
        withdrawal_reference,binding,history,session_dir):
    """Replay a completed AP-epoch collection without current-source/job checks."""
    from camera_install_receipts import (validate_history,load_reference,source_declaration,historical_native,
        historical_review,historical_reservation,_completed_terminal,_hardware_session)
    validate_history(binding,history,session_dir)
    summary=source_summary(pending_reference,initial_runtime_reference,withdrawal_reference,binding,history,session_dir)
    _,receipt=load_reference(reference)
    require(history[-1]['state']=='INSTALL_PATCH_AWAITING_OPERATOR_RECONNECT'
        and receipt.get('schema')==RECEIPT_SCHEMA and receipt.get('scope')==SCOPE
        and all(receipt.get(k)==v for k,v in binding.items()) and receipt.get('session_id')==Path(session_dir).name
        and receipt.get('pending_reference')==pending_reference
        and receipt.get('initial_runtime_reference')==initial_runtime_reference
        and receipt.get('withdrawal_reference')==withdrawal_reference
        and receipt.get('pending_event_sha256')==history[-1]['event_sha256']
        and receipt.get('history_sha256')==canonical_sha256(history) and receipt.get('source_summary')==summary,
        'Completed epoch original context differs')
    _completed_terminal(receipt,terminal_state='PENDING_EPOCH_TERMINAL_DURABLE_BEFORE_STOP',exit_state='PENDING_EPOCH_KNOWN_SERVICE_EXIT')
    source=source_declaration(receipt)
    require(type(receipt.get('injected_execution')) is bool and source is (not receipt['injected_execution'])
        and receipt.get('operator_never_started_confirmed') is True and receipt.get('manual_AP_reboot_confirmed') is True
        and receipt.get('withdrawal_preceded_manual_AP_reboot_confirmed') is True
        and receipt.get('reboot_order_is_operator_statement') is True
        and receipt.get('normal_body_matched') is True and all(receipt.get(k) is False for k in FALSE_CLAIMS)
        and (source is False or summary['sources_declared_hardware'] is True),'Epoch source/scope declarations differ')
    native=receipt['metadata_receipt'];ref=receipt['asset_reference'];reservation=receipt['reservation']
    require(source_declaration(native) is source,'Epoch native source differs')
    proof=metadata.validate_receipt(native,reference=ref,reservation=reservation)
    require(proof['metadata_version']==metadata.VERSION and receipt.get('metadata_proof')==proof
        and receipt.get('initial_boot_id')==summary['initial_boot_id'] and receipt.get('current_boot_id')==proof['boot_id']
        and receipt.get('boot_id_differs') is (summary['initial_boot_id']!=proof['boot_id']),
        'Boot UUID comparison differs from hash-bound native payload')
    path=Path(reference['path']).absolute().parent/'metadata-receipt.json'
    require(receipt['metadata_artifact'].get('path')==str(path),'Fixed durable epoch native receipt required')
    require(load_reference(receipt['metadata_artifact'])[1]==native,'Persisted epoch raw metadata differs')
    require(ref.get('nonce') not in summary['prior_nonces'],'Epoch job nonce reuses a prior publication')
    manifest=historical_native(ref)
    require(manifest.get('schema')=='camera-install-runtime-metadata-offline/2'
        and manifest.get('profile')=='fixed_partition_alias_metadata_v2_boot_epoch',
        'Recorded epoch assets must be the metadata V2 profile')
    review=historical_review(receipt['current_review'],expected_sources=manifest['sources']|manifest.get('historical_model_sources',{}),
        required_sources=('camera_install_epoch_session.py','camera_install_runtime_metadata.py','camera_install_card_withdraw.py'))
    require(review.get('schema')==REVIEW_SCHEMA and review.get('scope')==SCOPE
        and all(review.get(k)==v for k,v in binding.items()) and review.get('asset_reference')==ref
        and review.get('pending_reference')==pending_reference
        and review.get('initial_runtime_reference')==initial_runtime_reference
        and review.get('withdrawal_reference')==withdrawal_reference and review.get('source_summary')==summary
        and review.get('history_sha256')==canonical_sha256(history),'Historical epoch review differs')
    if source:
        _hardware_session(receipt)
        record=historical_reservation(reservation,('global_claim','job_claim'))
        expected=metadata._json(dict(scope=SCOPE,lease_identity=receipt['lease_identity'],
            journal_event_sha256=history[-1]['event_sha256'],body_sha256=binding['body_sha256'],plan_sha256=binding['plan_sha256'],
            session_dir=str(Path(session_dir).absolute()),pending_reference=pending_reference,
            initial_runtime_reference=initial_runtime_reference,withdrawal_reference=withdrawal_reference,
            operator_never_started_confirmed=True,**summary))
        require(record.get('asset_reference')==ref and record.get('evidence')==str(Path(reference['path']).absolute().parent)
            and metadata._json(record.get('context'))==expected,'Historical epoch reservation differs')
    return dict(reference=deepcopy(reference),receipt=receipt,metadata_proof=proof,
        initial_boot_id=summary['initial_boot_id'],current_boot_id=proof['boot_id'],boot_id_differs=receipt['boot_id_differs'],
        source_is_hardware=source,provenance='DECLARED_COLLECTOR_NOT_CRYPTO_ATTESTED',original_mm_continuity_proven=False)
