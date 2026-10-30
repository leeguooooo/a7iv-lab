"""Cancel pre-flash preparation by current observations, without restoring RAM.

Saved receipts describe trusted local collector declarations. They do not
cryptographically attest hardware origin or establish original-mm continuity.
"""
from copy import deepcopy
import hashlib
from pathlib import Path
import time

import camera_install_cancel as assessment
from camera_device_lease import DEFAULT_LOCK
from camera_install_journal import InstallJournal
from camera_install_patch_session import _held_lease, _source_only_runtime, canonical_sha256
from camera_operation_guard import DEFAULT_SESSIONS, assert_operation_allowed
from camera_stream_execution import durable_new

PENDING = 'INSTALL_PATCH_AWAITING_OPERATOR_RECONNECT'
TERMINAL = 'INSTALL_PREPARATION_CANCELLED'
SCHEMA = 'camera-install-preparation-cancellation/1'
SCOPE = 'PRE_FLASH_CANCELLED_BY_CURRENT_OBSERVATION'
EPOCH_CANCEL_SCOPE = 'PRE_FLASH_CANCELLED_BY_CHANGED_AP_BOOT_EPOCH'
DEFAULT_PRODUCER = 'DEFAULT_OWNED_FRESH_CURRENT_READ_AND_INACTIVE_CARD'
FALSE_CLAIMS = ('RAM_restoration_proven', 'RAM_original_state_verified', 'original_mm_continuity_proven',
    'firmware_installation_proven', 'hardware_admission_proven', 'installation_authorized', 'device_execution_proven',
    'ready_for_confirmation', 'restore_performed', 'automatic_restore', 'automatic_reboot',
    'card_contents_or_names_modified', 'explicit_card_writes', 'future_device_state_proven')


def require(ok, message):
    if not ok:
        raise ValueError(message)


def validate_completed_current_read(reference, **kwargs):
    from camera_install_receipts import validate_completed_current_read as validate
    return validate(reference, **kwargs)


def _reference(path):
    path = assessment._safe_path(path)
    require(path.is_file(), 'Regular cancellation evidence file required')
    return dict(path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest())


def _history(binding, history, session_dir, pending_reference, stage_reference):
    require(history and history[-1]['state'] == PENDING
            and history[-1]['session_id'] == Path(session_dir).name,
            'Original pending install-preparation journal required')
    require(all(event['binding'] == binding for event in history)
            and binding['model'] == 'ILCE-7M4', 'Cancellation binding differs')
    require(not any(event['state'] == 'FLASH_MAY_HAVE_STARTED' for event in history),
            'Possible FLASH history forbids preparation cancellation')
    require(history[-1]['details'].get('install_patch_artifact') == pending_reference,
            'Original pending receipt binding differs')
    require(isinstance(stage_reference, dict) and set(stage_reference) == {'path', 'sha256'},
            'Exact original stage reference required')
    stages = [event for event in history if event['state'] == 'SD_STAGED']
    require(len(stages) == 1 and stages[0]['details'].get('stage_report') == stage_reference['path']
            and stages[0]['details'].get('stage_report_sha256') == stage_reference['sha256'],
            'Original staged receipt binding differs')


def _original(proof):
    return (proof.get('observation') == 'ORIGINAL' and isinstance(proof.get('targets'), dict)
            and all(proof['targets'].get(name, {}).get('observation') == 'ORIGINAL' for name in ('lib', 'app')))


def _card_proof(card, stage_reference, body):
    _, _, stage = assessment._json_reference(stage_reference)
    require(isinstance(card, dict) and card.get('evidence_sha256') == hashlib.sha256(assessment._canonical(
            {k: v for k, v in card.items() if k != 'evidence_sha256'})).hexdigest(), 'Inactive-card evidence payload changed')
    require(card.get('schema') == 'camera-install-inactive-card-observation/1'
            and card.get('stage_path') == stage_reference['path']
            and card.get('stage_sha256') == stage_reference['sha256']
            and card.get('candidate_inactive') is True and card.get('stable_identity_matches_stage') is True
            and card.get('root_matches_original_stage') is True
            and card.get('explicit_card_writes') is False and card.get('card_contents_or_names_modified') is False,
            'Complete read-only inactive-card evidence required')
    require(stage.get('state') == 'STAGED_UNRECOGNIZED_FILE_VERIFIED_NOT_ACTIVATED'
            and stage.get('source_sha256') == assessment.CANDIDATE_SHA256
            and stage.get('bytes') == assessment.CANDIDATE_BYTES
            and stage.get('existing_root_update_unchanged') is True
            and stage.get('BODYDATA_DAT_created_or_replaced') is False
            and stage.get('camera_internal_firmware_modified') is False
            and stage.get('updater_invoked') is False, 'Complete original staging receipt required')
    old = assessment._identity(stage.get('volume_identity'), body)
    require(isinstance(card.get('volume_identity'), dict), 'Complete card volume identity required')
    current = assessment._identity(dict(card['volume_identity'], body_matched=True), body)
    require(all(old[key] == current[key] for key in assessment.STABLE_KEYS), 'Cancellation card identity differs')
    require(isinstance(card.get('identity_observations'), list) and len(card['identity_observations']) >= 4
            and all(value == current for value in card['identity_observations']), 'Pinned card observations required')
    relative = assessment.staged_relative_path(stage.get('target'), old['mount'], assessment.CANDIDATE_SHA256)
    candidate = card.get('candidate', {})
    require(type(candidate.get('descriptor_identity')) is list and len(candidate['descriptor_identity']) == 5,
            'Full candidate descriptor readback required')
    require(candidate.get('path') == str(Path(current['mount']) / relative)
            and candidate.get('bytes') == assessment.CANDIDATE_BYTES
            and candidate.get('sha256') == assessment.CANDIDATE_SHA256, 'Complete inactive candidate readback differs')
    original = stage.get('existing_root_update')
    require(card.get('original_root_snapshot') == original and isinstance(original, dict), 'Original root baseline differs')
    root = card.get('root_update', {})
    require(root.get('path') == str(Path(current['mount']) / 'BODYDATA.DAT'), 'Original root path differs')
    if original.get('exists') is True:
        require(type(root.get('descriptor_identity')) is list and len(root['descriptor_identity']) == 5,
                'Full original descriptor readback required')
        require(set(original) == {'exists','bytes','sha256'}
                and original['sha256'] != assessment.CANDIDATE_SHA256
                and root.get('bytes') == original['bytes'] and root.get('sha256') == original['sha256'],
                'Original root full readback differs')
    else:
        require(original == {'exists': False} and root.get('exists') is False, 'Absent original root baseline differs')
    return card


def validate_cancellation_receipt(reference, binding, history, session_dir):
    """Replay immutable cancellation evidence; origin is a collector declaration."""
    _, _, report = assessment._json_reference(reference)
    from camera_install_receipts import source_declaration
    require(source_declaration(report) is True, 'Cancellation requires a consistent default collector declaration')
    if report.get('scope') == EPOCH_CANCEL_SCOPE:
        return _validate_epoch_cancellation(report,binding,history,session_dir)
    require(report.get('schema') == SCHEMA and report.get('state') == TERMINAL and report.get('scope') == SCOPE
            and all(report.get(key) == value for key, value in binding.items())
            and report.get('session_id') == Path(session_dir).name, 'Cancellation receipt scope/binding differs')
    _history(binding, history, session_dir, report.get('pending_reference'), report.get('stage_reference'))
    require(report.get('pending_event_sha256') == history[-1]['event_sha256']
            and report.get('history_sha256') == canonical_sha256(history), 'Cancellation history changed')
    require(report.get('producer_kind') == DEFAULT_PRODUCER and report.get('source_is_hardware') is True
            and report.get('injected_execution') is False and report.get('cancellation_authorized') is True
            and report.get('card_read_authorized') is True
            and report.get('operator_health_confirmed') is True
            and report.get('operator_never_started_confirmed') is True
            and report.get('both_targets_currently_original') is True
            and report.get('no_FLASH_history') is True and report.get('cancellation_recorded') is False
            and report.get('separately_authorized_cleanup_required') is False
            and all(report.get(key) is False for key in FALSE_CLAIMS), 'Default-only cancellation evidence required')
    completed = validate_completed_current_read(report.get('completed_read_reference'),
        pending_reference=report['pending_reference'], binding=binding, history=history, session_dir=session_dir)
    require(completed['receipt'].get('lease_identity') == report.get('lease_identity')
            and isinstance(report.get('lease_identity'), dict), 'Read and cancellation lease binding differs')
    require(completed['source_is_hardware'] is True and _original(completed['proof'])
            and report.get('completed_read_payload_sha256') == canonical_sha256(completed['receipt'])
            and report.get('current_read_proof') == completed['proof'], 'Trusted current ORIGINAL read required')
    _card_proof(report.get('card_evidence'), report['stage_reference'], binding['body_sha256'])
    require(report.get('card_collector_kind') == 'DEFAULT_FILESYSTEM_DISCOVERY'
            and report.get('card_evidence_sha256') == canonical_sha256(report['card_evidence']),
            'Default inactive-card collector binding required')
    return report


def run_cancellation_session(expected_body_sha256, evidence, *, plan_sha256, pending_reference,
        stage_reference, read_assets, read_review_path, read_review_sha256, journal, lease,
        cancellation_authorized=False, card_read_authorized=False, operator_health_confirmed=False,
        operator_never_started_confirmed=False, read_session=None, discover=None,
        clock=time.monotonic, sleep=time.sleep):
    """Own fresh read/STOP and card readback; never write card contents or RAM."""
    folder = assessment._safe_path(evidence)
    attempted, append_attempted = False, False
    try:
        require(cancellation_authorized is True and card_read_authorized is True,
                'Explicit preparation cancellation and card-read authorization required')
        require(operator_health_confirmed is True and operator_never_started_confirmed is True,
                'Healthy-camera and never-started-update operator confirmations required')
        require((read_session is None) == (discover is None), 'Read session and discovery must both be injected or both default')
        require(read_session is None or (callable(read_session) and callable(discover)), 'Callable cancellation observers required')
        injected = read_session is not None
        require(isinstance(journal, InstallJournal), 'Original pending journal required')
        identity, history, binding = _held_lease(lease), journal.events, journal.binding
        require(binding == dict(body_sha256=expected_body_sha256, plan_sha256=plan_sha256, model='ILCE-7M4'),
                'Same-body original-plan binding required')
        _history(binding, history, journal.session_dir, pending_reference, stage_reference)
        assessment._json_reference(pending_reference)
        assessment._json_reference(stage_reference)
        prepared_review = None
        if not injected:
            require(Path(lease.path).absolute() == DEFAULT_LOCK.absolute()
                    and journal.session_dir.parent.absolute() == DEFAULT_SESSIONS.absolute(),
                    'Default cancellation requires canonical held lease and journal')
            _source_only_runtime()
            import camera_install_patch_read_execution as execution
            import camera_install_patch_read_session as current_session
            prepared_review = execution.preflight_assets(read_assets, pending_reference=pending_reference,
                expected_body_sha256=expected_body_sha256, plan_sha256=plan_sha256)
            reviewed = current_session.validate_review(read_review_path, read_review_sha256, prepared_review)
        require(folder.is_dir() and not any(folder.iterdir()), 'Fresh empty cancellation evidence directory required')
        def guard():
            require(_held_lease(lease) == identity, 'Cancellation lease identity changed')
            require(InstallJournal.open(journal.session_dir).events == history and journal.events == history,
                    'Cancellation pending history changed')
            assert_operation_allowed(journal, allowed_states=(PENDING,))
            if journal.session_dir.parent.resolve() != DEFAULT_SESSIONS.resolve():
                assert_operation_allowed(sessions_root=DEFAULT_SESSIONS)
            assessment._json_reference(pending_reference)
            assessment._json_reference(stage_reference)
            if not injected:
                _source_only_runtime()
                require(current_session.validate_review(read_review_path, read_review_sha256, prepared_review) == reviewed,
                        'Cancellation current source review changed')
        guard()
        if not injected:
            from camera_install_patch_read_session import run_current_read_session
            from camera_sd_stage import discover as default_discover
            read_session, discover = run_current_read_session, default_discover
        read_folder = folder / 'current-read'
        read_folder.mkdir(mode=0o700)
        attempted = True
        observed = read_session(expected_body_sha256, read_folder, plan_sha256=plan_sha256,
            pending_reference=pending_reference, review_path=read_review_path, review_sha256=read_review_sha256,
            assets=read_assets, journal=journal, lease=lease, read_authorized=True, clock=clock, sleep=sleep)
        guard()
        read_reference = _reference(read_folder / 'current-read-session-exit.json')
        completed = validate_completed_current_read(read_reference, pending_reference=pending_reference,
            binding=binding, history=history, session_dir=journal.session_dir)
        require(completed['receipt'] == observed, 'Completed current read differs from owned return')
        require(observed.get('lease_identity') == identity
                and observed.get('current_review', {}).get('path') == str(Path(read_review_path).absolute())
                and observed.get('current_review', {}).get('sha256') == read_review_sha256,
                'Owned completed read lease/review binding differs')
        original = _original(completed['proof'])
        report = dict(schema=SCHEMA, scope=SCOPE, **binding, session_id=journal.session_dir.name,
            pending_reference=deepcopy(pending_reference), stage_reference=deepcopy(stage_reference),
            pending_event_sha256=history[-1]['event_sha256'], history_sha256=canonical_sha256(history),
            lease_identity=identity, completed_read_reference=read_reference,
            completed_read_payload_sha256=canonical_sha256(completed['receipt']), current_read_proof=completed['proof'],
            producer_kind='INJECTED_ASSESSMENT' if injected else DEFAULT_PRODUCER,
            source_is_hardware=not injected and completed['source_is_hardware'] is True,
            injected_execution=injected, provenance='DECLARED_COLLECTOR_NOT_CRYPTO_ATTESTED', cancellation_authorized=True, card_read_authorized=True,
            operator_health_confirmed=True, operator_never_started_confirmed=True,
            both_targets_currently_original=original, no_FLASH_history=True, cancellation_recorded=False,
            separately_authorized_cleanup_required=not original, **dict.fromkeys(FALSE_CLAIMS, False))
        if not original:
            report.update(state='CANCELLATION_BLOCKED_CURRENT_OBSERVATION',
                remaining_action='Separate authorization and implementation for current-context restoration or reviewed reboot semantics required')
            durable_new(folder / 'cancellation-blocked.json', report)
            guard()
            return report
        require(injected or completed['source_is_hardware'] is True, 'Default owned current read must declare hardware source')
        def pinned_discover():
            guard()
            value = discover()
            guard()
            return value
        card = assessment.observe_inactive_card(stage_reference, body_sha256=expected_body_sha256, discover=pinned_discover)
        guard()
        report.update(card_evidence=card, card_evidence_sha256=canonical_sha256(card),
            card_collector_kind='INJECTED_FILESYSTEM_DISCOVERY' if injected else 'DEFAULT_FILESYSTEM_DISCOVERY',
            state='CANCELLATION_ASSESSED_ONLY' if injected else TERMINAL)
        path = folder / ('cancellation-assessment.json' if injected else 'preparation-cancellation.json')
        durable_new(path, report)
        reference = _reference(path)
        _, _, saved = assessment._json_reference(reference)
        require(saved == report, 'Durable cancellation evidence changed')
        guard()
        if injected:
            return report
        validate_cancellation_receipt(reference, binding, history, journal.session_dir)
        guard()
        append_attempted = True
        event = journal.record_install_preparation_cancelled(path, explicit_user_approval=True)
        require(event['state'] == TERMINAL, 'Cancellation terminal was not recorded')
        return report | dict(cancellation_recorded=True, journal_event=event, cancellation_artifact=reference)
    except BaseException as error:
        try:
            if folder.is_dir():
                durable_new(folder / 'cancellation-unknown.json', dict(schema=SCHEMA,
                    state='CANCELLATION_UNKNOWN' if attempted else 'CANCELLATION_LOCAL_REJECTED',
                    error_type=type(error).__name__, cancellation_recorded=False,
                    journal_append_attempted=append_attempted, journal_may_have_changed=append_attempted,
                    journal_not_automatically_changed=not append_attempted,
                    automatic_retry=False, separately_authorized_cleanup_required=attempted,
                    remaining_action='Review unresolved current context and preserved receipts; restoration or reboot requires separate authorization and implementation'
                        if attempted else 'Correct local validation failure before a new attempt',
                    **dict.fromkeys(FALSE_CLAIMS, False)))
        except BaseException:
            pass
        raise


def _validate_epoch_cancellation(report,binding,history,session_dir):
    from camera_install_epoch_session import validate_completed_pending_epoch
    require(report.get('schema')==SCHEMA and report.get('state')==TERMINAL
        and all(report.get(k)==v for k,v in binding.items()) and report.get('session_id')==Path(session_dir).name,
        'AP-epoch cancellation scope/binding differs')
    _history(binding,history,session_dir,report.get('pending_reference'),report.get('stage_reference'))
    require(report.get('pending_event_sha256')==history[-1]['event_sha256']
        and report.get('history_sha256')==canonical_sha256(history)
        and report.get('producer_kind')=='DEFAULT_OWNED_PENDING_EPOCH_AND_INACTIVE_CARD'
        and report.get('source_is_hardware') is True and report.get('injected_execution') is False
        and all(report.get(k) is True for k in ('cancellation_authorized','card_read_authorized',
            'operator_health_confirmed','operator_never_started_confirmed','manual_AP_reboot_confirmed',
            'withdrawal_preceded_manual_AP_reboot_confirmed','reboot_order_is_operator_statement',
            'AP_boot_epoch_change_observed','previous_AP_process_contexts_ended','no_FLASH_history'))
        and report.get('cancellation_recorded') is False and report.get('separately_authorized_cleanup_required') is False
        and all(report.get(k) is False for k in (*FALSE_CLAIMS,'CP_coldboot_proven','NOR_state_proven','full_camera_coldboot_proven')),
        'Exact default AP-only cancellation declarations required')
    completed=validate_completed_pending_epoch(report.get('completed_epoch_reference'),
        pending_reference=report['pending_reference'],initial_runtime_reference=report['initial_runtime_reference'],
        withdrawal_reference=report['withdrawal_reference'],binding=binding,history=history,session_dir=session_dir)
    require(completed['source_is_hardware'] is True and completed['boot_id_differs'] is True
        and report.get('initial_boot_id')==completed['initial_boot_id']
        and report.get('current_boot_id')==completed['current_boot_id']
        and report.get('completed_epoch_payload_sha256')==canonical_sha256(completed['receipt'])
        and report.get('lease_identity')==completed['receipt'].get('lease_identity'),
        'Changed AP boot epoch must come from the owned trusted completed collector')
    _card_proof(report.get('card_evidence'),report['stage_reference'],binding['body_sha256'])
    require(report.get('card_collector_kind')=='DEFAULT_FILESYSTEM_DISCOVERY'
        and report.get('card_evidence_sha256')==canonical_sha256(report['card_evidence']),
        'Fresh default inactive-card evidence required after AP reboot')
    return report


def run_epoch_cancellation_session(body_sha256,evidence,*,plan_sha256,pending_reference,stage_reference,
        initial_runtime_reference,withdrawal_reference,epoch_assets,epoch_review_path,epoch_review_sha256,
        journal,lease,cancellation_authorized=False,card_read_authorized=False,operator_health_confirmed=False,
        operator_never_started_confirmed=False,manual_AP_reboot_confirmed=False,
        withdrawal_preceded_manual_AP_reboot_confirmed=False,epoch_session=None,discover=None,clock=time.monotonic,sleep=time.sleep):
    """Close preparation after an observed new AP boot, without power commands.

    The initial V2 boot observation precedes patch intent. Withdrawal is a
    separately retained before-power receipt. This establishes no CP/NOR state,
    original-mm restoration, firmware installation or future device condition.
    """
    import camera_install_epoch_session as epoch
    folder=assessment._safe_path(evidence);attempted=False;append_attempted=False
    try:
        require(all(value is True for value in (cancellation_authorized,card_read_authorized,
            operator_health_confirmed,operator_never_started_confirmed,manual_AP_reboot_confirmed,
            withdrawal_preceded_manual_AP_reboot_confirmed)),
            'Explicit AP-epoch cancellation, card read, healthy/never-FLASH/manual-reboot confirmations required')
        require((epoch_session is None)==(discover is None),'Epoch session and discovery must both be injected or default')
        require(epoch_session is None or (callable(epoch_session) and callable(discover)),'Callable paired epoch cancellation observers required')
        injected=epoch_session is not None
        require(isinstance(journal,InstallJournal),'Original pending preparation journal required')
        identity,history,binding=_held_lease(lease),journal.events,journal.binding
        require(binding==dict(body_sha256=body_sha256,plan_sha256=plan_sha256,model='ILCE-7M4'),'Epoch cancellation body/plan differs')
        _history(binding,history,journal.session_dir,pending_reference,stage_reference)
        prepared=summary=reviewed=None
        if not injected:
            require(Path(lease.path).absolute()==DEFAULT_LOCK.absolute()
                and journal.session_dir.parent.absolute()==DEFAULT_SESSIONS.absolute(),'Default AP cancellation requires canonical held context')
            _source_only_runtime()
            summary=epoch.source_summary(pending_reference,initial_runtime_reference,withdrawal_reference,binding,history,journal.session_dir)
            prepared=epoch.metadata.preflight_assets(epoch_assets)
            reviewed=epoch.validate_review(epoch_review_path,epoch_review_sha256,prepared,binding=binding,
                pending_reference=pending_reference,initial_runtime_reference=initial_runtime_reference,
                withdrawal_reference=withdrawal_reference,summary=summary,history=history,session_dir=journal.session_dir)
        require(folder.is_dir() and not any(folder.iterdir()),'Fresh empty AP cancellation evidence directory required')
        def guard():
            require(_held_lease(lease)==identity,'AP cancellation lease changed')
            require(InstallJournal.open(journal.session_dir).events==history and journal.events==history,'AP cancellation history changed')
            assert_operation_allowed(journal,allowed_states=(PENDING,))
            if journal.session_dir.parent.resolve()!=DEFAULT_SESSIONS.resolve():assert_operation_allowed(sessions_root=DEFAULT_SESSIONS)
            for ref in (pending_reference,stage_reference,initial_runtime_reference,withdrawal_reference):assessment._json_reference(ref)
            if not injected:
                _source_only_runtime()
                require(epoch.validate_review(epoch_review_path,epoch_review_sha256,prepared,binding=binding,
                    pending_reference=pending_reference,initial_runtime_reference=initial_runtime_reference,
                    withdrawal_reference=withdrawal_reference,summary=summary,history=history,session_dir=journal.session_dir)==reviewed,
                    'AP cancellation current source review changed')
        guard()
        if not injected:
            from camera_sd_stage import discover as actual_discover
            epoch_session,discover=epoch.run_pending_epoch_session,actual_discover
        subfolder=folder/'pending-epoch';subfolder.mkdir(mode=0o700);attempted=True
        observed=epoch_session(body_sha256,subfolder,plan_sha256=plan_sha256,pending_reference=pending_reference,
            initial_runtime_reference=initial_runtime_reference,withdrawal_reference=withdrawal_reference,
            review_path=epoch_review_path,review_sha256=epoch_review_sha256,assets=epoch_assets,journal=journal,lease=lease,
            epoch_read_authorized=True,operator_never_started_confirmed=True,manual_AP_reboot_confirmed=True,
            withdrawal_preceded_manual_AP_reboot_confirmed=True,clock=clock,sleep=sleep)
        guard();reference=_reference(subfolder/'pending-epoch-session-exit.json')
        completed=epoch.validate_completed_pending_epoch(reference,pending_reference=pending_reference,
            initial_runtime_reference=initial_runtime_reference,withdrawal_reference=withdrawal_reference,
            binding=binding,history=history,session_dir=journal.session_dir)
        require(completed['receipt']==observed and observed.get('lease_identity')==identity
            and observed.get('current_review',{}).get('path')==str(Path(epoch_review_path).absolute())
            and observed.get('current_review',{}).get('sha256')==epoch_review_sha256,'Owned epoch return/lease/review differs')
        changed=completed['boot_id_differs'] is True
        hardware=not injected and completed['source_is_hardware'] is True
        report=dict(schema=SCHEMA,scope=EPOCH_CANCEL_SCOPE,**binding,session_id=journal.session_dir.name,
            pending_reference=deepcopy(pending_reference),stage_reference=deepcopy(stage_reference),
            initial_runtime_reference=deepcopy(initial_runtime_reference),withdrawal_reference=deepcopy(withdrawal_reference),
            pending_event_sha256=history[-1]['event_sha256'],history_sha256=canonical_sha256(history),lease_identity=identity,
            completed_epoch_reference=reference,completed_epoch_payload_sha256=canonical_sha256(observed),
            initial_boot_id=completed['initial_boot_id'],current_boot_id=completed['current_boot_id'],
            AP_boot_epoch_change_observed=changed,previous_AP_process_contexts_ended=hardware and changed,
            source_is_hardware=hardware,injected_execution=injected,
            producer_kind='INJECTED_AP_EPOCH_ASSESSMENT' if injected else 'DEFAULT_OWNED_PENDING_EPOCH_AND_INACTIVE_CARD',
            provenance='DECLARED_COLLECTOR_NOT_CRYPTO_ATTESTED',cancellation_authorized=True,card_read_authorized=True,
            operator_health_confirmed=True,operator_never_started_confirmed=True,manual_AP_reboot_confirmed=True,
            withdrawal_preceded_manual_AP_reboot_confirmed=True,reboot_order_is_operator_statement=True,
            no_FLASH_history=True,cancellation_recorded=False,separately_authorized_cleanup_required=not changed,
            CP_coldboot_proven=False,NOR_state_proven=False,full_camera_coldboot_proven=False,**dict.fromkeys(FALSE_CLAIMS,False))
        if not changed:
            report.update(state='CANCELLATION_BLOCKED_SAME_AP_BOOT_EPOCH',remaining_action='No changed AP boot epoch observed; separate reviewed cleanup is still required')
            durable_new(folder/'cancellation-blocked.json',report);guard();return report
        require(injected or hardware,'Default AP epoch source must remain trusted')
        def pinned_discover():
            guard();value=discover();guard();return value
        card=assessment.observe_inactive_card(stage_reference,body_sha256=body_sha256,discover=pinned_discover)
        guard();report.update(card_evidence=card,card_evidence_sha256=canonical_sha256(card),
            card_collector_kind='INJECTED_FILESYSTEM_DISCOVERY' if injected else 'DEFAULT_FILESYSTEM_DISCOVERY',
            state='CANCELLATION_ASSESSED_ONLY' if injected else TERMINAL)
        path=folder/('cancellation-assessment.json' if injected else 'preparation-cancellation.json')
        durable_new(path,report);artifact=_reference(path)
        require(assessment._json_reference(artifact)[2]==report,'Durable AP cancellation report changed');guard()
        if injected:return report
        validate_cancellation_receipt(artifact,binding,history,journal.session_dir);guard();append_attempted=True
        event=journal.record_install_preparation_cancelled(path,explicit_user_approval=True)
        require(event['state']==TERMINAL,'AP preparation cancellation was not recorded')
        return report|dict(cancellation_recorded=True,journal_event=event,cancellation_artifact=artifact)
    except BaseException as error:
        try:
            if folder.is_dir():durable_new(folder/'cancellation-unknown.json',dict(schema=SCHEMA,scope=EPOCH_CANCEL_SCOPE,
                state='AP_EPOCH_CANCELLATION_UNKNOWN' if attempted else 'LOCAL_AP_EPOCH_CANCELLATION_REJECTED',
                error_type=type(error).__name__,journal_append_attempted=append_attempted,journal_may_have_changed=append_attempted,
                cancellation_recorded=False,automatic_retry=False,CP_coldboot_proven=False,NOR_state_proven=False,
                full_camera_coldboot_proven=False,**dict.fromkeys(FALSE_CLAIMS,False)))
        except BaseException:pass
        raise
