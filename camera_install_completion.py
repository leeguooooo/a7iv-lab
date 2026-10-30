"""Bind an operator's completion/re-entry report to the formal update intent.

This records an observation and explicit re-entry permission, not file contents,
physical NOR, update atomicity, photographic behavior or recovery capability.
"""
from pathlib import Path

from camera_install_receipts import load_reference, validate_history, file_proof, modeled
from camera_install_admission import validate_start_intent, validate_admission_receipt
from camera_sd_stage import DIGEST

SCHEMA = 'camera-install-device-completion/1'
KIND = 'EXPLICIT_OPERATOR_UPDATE_COMPLETION'
FALSE_CLAIMS = ('installation_proven', 'photo_verified', 'video_verified', 'actual_NOR_verified',
                'whole_device_recovery_proven')


def require(value, message):
    if not value:
        raise ValueError(message)


def validate_completion_receipt(reference, binding, history, session_dir):
    _, report = load_reference(reference)
    return _validate_report(report, binding, history, session_dir)


def _validate_report(report, binding, history, session_dir):
    require(not modeled(report), 'Modeled completion cannot authorize normal-service re-entry')
    require(report.get('source_is_hardware') is False,
            'Completion is an operator observation, not a hardware collector attestation')
    validate_history(binding, history, session_dir)
    flashes = [(i, event) for i, event in enumerate(history)
               if event['state'] == 'FLASH_MAY_HAVE_STARTED'
               and event['event_sha256'] == report.get('flash_event_sha256')]
    require(len(flashes) == 1, 'Unique formal FLASH intent ancestor required')
    index, flash = flashes[0]
    require(not any(e['state'] == 'STOPPED_UNKNOWN' for e in history[index + 1:]),
            'Unknown update outcome cannot be replaced by a completion report')
    start_ref = flash['details'].get('start_intent_artifact')
    require(report.get('start_intent_reference') == start_ref, 'Completion refers to another start intent')
    start = validate_start_intent(start_ref, binding, history[:index], session_dir)
    ready = [(i, e) for i, e in enumerate(history[:index])
             if e['state'] == 'INSTALL_READY_FOR_OPERATOR_START'
             and e['event_sha256'] == start['ready_event_sha256']]
    require(len(ready) == 1, 'Formal READY ancestor required')
    admission = validate_admission_receipt(start['admission_reference'], binding,
                                          history[:ready[0][0]], session_dir)
    require(report.get('schema') == SCHEMA and report.get('state') == 'DEVICE_COMPLETION_REPORTED'
            and report.get('source_kind') == KIND and report.get('session_id') == Path(session_dir).name
            and all(report.get(k) == v for k, v in binding.items())
            and report.get('candidate_sha256') == DIGEST
            and report.get('runtime_reference') == admission['references']['runtime'],
            'Completion report must bind this candidate, baseline and session')
    require(all(report.get(k) is True for k in ('reported_complete', 'updater_stopped_confirmed',
            'normal_service_reentry_authorized', 'completed_after_camera_requested_steps')),
            'Explicit completed updater and normal-service re-entry confirmations required')
    require(all(report.get(k) is False for k in FALSE_CLAIMS), 'Operator completion is not installation acceptance')
    statement = report.get('statement')
    require(type(statement) is str and 0 < len(statement.strip()) <= 8192, 'Bounded explicit operator statement required')
    refs = report.get('evidence_references')
    require(isinstance(refs, list) and len(refs) <= 32, 'Bounded operator evidence list required')
    for ref in refs:
        file_proof(ref)
    return report


def seal_completion(output, *, binding, history, session_dir, observations):
    """Persist only supplied explicit observations; no defaults fill confirmations."""
    require(isinstance(observations, dict), 'Explicit completion observations required')
    require(not modeled(observations) and observations.get('source_is_hardware', False) is False,
            'Completion observations cannot claim model or hardware-collector authority')
    flashes = [e for e in history if e['state'] == 'FLASH_MAY_HAVE_STARTED']
    require(history and history[-1]['state'] == 'FLASH_MAY_HAVE_STARTED' and len(flashes) == 1,
            'Completion requires the current formal FLASH intent')
    flash = flashes[0]
    start_ref = flash['details'].get('start_intent_artifact')
    _, start = load_reference(start_ref)
    _, admission = load_reference(start['admission_reference'])
    report = dict(observations, schema=SCHEMA, state='DEVICE_COMPLETION_REPORTED', source_kind=KIND,
        **binding, session_id=Path(session_dir).name, candidate_sha256=DIGEST,
        flash_event_sha256=flash['event_sha256'], start_intent_reference=start_ref,
        runtime_reference=admission['references']['runtime'], source_is_hardware=False,
        **dict.fromkeys(FALSE_CLAIMS, False))
    output = Path(output).absolute()
    require(all(not p.is_symlink() for p in (output, *output.parents)), 'Nonsymlink completion output required')
    require(output.parent.is_dir() and not output.exists(), 'Fresh completion file with existing parent required')
    _validate_report(report, binding, history, session_dir)
    from camera_install_admission import _save
    reference = _save(output, report)
    validate_completion_receipt(reference, binding, history, session_dir)
    return reference
