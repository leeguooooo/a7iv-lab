"""Evidence-bound full-install admission and manual-start intent; no executor.

An admission authorizes only the separately approved operator action. It does
not prove installation, historical hardware origin, mm continuity or recovery.
"""
from copy import deepcopy
import json
import os
from pathlib import Path

from camera_install_receipts import (require, canonical, sha, safe_path, file_proof,
    load_reference, modeled, validate_history, validate_completed_runtime,
    validate_completed_pending, validate_completed_current_read, validate_completed_card)
from camera_sd_stage import DIGEST, SIZE
from camera_package_audit import PLAIN_SHA, PLAIN_BYTES
from camera_install_requirements import read_requirements

ROOT = Path(__file__).resolve().parent
SCHEMA = 'camera-install-admission/1'
START_SCHEMA = 'camera-install-start-intent/1'
READY = 'INSTALL_READY_FOR_OPERATOR_START'
PENDING = 'INSTALL_PATCH_AWAITING_OPERATOR_RECONNECT'
REF_KEYS = frozenset(('runtime','pending','current_read','card','candidate','write_scope','recovery','operator','approval'))
MUTATION_DOMAINS = ('six_partition_images','conditional_P1_nwu','conditional_CP_NOR_0751',
                    'settings','MPR','logs','conditional_external_peripherals')
WRITE_SCOPE_AUDIT_SHA = 'cc1e8f86faa059a0ca2e8c6d5e79f796bca7e51af682abdf9aff6f54ffe48838'
RECOVERY_BASELINE = ROOT / 'output/recovery-readiness-20261029-01/backup-file-rehash.json'
RECOVERY_BASELINE_SHA = '7983203917b2081c63cbf94fe8de8aba26beb57b9f10e5e7672e2291cb5329c9'
OBSERVED = ('slot1','power_suitable','no_error_or_inhibit','no_restart_or_context_change_since_read','final_update_not_pressed')
FALSE_CLAIMS = ('firmware_installation_proven','physical_acceptance_proven','original_hardware_origin_proven',
                'original_mm_continuity_proven','restoration_proven','recovery_guaranteed','automatic_device_action')


def _binding(report, binding, schema):
    require(report.get('schema') == schema and all(report.get(k) == v for k,v in binding.items())
            and report.get('candidate_sha256') == DIGEST, 'Artifact schema/body/plan/candidate binding differs')
    require(not modeled(report), 'Model/injected artifacts cannot authorize installation')


def _statement(report):
    value = report.get('statement')
    require(type(value) is str and 1 <= len(value.strip()) <= 4096 and '\x00' not in value,
            'Bounded explicit operator statement required')


def _file_references(values):
    require(isinstance(values, list) and 0 < len(values) <= 64, 'Actual referenced evidence files required')
    return [file_proof(value) for value in values]


def validate_candidate(reference, binding):
    _, report = load_reference(reference)
    _binding(report, binding, 'camera-install-candidate/1')
    encrypted, plaintext = file_proof(report['encrypted']), file_proof(report['plaintext'])
    require(encrypted['sha256'] == DIGEST and encrypted['bytes'] == SIZE
            and plaintext['sha256'] == PLAIN_SHA and plaintext['bytes'] == PLAIN_BYTES,
            'Exact encrypted and plaintext candidate required')
    required = read_requirements(report['plaintext']['path'])
    require(report.get('required_partition_sizes') == required['required_partition_sizes']
            and required['model_code'] == 0x01030081 and required['region'] == 0,
            'Candidate package requirements differ')
    return report, required


def validate_write_scope(reference, binding):
    _, report = load_reference(reference)
    _binding(report, binding, 'camera-install-write-scope/1')
    require(report.get('write_scope') == 'full_sd' and report.get('mutation_domains') == list(MUTATION_DOMAINS),
            'Complete full-SD mutation domains required')
    require(report.get('audit_reference',{}).get('sha256') == WRITE_SCOPE_AUDIT_SHA, 'Pinned full candidate write-scope audit required')
    load_reference(report.get('audit_reference'))
    return report


def assess_recovery(reference, binding):
    _, report = load_reference(reference)
    _binding(report, binding, 'camera-install-recovery/1')
    require(report.get('write_scope') == 'full_sd', 'Full-SD recovery scope required')
    _, baseline = load_reference(dict(path=str(RECOVERY_BASELINE), sha256=RECOVERY_BASELINE_SHA))
    expected = {item['partition']: item for item in baseline['partitions']}
    backups = report.get('backup_references')
    require(isinstance(backups, list) and len(backups) == 14 and len(expected) == 14
            and {item.get('partition') for item in backups} == set(expected), 'Exact historical 14-partition inventory required')
    gaps = []
    copy_filesystem_facts = []
    for item in backups:
        name = item['partition'];old = expected[name]
        require(item.get('bytes') == old['bytes'], 'Historical backup geometry differs')
        primary = item.get('primary')
        if primary is None:
            gaps.append('primary_backup_missing:' + name)
            copy_filesystem_facts.append(dict(partition=name,primary_present=False,copy_present=False,physical_media_independence_proven=False))
            require(item.get('independent_copy') is None, 'Copy without a primary is not a verified pair')
            continue
        first = file_proof(primary)
        require(first['sha256'] == old['sha256'] and first['bytes'] == old['bytes'], 'Primary backup corrupt or mismatched')
        copy = item.get('independent_copy')
        if copy is None:
            gaps.append('independent_medium_missing:' + name)
            copy_filesystem_facts.append(dict(partition=name,primary_present=True,copy_present=False,primary_filesystem_device=first['device'],physical_media_independence_proven=False))
        else:
            second = file_proof(copy)
            require(second['sha256'] == first['sha256'] and second['bytes'] == first['bytes']
                    and (second['device'],second['inode']) != (first['device'],first['inode']), 'Backup copy corrupt, same file or mismatched')
            same_filesystem = second['device'] == first['device']
            copy_filesystem_facts.append(dict(partition=name,primary_present=True,copy_present=True,copy_bytes_match=True,
                primary_filesystem_device=first['device'],copy_filesystem_device=second['device'],same_filesystem=same_filesystem,physical_media_independence_proven=False))
            gaps.append(('independent_medium_missing:' if same_filesystem else 'independent_medium_unverified:') + name)
    nor = report.get('physical_nor_reference')
    if nor is None:
        gaps.append('physical_NOR_backup_missing')
    else:
        raise ValueError('No completed physical NOR collector contract is implemented; report the known missing-backup gap explicitly')
    for name in ('backup_epoch_current','recovery_entry_verified'):
        require(type(report.get(name)) is bool, 'Explicit recovery limitation required')
        require(report[name] is False, 'No validated current-epoch/full-recovery-entry contract exists for a True assertion')
        gaps.append(name + '_false')
    gaps = sorted(gaps)
    return report, dict(policy_status='POLICY_BLOCK' if gaps else 'POLICY_OK', known_gaps=gaps,
        copy_filesystem_facts=copy_filesystem_facts,physical_recovery_guaranteed=False)


def validate_recovery(reference, binding):
    report, assessment = assess_recovery(reference,binding)
    gaps = assessment['known_gaps']
    exception_ref = report.get('informed_exception_reference')
    if gaps:
        require(exception_ref is not None, 'Recovery POLICY_BLOCK: explicit informed exception missing')
        _, exception = load_reference(exception_ref)
        _binding(exception, binding, 'camera-install-recovery-exception/1')
        require(exception.get('approval_kind') == 'EXPLICIT_USER_INFORMED_RECOVERY_EXCEPTION'
                and exception.get('write_scope') == 'full_sd' and exception.get('approved') is True
                and exception.get('accepted_gaps') == gaps, 'Exception does not accept these exact known policy gaps')
        _statement(exception)
    else:
        require(exception_ref is None, 'Unnecessary recovery exception is ambiguous')
    return report, assessment | dict(policy_status='POLICY_OK_WITH_EXPLICIT_EXCEPTION' if gaps else 'POLICY_OK')


def validate_operator(reference, binding, references):
    _, report = load_reference(reference)
    _binding(report, binding, 'camera-install-operator-observation/1')
    require(report.get('observation_kind') == 'EXPLICIT_OPERATOR_OBSERVATION'
            and all(report.get(name+'_reference') == references[name] for name in ('pending','current_read','card','runtime')),
            'Actual operator observation must bind the exact collected evidence')
    observed = report.get('observed')
    require(isinstance(observed,dict) and set(observed) == {'model','target_version',*OBSERVED}
            and observed['model'] == 'ILCE-7M4' and observed['target_version'] == '6.02'
            and all(observed[name] is True for name in OBSERVED), 'Unknown or unacceptable current operator conditions')
    _statement(report);_file_references(report.get('evidence_references'))
    return report


def validate_approval(reference, binding, references):
    _, report = load_reference(reference)
    _binding(report, binding, 'camera-install-full-approval/1')
    expected = {name: references[name] for name in REF_KEYS - {'approval'}}
    require(report.get('approval_kind') == 'EXPLICIT_FULL_INSTALL_APPROVAL'
            and report.get('scope') == 'FULL_INSTALL' and report.get('write_scope') == 'full_sd'
            and report.get('approved') is True and report.get('evidence_references') == expected,
            'Separate exact full-install approval required before manual start')
    _statement(report)
    return report


def _admit(references, binding, history, session_dir):
    require(isinstance(references,dict) and set(references) == REF_KEYS, 'Complete exact admission references required')
    validate_history(binding,history,session_dir)
    runtime = validate_completed_runtime(references['runtime'],binding=binding,history=history,session_dir=session_dir)
    pending = validate_completed_pending(references['pending'],binding=binding,history=history,session_dir=session_dir)
    current = validate_completed_current_read(references['current_read'],pending_reference=references['pending'],binding=binding,history=history,session_dir=session_dir)
    card = validate_completed_card(references['card'],binding=binding,history=history,session_dir=session_dir)
    require(all(item['source_is_hardware'] is True and not modeled(item['receipt']) for item in (runtime,pending,current,card)),
            'Admission requires declared default-collector evidence; injected/model evidence is not admissible')
    require(runtime.get('receiver_compatible') is True and isinstance(runtime.get('receiver_proof'),dict),
            'Current full P1 receiver semantics must be verified from collected bytes')
    require(runtime['ancestor_index'] < pending['ancestor_index'] == current['ancestor_index'] == card['ancestor_index'],
            'Runtime must precede the exact same pending/read/card journal ancestor')
    require(current['proof']['observation'] == 'PATCHED'
            and all(item['observation'] == 'PATCHED' for item in current['proof']['targets'].values()),
            'Both current RAM targets must be PATCHED')
    _, package = validate_candidate(references['candidate'],binding)
    require(runtime['required_partition_sizes'] == package['required_partition_sizes'], 'Observed capacities use different package requirements')
    validate_write_scope(references['write_scope'],binding)
    _, recovery = validate_recovery(references['recovery'],binding)
    validate_operator(references['operator'],binding,references)
    validate_approval(references['approval'],binding,references)
    return dict(pending_event_sha256=history[pending['ancestor_index']]['event_sha256'],
        runtime_group_nonce=runtime['receipt']['group_nonce'], current_read_nonce=current['proof']['nonce'],
        receiver_proof=runtime['receiver_proof'], recovery=recovery, provenance='DECLARED_DEFAULT_COLLECTOR_NOT_CRYPTO_ATTESTED')


def validate_admission_receipt(reference, binding, history, session_dir):
    _, report = load_reference(reference)
    require(report.get('schema') == SCHEMA and report.get('state') == 'FULL_INSTALL_ADMISSION_RECORDED'
            and all(report.get(k) == v for k,v in binding.items()) and report.get('session_id') == Path(session_dir).name
            and report.get('candidate_sha256') == DIGEST and report.get('write_scope') == 'full_sd'
            and report.get('installation_authorized') is True and report.get('manual_start_required') is True
            and all(report.get(name) is False for name in FALSE_CLAIMS), 'Full-install admission scope differs')
    proof = _admit(report.get('references'),binding,history,session_dir)
    require(report.get('proof') == proof, 'Admission proof differs from completed evidence')
    return report


def validate_start_intent(reference, binding, history, session_dir):
    validate_history(binding,history,session_dir)
    _, report = load_reference(reference)
    matches = [(i,e) for i,e in enumerate(history) if e['state'] == READY and e['event_sha256'] == report.get('ready_event_sha256')]
    require(len(matches) == 1, 'Unique formal READY ancestor required')
    ready_index, ready_event = matches[0]
    require(report.get('schema') == START_SCHEMA and report.get('state') == 'MANUAL_START_MAY_FOLLOW'
            and all(report.get(k) == v for k,v in binding.items()) and report.get('session_id') == Path(session_dir).name
            and report.get('candidate_sha256') == DIGEST and report.get('write_scope') == 'full_sd'
            and report.get('ready_event_sha256') == ready_event['event_sha256']
            and report.get('admission_reference') == ready_event['details'].get('admission_artifact')
            and report.get('manual_start_not_yet_instructed') is True and report.get('automatic_device_action') is False,
            'Manual start intent is not bound to the formal READY event')
    admission = validate_admission_receipt(report['admission_reference'],binding,history[:ready_index],session_dir)
    require(report.get('approval_reference') == admission['references']['approval'], 'Manual start approval differs')
    return report


def _save(path, report):
    path = safe_path(path)
    require(path.parent.is_dir(), 'Existing private output directory required')
    raw = json.dumps(report,sort_keys=True,indent=2,allow_nan=False).encode()+b'\n'
    with path.open('xb') as stream:
        os.fchmod(stream.fileno(),0o600);stream.write(raw);stream.flush();os.fsync(stream.fileno())
    fd=os.open(path.parent,os.O_RDONLY)
    try:os.fsync(fd)
    finally:os.close(fd)
    return dict(path=str(path),sha256=sha(raw))


def seal_admission(output, *, binding, history, session_dir, references):
    require(history[-1]['state'] == PENDING, 'Admission must be recorded from original pending state')
    proof = _admit(references,binding,history,session_dir)
    report = dict(schema=SCHEMA,state='FULL_INSTALL_ADMISSION_RECORDED',**binding,session_id=Path(session_dir).name,
        candidate_sha256=DIGEST,write_scope='full_sd',references=deepcopy(references),proof=proof,
        installation_authorized=True,manual_start_required=True,**dict.fromkeys(FALSE_CLAIMS,False))
    return _save(output,report)


def seal_start_intent(output, *, admission_reference, binding, history, session_dir):
    require(history[-1]['state'] == READY and history[-1]['details'].get('admission_artifact') == admission_reference,
            'Formal recorded READY admission required')
    admission=validate_admission_receipt(admission_reference,binding,history[:-1],session_dir)
    report=dict(schema=START_SCHEMA,state='MANUAL_START_MAY_FOLLOW',**binding,session_id=Path(session_dir).name,
        candidate_sha256=DIGEST,write_scope='full_sd',ready_event_sha256=history[-1]['event_sha256'],
        admission_reference=deepcopy(admission_reference),approval_reference=admission['references']['approval'],
        manual_start_not_yet_instructed=True,automatic_device_action=False)
    reference=_save(output,report)
    validate_start_intent(reference,binding,history,session_dir)
    return reference
