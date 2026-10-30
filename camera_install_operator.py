"""Prepare factual local artifacts and record separately supplied operator choices.

No confirmation is inferred from a development request. Machine facts and blank
operator templates never grant firmware permission. No device action exists.
"""
from copy import deepcopy
from pathlib import Path

import camera_install_admission as admission
from camera_install_receipts import load_reference, file_proof, safe_path, modeled
from camera_install_requirements import read_requirements
from camera_toolchain import PACKAGE, PLAIN, PACKAGE_SHA, PLAIN_SHA

ROOT = Path(__file__).resolve().parent
AUDIT = ROOT / 'output/full-install-blocker-premise-20261029-01/review.json'


def require(value, message):
    if not value:
        raise ValueError(message)


def _base(binding, schema):
    require(isinstance(binding, dict) and set(binding) == {'body_sha256','plan_sha256','model'}
            and binding['model'] == 'ILCE-7M4'
            and all(type(binding[k]) is str and len(binding[k]) == 64
                    and all(c in '0123456789abcdef' for c in binding[k]) for k in ('body_sha256','plan_sha256')),
            'Exact body/original-plan binding required')
    return dict(schema=schema, **binding, candidate_sha256=PACKAGE_SHA)


def _save(output, report):
    return admission._save(output, report)


def prepare_static_facts(output, *, binding, second_copies=None):
    """Rehash actual package/backups; keep every unverified recovery condition explicit."""
    folder = safe_path(output)
    require(folder.is_relative_to(ROOT/'output') and not folder.exists(), 'Fresh private workspace facts directory required')
    copies = {} if second_copies is None else dict(second_copies)
    _, baseline = load_reference(dict(path=str(admission.RECOVERY_BASELINE), sha256=admission.RECOVERY_BASELINE_SHA))
    partitions = baseline['partitions']
    require(set(copies).issubset({p['partition'] for p in partitions}), 'Unknown backup copy partition')
    encrypted = dict(path=str(PACKAGE), sha256=PACKAGE_SHA)
    plaintext = dict(path=str(PLAIN), sha256=PLAIN_SHA)
    file_proof(encrypted);file_proof(plaintext)
    requirements = read_requirements(PLAIN)
    audit = dict(path=str(AUDIT), sha256=admission.WRITE_SCOPE_AUDIT_SHA)
    load_reference(audit)
    backups = []
    for item in partitions:
        primary = dict(path=str(safe_path(ROOT/item['source'])),sha256=item['sha256'])
        file_proof(primary)
        copy = copies.get(item['partition'])
        if copy is None and item.get('recovery'):
            copy = dict(path=str(safe_path(ROOT/item['recovery'])),sha256=item['sha256'])
        if copy is not None:file_proof(copy)
        backups.append(dict(partition=item['partition'], bytes=item['bytes'], primary=primary, independent_copy=copy))
    candidate = _base(binding,'camera-install-candidate/1') | dict(encrypted=encrypted,plaintext=plaintext,
        required_partition_sizes=requirements['required_partition_sizes'])
    scope = _base(binding,'camera-install-write-scope/1') | dict(write_scope='full_sd',
        mutation_domains=list(admission.MUTATION_DOMAINS),audit_reference=audit)
    recovery = _base(binding,'camera-install-recovery/1') | dict(write_scope='full_sd',backup_references=backups,
        physical_nor_reference=None,backup_epoch_current=False,recovery_entry_verified=False,informed_exception_reference=None)
    folder.mkdir(mode=0o700,parents=True)
    references = dict(candidate=_save(folder/'candidate.json',candidate),
                      write_scope=_save(folder/'write-scope.json',scope),
                      recovery=_save(folder/'recovery-not-authorized.json',recovery))
    admission.validate_candidate(references['candidate'],binding)
    admission.validate_write_scope(references['write_scope'],binding)
    _, policy = admission.assess_recovery(references['recovery'],binding)
    policy_ref = _save(folder/'recovery-assessment.json',dict(schema='camera-install-recovery-assessment/1',
        **binding,candidate_sha256=PACKAGE_SHA,recovery_reference=references['recovery'],assessment=policy,
        approved=False,write_admission=False,installation_authorized=False))
    return dict(references,policy_assessment=policy_ref,approved=False,installation_authorized=False)


def record_recovery_exception(output, *, binding, recovery_reference, statement, explicit_user_approval=False):
    require(explicit_user_approval is True, 'Explicit acceptance of these exact recovery risks required')
    old, policy = admission.assess_recovery(recovery_reference,binding)
    require(policy['known_gaps'], 'No risk exception is needed')
    report = _base(binding,'camera-install-recovery-exception/1') | dict(
        approval_kind='EXPLICIT_USER_INFORMED_RECOVERY_EXCEPTION',write_scope='full_sd',
        accepted_gaps=policy['known_gaps'],approved=True,statement=statement)
    admission._statement(report)
    reference = _save(output,report)
    return reference


def bind_recovery_exception(output, *, binding, recovery_reference, exception_reference):
    _, report = load_reference(recovery_reference)
    report = deepcopy(report);report['informed_exception_reference'] = exception_reference
    reference = _save(output,report)
    admission.validate_recovery(reference,binding)
    return reference


def record_observation(output, *, binding, references, observed, statement, evidence_references):
    require(isinstance(observed,dict) and set(observed) == {'model','target_version',*admission.OBSERVED}
            and observed['model']=='ILCE-7M4' and observed['target_version']=='6.02'
            and all(observed[k] is True for k in admission.OBSERVED), 'Explicit complete current observations required')
    require(set(('runtime','pending','current_read','card')).issubset(references), 'Collected evidence references required')
    report = _base(binding,'camera-install-operator-observation/1') | dict(
        observation_kind='EXPLICIT_OPERATOR_OBSERVATION',observed=deepcopy(observed),statement=statement,
        evidence_references=deepcopy(evidence_references),
        **{name+'_reference':deepcopy(references[name]) for name in ('runtime','pending','current_read','card')})
    require(not modeled(report), 'Model observations cannot authorize firmware')
    admission._statement(report);admission._file_references(evidence_references)
    reference = _save(output,report)
    admission.validate_operator(reference,binding,references)
    return reference


def record_full_approval(output, *, binding, references, statement, explicit_user_approval=False):
    require(explicit_user_approval is True, 'Separate explicit full-install approval required')
    expected = admission.REF_KEYS - {'approval'}
    require(isinstance(references,dict) and set(references) == expected, 'Exact full-install evidence set required')
    report = _base(binding,'camera-install-full-approval/1') | dict(approval_kind='EXPLICIT_FULL_INSTALL_APPROVAL',
        scope='FULL_INSTALL',write_scope='full_sd',evidence_references=deepcopy(references),approved=True,statement=statement)
    require(not modeled(report), 'Model approval cannot authorize firmware')
    admission._statement(report)
    for reference in references.values():load_reference(reference)
    reference = _save(output,report)
    admission.validate_approval(reference,binding,references|{'approval':reference})
    return reference


def write_operator_template(output, *, binding):
    report = _base(binding,'camera-install-operator-template/1') | dict(template_only=True,
        approved=False,installation_authorized=False,statement='',observed={name:None for name in
            ('model','target_version',*admission.OBSERVED)},full_install_approval_required_separately=True)
    return _save(output,report)
