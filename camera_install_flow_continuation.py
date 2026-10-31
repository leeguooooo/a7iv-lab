"""A source-version bridge for one locally rejected same-PID read preparation.

No SDK/device I/O, source rewriting, ledger mutation, or operation consent.
Historical bytes are parsed under this explicit v1 schema; snapshots are never
executed. Hashes detect drift relative to reviewed references, not authenticity
of a wholly rewritten ledger or an operator's identity.
"""
from pathlib import Path
import os

from camera_device_lease import DEFAULT_LOCK
from camera_install_journal import InstallJournal
from camera_install_patch_session import _held_lease
from camera_operation_guard import DEFAULT_SESSIONS, assert_operation_allowed
from camera_install_receipts import load_reference, safe_path, sha, canonical, validate_completed_pending, validate_completed_runtime
from camera_stream_execution import durable_new

ROOT = Path(__file__).resolve().parent
SCHEMA = 'camera-install-flow-source-continuation/1'
ACTIVE_SCHEMA = 'camera-install-flow-source-continuation-active/1'
PENDING = 'INSTALL_PATCH_AWAITING_OPERATOR_RECONNECT'
READ_STEPS = ('prepare-read', 'read', 'observe-card')
CHANGED = ('camera_install_flow.py', 'tools/emulate_install_patch_read_offline.py')
HELPER = 'camera_install_flow_continuation.py'
BEFORE_CONTROLLER = 'e7a7f4892835508263b492cda7065e43455c16b801f7e85502c830a27cc81893'
BEFORE_EMULATOR = '30af0b6c78f04c18ae04d3f2604e8b12b8e0f847452b8d979c79adc6ec123810'
AFTER_CONTROLLER = 'b2e32e43198b3b76592113ec07fbd2c6a83ac433bd7aeb6995585f8f6186de08'
AFTER_EMULATOR = '8c407f2bf40fc59d092ba0dd7e412948c523022a8c868a39587216931fd7ee36'
APPROVAL_SHA256 = '530081b6d1adacf38c7dba4f26346a797e7afe7adad873e9a2ed9353255f1893'
CARD_KEYS = ('body_sha256', 'volume_uuid', 'filesystem', 'volume_bytes')


def require(value, message):
    if not value:
        raise ValueError(message)


def local(path, directory=False):
    p = safe_path(path)
    require(p.is_relative_to(ROOT / 'output'), 'Continuation must stay inside canonical workspace output')
    if directory:
        require(p.is_dir(), 'Existing local directory required')
    return p


def reference(path):
    p = local(path)
    require(p.is_file(), 'Regular continuation input required')
    return dict(path=str(p), sha256=sha(p.read_bytes()))


def load(ref):
    local(ref['path'])
    return load_reference(ref)[1]


def _source_path(directory, name):
    relative = Path(name)
    require(not relative.is_absolute() and '..' not in relative.parts, 'Relative source name required')
    return safe_path(directory / relative)


def _sources(config, new_sources, snapshots):
    """Old source semantics stay frozen; only this reviewed delta is current."""
    import camera_install_flow as flow
    old = config['sources']
    require(isinstance(old, dict) and old.get(CHANGED[0]) == BEFORE_CONTROLLER
            and old.get(CHANGED[1]) == BEFORE_EMULATOR and HELPER not in old,
            'Unsupported historical source version')
    require(set(new_sources) == set(old) | {HELPER} and set(flow.source_paths()).issubset(new_sources),
            'Complete current source closure required')
    original_snapshots = local(config['source_snapshot_directory'], directory=True)
    current_snapshots = local(snapshots, directory=True)
    changed = set()
    for name, digest in old.items():
        require(sha(_source_path(original_snapshots, name).read_bytes()) == digest,
                'Historical source snapshot changed: ' + name)
        if new_sources[name] != digest:
            changed.add(name)
    require(changed == set(CHANGED) and new_sources[CHANGED[0]] == AFTER_CONTROLLER
            and new_sources[CHANGED[1]] == AFTER_EMULATOR,
            'Only the exact reviewed emulator/controller repair may change')
    for name, digest in new_sources.items():
        require(sha(_source_path(ROOT, name).read_bytes()) == digest ==
                sha(_source_path(current_snapshots, name).read_bytes()),
                'Current continuation source or snapshot changed: ' + name)


def _event_prefix(folder, refs):
    require(type(refs) is list and 0 < len(refs) <= 10000, 'Bounded original event prefix required')
    events, active, completed = [], None, set()
    for number, item in enumerate(refs, 1):
        require(item['path'] == str(folder / 'events' / f'{number:08d}.json'), 'Flow prefix moved or missing')
        event = load(item)
        require(event['prev_sha256'] == (events[-1]['event_sha256'] if events else '0' * 64)
                and event['event_sha256'] == sha(canonical({k: v for k, v in event.items() if k != 'event_sha256'})),
                'Historical flow hash chain changed')
        step, phase, attempt = event['step'], event['phase'], event['attempt']
        require(type(attempt) is int and attempt == 1, 'Only the original first-attempt prefix is supported')
        if phase == 'INTENT':
            require(active is None and step not in completed, 'Original flow has overlapping/repeated intent')
            active = step
        elif phase == 'COMPLETED':
            require(active == step and event.get('source_is_hardware') is True, 'Original real producer completion required')
            load(event['receipt_reference'])
            completed.add(step)
            active = None
        elif phase == 'REJECTED_LOCAL':
            require(active == step == 'prepare-read' and event is not None
                    and event.get('journal_unchanged') is True and event.get('SDK_requests_attempted') is False
                    and event.get('manual_instruction_released') is False and event.get('automatic_retry') is False,
                    'Exact local-only failed preparation proof required')
            active = None
        else:
            raise ValueError('Unknown or unsupported original flow outcome')
        events.append(event)
    require(active is None and completed == {'runtime', 'probe', 'stage', 'activate', 'patch'}
            and len(events) == 12 and events[-1]['step'] == 'prepare-read'
            and events[-1]['phase'] == 'REJECTED_LOCAL', 'Exact completed producer/local-rejection prefix required')
    return events


def _approval(ref, folder, config_ref):
    require(ref['sha256'] == APPROVAL_SHA256, 'Exact existing preparation authorization required')
    value = load(ref)
    require(value.get('schema') == 'onsite-explicit-preparation-approval/1'
            and value.get('config_sha256') == config_ref['sha256']
            and value.get('flow') == str(folder.relative_to(ROOT))
            and value.get('authorized_steps') == dict.fromkeys(('stage', 'activate', 'patch', *READ_STEPS), 1)
            and value.get('patches_remain_acknowledged') is True and value.get('firmware_never_started') is True
            and value.get('slot1_confirmed') is True and value.get('single_writer_acknowledged') is True
            and value.get('installation_authorized') is False and value.get('manual_update_start_authorized') is False
            and value.get('automatic_retry') is False, 'Existing preparation approval differs')
    return value


def _context(review, *, activation=False):
    import camera_install_flow as flow
    folder = local(review['flow_directory'], directory=True)
    require(review['header_reference'] == reference(folder / 'flow.json'), 'Original flow header changed')
    header = load(review['header_reference'])
    require(header.get('schema') == flow.SCHEMA and header.get('injected_execution') is False
            and header['config_reference'] == review['config_reference']
            and header['journal_session'] == review['journal_directory'], 'Continuation belongs to another flow/journal')
    config = flow._config_structure(review['config_reference'], injected=False)
    require(review['body_sha256'] == config['body_sha256'] and review['candidate_sha256'] == config['candidate_sha256']
            and review['original_plan_reference'] == config['original_plan_reference'], 'Original body/plan/candidate changed')
    _approval(review['approval_reference'], folder, review['config_reference'])
    events = _event_prefix(folder, review['event_prefix'])
    require(review['event_ancestor_sha256'] == events[-1]['event_sha256'], 'Flow ancestor differs')
    session = local(review['journal_directory'], directory=True)
    require(session.parent == DEFAULT_SESSIONS, 'Canonical original journal required')
    # Producers may be validated from a future admission event: never open
    # that future journal here, which would recurse into its card producer.
    from camera_install_journal import _read_json, _canonical, _binding, _transition
    prefix = review['journal_prefix']
    require(type(prefix) is list and 0 < len(prefix) <= 10000, 'Original journal prefix missing')
    history = []
    for number, item in enumerate(prefix, 1):
        path = session / f'{number:08d}.json'
        require(item == reference(path), 'Original journal ancestor changed')
        raw, event = _read_json(path)
        require(raw == _canonical(event) and event['schema'] == 1 and type(event['schema']) is int
                and event['seq'] == number and type(event['seq']) is int and event['session_id'] == session.name
                and event['prev_sha256'] == (history[-1]['event_sha256'] if history else '0' * 64)
                and event['event_sha256'] == sha(_canonical({k: v for k, v in event.items() if k != 'event_sha256'})),
                'Historical journal chain changed')
        _binding(event['binding'])
        require(not history or event['binding'] == history[0]['binding'], 'Historical journal binding changed')
        _transition(history, event['state'])
        history.append(event)
    journal = InstallJournal(session, history)
    ancestor = history[-1]
    require(ancestor['state'] == PENDING and ancestor['event_sha256'] == review['journal_ancestor_sha256']
            and journal.binding == dict(body_sha256=config['body_sha256'], plan_sha256=config['original_plan_reference']['sha256'], model='ILCE-7M4'),
            'Original known pending journal ancestor required')
    pending = flow._artifact(events, 'patch')
    require(pending == review['pending_reference'] and ancestor['details'].get('install_patch_artifact') == pending,
            'Original pending artifact changed')
    pending_proof = validate_completed_pending(pending, binding=journal.binding, history=history, session_dir=session)
    runtime_proof = validate_completed_runtime(flow._artifact(events, 'runtime'),
            binding=journal.binding, history=history, session_dir=session)
    require(pending_proof['source_is_hardware'] is True and runtime_proof['source_is_hardware'] is True,
            'Original complete pending/runtime producers must declare real sources')
    stage, activation_receipt = (load(flow._artifact(events, name)) for name in ('stage', 'activate'))
    card = {key: stage['volume_identity'][key] for key in CARD_KEYS}
    require(review['card_identity'] == card and card['body_sha256'] == config['body_sha256']
            and all(activation_receipt['volume_identity'][key] == value for key, value in card.items())
            and activation_receipt.get('state') == 'ACTIVATED_PREVIEW_ONLY'
            and activation_receipt.get('updater_invoked') is False, 'Original activated body/card context differs')
    if activation:
        require(len(list(session.iterdir())) == len(prefix) and journal.state == PENDING
                and len(list((folder / 'events').iterdir())) == len(events), 'Continuation activation requires unchanged locally rejected pending boundary')
        require(InstallJournal.open(session).events == history, 'Live pending journal differs at activation')
        assert_operation_allowed(journal, allowed_states=(PENDING,))
    return config, journal


def validate_review(ref, *, activation=False):
    review = load(ref)
    require(review.get('schema') == SCHEMA and review.get('read_steps') == list(READ_STEPS)
            and review.get('operation_consent_granted') is False
            and review.get('other_steps_require_fresh_source_bound_operator') is True,
            'Source continuation grants no operation consent')
    config, journal = _context(review, activation=activation)
    _sources(config, review['sources'], review['source_snapshot_directory'])
    expected_delta = {name: dict(before=config['sources'].get(name), after=review['sources'][name])
                      for name in (*CHANGED, HELPER)}
    require(review['source_delta'] == expected_delta, 'Exact reviewed source delta required')
    return review, config, journal


def seal(flow_directory, output, *, approval_reference, lease):
    """Prepare a review under current ownership; never creates the active sidecar."""
    import camera_install_flow as flow
    require(safe_path(lease.path) == safe_path(DEFAULT_LOCK), 'Canonical continuation lease required')
    identity = _held_lease(lease)
    folder, out = local(flow_directory, directory=True), local(output)
    require(not out.exists(), 'Fresh continuation review directory required')
    header_ref = reference(folder / 'flow.json')
    header = load(header_ref)
    config = flow._config_structure(header['config_reference'], injected=False)
    sources = {name: sha(_source_path(ROOT, name).read_bytes()) for name in set(config['sources']) | {HELPER}}
    journal = InstallJournal.open(header['journal_session'])
    refs = [reference(p) for p in sorted((folder / 'events').iterdir())]
    events = _event_prefix(folder, refs)
    stage = load(flow._artifact(events, 'stage'))
    out.mkdir(mode=0o700, parents=True)
    snapshots = out / 'sources'
    snapshots.mkdir(mode=0o700)
    for name, digest in sources.items():
        raw = _source_path(ROOT, name).read_bytes()
        require(sha(raw) == digest, 'Source changed while preparing continuation')
        path = _source_path(snapshots, name)
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with path.open('xb') as stream:
            os.fchmod(stream.fileno(), 0o400)
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    review = dict(schema=SCHEMA, flow_directory=str(folder), header_reference=header_ref,
            config_reference=header['config_reference'], original_plan_reference=config['original_plan_reference'],
            body_sha256=config['body_sha256'], candidate_sha256=config['candidate_sha256'],
            approval_reference=approval_reference, journal_directory=str(journal.session_dir),
            pending_reference=flow._artifact(events, 'patch'), card_identity={key: stage['volume_identity'][key] for key in CARD_KEYS},
            event_prefix=refs, event_ancestor_sha256=events[-1]['event_sha256'],
            journal_prefix=[reference(journal.session_dir / f'{i:08d}.json') for i in range(1, len(journal.events) + 1)],
            journal_ancestor_sha256=journal.events[-1]['event_sha256'], sources=sources,
            source_snapshot_directory=str(snapshots), read_steps=list(READ_STEPS),
            source_delta={name: dict(before=config['sources'].get(name), after=sources[name]) for name in (*CHANGED, HELPER)},
            operation_consent_granted=False, other_steps_require_fresh_source_bound_operator=True)
    path = out / 'review.json'
    durable_new(path, review)
    ref = reference(path)
    validate_review(ref, activation=True)
    require(_held_lease(lease) == identity, 'Lease changed while sealing source continuation')
    return ref


def activate(review_reference, *, lease):
    """Publish one new same-flow sidecar; no existing evidence is rewritten."""
    require(safe_path(lease.path) == safe_path(DEFAULT_LOCK), 'Canonical continuation lease required')
    identity = _held_lease(lease)
    review, _, _ = validate_review(review_reference, activation=True)
    folder = local(review['flow_directory'], directory=True)
    path = folder / 'source-continuation.json'
    durable_new(path, dict(schema=ACTIVE_SCHEMA, flow_directory=str(folder), review_reference=review_reference,
                lease_identity_at_activation=identity, operation_consent_granted=False))
    require(_held_lease(lease) == identity, 'Lease changed during source continuation activation')
    validate_active(folder, load(review['header_reference']))
    return reference(path)


def validate_active(folder, header):
    folder = local(folder, directory=True)
    active = load(reference(folder / 'source-continuation.json'))
    require(active.get('schema') == ACTIVE_SCHEMA and active.get('flow_directory') == str(folder)
            and active.get('operation_consent_granted') is False, 'Flow-bound source continuation required')
    review, config, _ = validate_review(active['review_reference'])
    require(review['flow_directory'] == str(folder) and load(review['header_reference']) == header,
            'Continuation cannot be reused for another flow')
    return config


def authorize_step(folder, step, operator):
    import camera_install_flow as flow
    active_ref = reference(local(folder, directory=True) / 'source-continuation.json')
    validate_active(folder, load(reference(Path(folder) / 'flow.json')))
    require(step in flow.STEPS, 'Known formal-flow step required')
    if step not in READ_STEPS:
        require(operator.get('source_continuation_reference') == active_ref,
                'A fresh operator artifact must bind this exact source continuation for later operations')
