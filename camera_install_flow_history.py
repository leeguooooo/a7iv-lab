"""Data-only v1 flow history, separate from live-source execution admission.

Snapshots are integrity inputs, never executable modules. Known producer ABIs
are maintained here explicitly; an archive's self-declared hash grants no ABI
support or physical authenticity. Current execution must use the strict live
controller, never this historical reader.
"""
from pathlib import Path
import re

from camera_install_journal import InstallJournal
from camera_operation_guard import DEFAULT_SESSIONS
from camera_install_receipts import load_reference, safe_path, sha, canonical, validate_completed_pending, validate_completed_runtime, modeled

ROOT = Path(__file__).resolve().parent
SCHEMA = 'camera-install-flow-source-continuation/1'
ACTIVE_SCHEMA = 'camera-install-flow-source-continuation-active/1'
HEADER_SCHEMA = 'camera-install-flow/1'
CONFIG_SCHEMA = 'camera-install-flow-config/1'
DIGEST = 'fc8a7865c95059dcb4ac2a347a06b4a76f016b9c37dcc8412dfe9c2c2111de6a'
PLAIN_SHA = 'ebc7f537c21b685609f646670ab8b381db15d7283d259cbb587a2c0a008a51bf'
PENDING = 'INSTALL_PATCH_AWAITING_OPERATOR_RECONNECT'
READ_STEPS = ('prepare-read', 'read', 'observe-card')
CHANGED = ('camera_install_flow.py', 'tools/emulate_install_patch_read_offline.py')
HELPER = 'camera_install_flow_continuation.py'
BEFORE_CONTROLLER = 'e7a7f4892835508263b492cda7065e43455c16b801f7e85502c830a27cc81893'
BEFORE_EMULATOR = '30af0b6c78f04c18ae04d3f2604e8b12b8e0f847452b8d979c79adc6ec123810'
AFTER_CONTROLLER = 'b2e32e43198b3b76592113ec07fbd2c6a83ac433bd7aeb6995585f8f6186de08'
AFTER_EMULATOR = '8c407f2bf40fc59d092ba0dd7e412948c523022a8c868a39587216931fd7ee36'
CONTINUATION_HELPER = 'd9837989b30d251b13c8de866db7c1e7cbe53571580b8bb29a3c40a033857488'
CURRENT_CONTROLLER = '12a5c68db7b7d86dd202fa4019a888cac10912af294046454abad565047d7264'
APPROVAL_SHA256 = '530081b6d1adacf38c7dba4f26346a797e7afe7adad873e9a2ed9353255f1893'
CARD_KEYS = ('body_sha256', 'volume_uuid', 'filesystem', 'volume_bytes')
REQUIRED_SOURCES_V1 = frozenset(('camera_install_flow.py','tools/emulate_install_patch_read_offline.py',
    'camera_device_lease.py','camera_operation_guard.py','camera_install_journal.py',
    'camera_stream_channel.py','camera_stream_execution.py','native/install_patch_read.c',
    'Sony-PMCA-RE/pmca/usb/sony.py'))
STEPS_V1 = ('runtime','probe','stage','activate','patch','prepare-read','read','observe-card','admit',
    'start','complete','prepare-post','post','content','features','withdraw','prepare-epoch','cancel')
HOST_ONLY_V1 = frozenset(('prepare-read','prepare-post','prepare-epoch','admit','start','complete','content','features'))



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


def _config_v1(config_reference, *, injected=False):
    config=load(config_reference)
    require(config.get('card_activation_protocol', 'EXCLUSIVE_RENAME') in
            ('EXCLUSIVE_RENAME','BACKUP_COPY_ATOMIC_REPLACE'), 'Known historical card protocol required')
    require(config.get('schema')==CONFIG_SCHEMA and config.get('candidate_sha256')==DIGEST
        and type(config.get('model_fixture_only',False)) is bool
        and (injected or config.get('model_fixture_only',False) is False),'Formal flow config required')
    original_ref=config['original_plan_reference'];original=load(original_ref)
    require(original_ref==config['patch']['review_reference']
        and original.get('schema')=='camera-install-patch-session-plan/1'
        and original.get('scope')=='INSTALL_PREPARATION_VOLATILE_PATCH_ONLY'
        and original.get('body_sha256')==config.get('body_sha256') and original.get('model')=='ILCE-7M4'
        and original.get('package_sha256')==DIGEST and original.get('plaintext_sha256')==PLAIN_SHA
        and original.get('local_checks_passed') is True and original.get('prepared_offline_only') is True
        and original.get('execution_approval_received') is False
        and all(original.get(k) is False for k in ('installation_authorized','hardware_admission_proven','flash_authorized')),
        'Original plan must be the exact checked preparation review, never full-install permission')
    runtime=load(config['runtime']['review_reference'])
    require(runtime.get('asset_reference')==config['runtime']['asset_reference']
        and runtime.get('body_sha256')==config['body_sha256']
        and runtime.get('original_plan_sha256')==original_ref['sha256'],'Runtime original-plan/assets differ')
    require(original.get('asset_reference')==config['patch']['asset_reference'],'Patch assets differ from original review')
    local(config['post']['directory'],directory=True)
    require(isinstance(config['post'].get('asset_reference'),dict),'Reviewed post asset reference required')
    return config


def _snapshot_sources(sources, directory):
    directory = local(directory, directory=True)
    require(type(sources) is dict and REQUIRED_SOURCES_V1.issubset(sources), 'Historical source closure incomplete')
    for name, digest in sources.items():
        require(type(digest) is str and re.fullmatch('[0-9a-f]{64}', digest), 'Invalid historical source hash')
        path = _source_path(directory, name)
        require(path.is_file() and path.stat().st_size <= 4 << 20 and sha(path.read_bytes()) == digest,
                'Historical source snapshot changed: ' + name)


def _sources_v1(config, sources, directory):
    old = config['sources']
    require(old.get(CHANGED[0]) == BEFORE_CONTROLLER and old.get(CHANGED[1]) == BEFORE_EMULATOR
            and HELPER not in old, 'Unsupported original flow source profile')
    _snapshot_sources(old, config['source_snapshot_directory'])
    require(set(sources) == set(old) | {HELPER}, 'Historical continuation closure differs')
    expected = dict(old)
    expected.update({CHANGED[0]: AFTER_CONTROLLER, CHANGED[1]: AFTER_EMULATOR, HELPER: CONTINUATION_HELPER})
    require(sources == expected, 'Unsupported historical continuation source profile')
    _snapshot_sources(sources, directory)



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


def _transition_v1(history, state):
    edges = {'PLANNED': {'SD_STAGE_INTENT'}, 'SD_STAGE_INTENT': {'SD_STAGED'},
             'SD_STAGED': {'INSTALL_PATCH_MAY_BE_ACTIVE'},
             'INSTALL_PATCH_MAY_BE_ACTIVE': {'INSTALL_PATCH_AWAITING_OPERATOR_RECONNECT'}}
    require(state == 'PLANNED' if not history else state in edges.get(history[-1]['state'], set()),
            'Unsupported historical producer journal transition')


def _context_v1(review):
    folder = local(review['flow_directory'], directory=True)
    require(review['header_reference'] == reference(folder / 'flow.json'), 'Original flow header changed')
    header = load(review['header_reference'])
    require(header.get('schema') == HEADER_SCHEMA and header.get('injected_execution') is False
            and header['config_reference'] == review['config_reference']
            and header['journal_session'] == review['journal_directory'], 'Continuation belongs to another flow/journal')
    config = _config_v1(review['config_reference'], injected=False)
    require(review['body_sha256'] == config['body_sha256'] and review['candidate_sha256'] == config['candidate_sha256']
            and review['original_plan_reference'] == config['original_plan_reference'], 'Original body/plan/candidate changed')
    _approval(review['approval_reference'], folder, review['config_reference'])
    events = _event_prefix(folder, review['event_prefix'])
    require(review['event_ancestor_sha256'] == events[-1]['event_sha256'], 'Flow ancestor differs')
    session = local(review['journal_directory'], directory=True)
    require(session.parent == DEFAULT_SESSIONS, 'Canonical original journal required')
    # Producers may be validated from a future admission event: never open
    # that future journal here, which would recurse into its card producer.
    from camera_install_journal import _read_json, _canonical, _binding
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
        _transition_v1(history, event['state'])
        history.append(event)
    journal = InstallJournal(session, history)
    ancestor = history[-1]
    require(ancestor['state'] == PENDING and ancestor['event_sha256'] == review['journal_ancestor_sha256']
            and journal.binding == dict(body_sha256=config['body_sha256'], plan_sha256=config['original_plan_reference']['sha256'], model='ILCE-7M4'),
            'Original known pending journal ancestor required')
    pending = _artifact(events, 'patch')
    require(pending == review['pending_reference'] and ancestor['details'].get('install_patch_artifact') == pending,
            'Original pending artifact changed')
    pending_proof = validate_completed_pending(pending, binding=journal.binding, history=history, session_dir=session)
    runtime_proof = validate_completed_runtime(_artifact(events, 'runtime'),
            binding=journal.binding, history=history, session_dir=session)
    require(pending_proof['source_is_hardware'] is True and runtime_proof['source_is_hardware'] is True,
            'Original complete pending/runtime producers must declare real sources')
    stage, activation_receipt = (load(_artifact(events, name)) for name in ('stage', 'activate'))
    card = {key: stage['volume_identity'][key] for key in CARD_KEYS}
    require(review['card_identity'] == card and card['body_sha256'] == config['body_sha256']
            and all(activation_receipt['volume_identity'][key] == value for key, value in card.items())
            and activation_receipt.get('state') == 'ACTIVATED_PREVIEW_ONLY'
            and activation_receipt.get('updater_invoked') is False, 'Original activated body/card context differs')
    return config, journal


def _artifact(events, step):
    matches = [e for e in events if e['step'] == step and e['phase'] == 'COMPLETED']
    require(len(matches) == 1, 'Unique historical producer completion required')
    wrapper = load(matches[0]['receipt_reference'])
    ref = wrapper['artifact_reference']
    load(ref)
    return ref


def _config_history(folder, header):
    require(header.get('schema') == HEADER_SCHEMA and header.get('injected_execution') is False,
            'Historical production flow required')
    config = _config_v1(header['config_reference'], injected=False)
    active_path = folder / 'source-continuation.json'
    if active_path.exists() or active_path.is_symlink():
        active = load(reference(active_path))
        require(active.get('schema') == ACTIVE_SCHEMA and active.get('flow_directory') == str(folder)
                and active.get('operation_consent_granted') is False, 'Flow-bound historical continuation required')
        active_ref = reference(active_path)
        review = load(active['review_reference'])
        require(review.get('schema') == SCHEMA and review.get('flow_directory') == str(folder)
                and review.get('header_reference') == reference(folder / 'flow.json')
                and review.get('config_reference') == header['config_reference']
                and review.get('read_steps') == list(READ_STEPS) and review.get('operation_consent_granted') is False
                and review.get('other_steps_require_fresh_source_bound_operator') is True,
                'Historical source capsule belongs to another flow')
        # The first appended post-activation intent pins the exact capsule.
        # Read only that bound event, never a future journal/admission.
        next_event = folder / 'events' / f"{len(review['event_prefix'])+1:08d}.json"
        if next_event.exists() or next_event.is_symlink():
            anchor = load(reference(next_event))
            require(anchor.get('source_continuation_reference') == active_ref
                    and anchor.get('prev_sha256') == review['event_ancestor_sha256']
                    and anchor.get('phase') == 'INTENT' and anchor.get('step') in STEPS_V1
                    and anchor.get('event_sha256') == sha(canonical({k:v for k,v in anchor.items() if k != 'event_sha256'})),
                    'Historical source capsule does not match its recorded continuation intent')
        checked, _ = _context_v1(review)
        require(checked == config, 'Historical source capsule config differs')
        _sources_v1(config, review['sources'], review['source_snapshot_directory'])
        require(review['source_delta'] == {name: dict(before=config['sources'].get(name), after=review['sources'][name])
                for name in (*CHANGED, HELPER)}, 'Historical source delta differs')
    else:
        sources = config['sources']
        pair = (sources.get(CHANGED[0]), sources.get(CHANGED[1]))
        require(pair in ((BEFORE_CONTROLLER, BEFORE_EMULATOR), (CURRENT_CONTROLLER, AFTER_EMULATOR)),
                'Unsupported historical controller ABI')
        if pair[0] == CURRENT_CONTROLLER:
            require('camera_install_flow_history.py' in sources, 'Current historical parser source missing')
        _snapshot_sources(sources, config['source_snapshot_directory'])
    return config


def _events_v1(folder, producer_step=None):
    events, active, completed, attempts, unknown = [], None, set(), {}, False
    producer_intent = None
    for number, path in enumerate(sorted((folder / 'events').iterdir()), 1):
        require(number <= 10000 and path.name == f'{number:08d}.json', 'Historical flow sequence differs')
        event = load(reference(path))
        require(event['prev_sha256'] == (events[-1]['event_sha256'] if events else '0' * 64)
                and event['event_sha256'] == sha(canonical({k: v for k, v in event.items() if k != 'event_sha256'})),
                'Historical flow hash chain changed')
        step, phase, attempt = event.get('step'), event.get('phase'), event.get('attempt')
        require(step in STEPS_V1 and phase in ('INTENT','COMPLETED','UNKNOWN','REJECTED_LOCAL','BLOCKED_READ_ONLY')
                and type(attempt) is int and attempt > 0, 'Unknown historical event ABI')
        if phase == 'INTENT':
            require(active is None and not unknown and step not in completed and attempt == attempts.get(step,0)+1,
                    'Overlapping or replayed historical intent')
            attempts[step] = attempt
            active = (step, attempt)
            if step == producer_step:
                producer_intent = event
        else:
            require(active == (step, attempt), 'Historical result lacks matching intent')
            active = None
            if phase == 'COMPLETED':
                completed.add(step)
                load(event['receipt_reference'])
            elif phase == 'UNKNOWN':
                unknown = True
            elif phase == 'REJECTED_LOCAL':
                require(step in HOST_ONLY_V1 and event.get('journal_unchanged') is True
                        and event.get('SDK_requests_attempted') is False and event.get('manual_instruction_released') is False
                        and event.get('automatic_retry') is False, 'Historical local rejection differs')
            else:
                require(step == 'cancel' and event.get('journal_unchanged') is True and
                        event.get('cancellation_recorded') is False and event.get('automatic_retry') is False
                        and load(event['receipt_reference']).get('blocked_read_only') is True,
                        'Historical blocking observation differs')
        events.append(event)
        if step == producer_step and phase == 'COMPLETED':
            require(producer_intent is not None and event.get('source_is_hardware') is True,
                    'Historical real producer completion required')
            return events, producer_intent
    require(producer_step is None, 'Historical producer not completed')
    return events, None



def _journal_binding_v1(header, config, intent):
    """Check only the hash-bound ancestor recorded before a successful actor."""
    from camera_install_journal import _read_json, _canonical, _binding
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
        _transition_v1(history,event['state']);history.append(event)
        if event['event_sha256']==target:return expected
    raise ValueError('Producer journal ancestor exceeded bound')


def open_producer(folder, step):
    require(step in ('probe','activate','withdraw'), 'Historical producer role required')
    folder = local(folder, directory=True)
    header = load(reference(folder / 'flow.json'))
    config = _config_history(folder, header)
    events, intent = _events_v1(folder, step)
    return folder, header, config, events, _journal_binding_v1(header, config, intent)


def _content_proof_v1(folder, config, events, journal):
    from camera_postinstall_verify import verify_capture_run
    ref = _artifact(events, 'content')
    require(ref == journal.events[-1]['details']['verification_artifact'] and ref == _artifact(events, 'post'),
            'Historical content proof is not the recorded post result')
    saved = load(ref)
    require(not modeled(saved) and saved.get('source_is_hardware') is True
            and saved.get('all_passed') is True and saved.get('verification_scope') == 'FIRMWARE_FILES_AND_CRITICAL_SETTINGS',
            'Complete actual content proof required for historical status')
    group = local(Path(ref['path']).parent, directory=True)
    descriptor = load(reference(group / 'group.json'))
    verified = verify_capture_run(group / 'capture-run.json', plan_sha256=config['original_plan_reference']['sha256'],
            body_sha256=config['body_sha256'], model='ILCE-7M4', group_nonce=descriptor['group_nonce'], source_is_hardware=True)
    require(saved == verified and verified.get('all_passed') is True, 'Historical raw content evidence changed')


def open_closed(folder):
    """Read-only query role, never an execution or UNKNOWN reconciliation path."""
    folder = local(folder, directory=True)
    header = load(reference(folder / 'flow.json'))
    config = _config_history(folder, header)
    events, _ = _events_v1(folder)
    journal = InstallJournal.open(local(header['journal_session'], directory=True))
    require(journal.session_dir.parent == DEFAULT_SESSIONS and journal.state == 'CONTENT_VERIFIED'
            and journal.binding == dict(body_sha256=config['body_sha256'], plan_sha256=config['original_plan_reference']['sha256'], model='ILCE-7M4'),
            'Historical status requires a complete CONTENT_VERIFIED journal')
    require(not any(e['phase'] in ('UNKNOWN','INTENT') and not any(x['step'] == e['step'] and
            x['attempt'] == e['attempt'] and x['phase'] in ('COMPLETED','REJECTED_LOCAL','BLOCKED_READ_ONLY') for x in events)
            for e in events), 'Unresolved historical flow cannot become safe')
    _content_proof_v1(folder, config, events, journal)
    return folder, header, config, events, journal
