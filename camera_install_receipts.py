"""Read completed installation evidence without executing or consuming jobs.

Historical snapshots are checked against their recorded hashes, never against
current checkout files. Source declarations are not hardware attestation.
"""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import re
import stat

import camera_install_patch_read as current_read
import camera_install_runtime as runtime
import camera_install_runtime_metadata as metadata
import camera_postinstall_verify as postinstall
from camera_sd_stage import DIGEST, SIZE

SHA = re.compile(r'[0-9a-f]{64}\Z')
PROVENANCE = 'DECLARED_COLLECTOR_NOT_CRYPTO_ATTESTED'
LEGACY_BOOTSTRAP_CASES = ('success','wait_eintr','not_root','unlink_error','wrong_fs','low_tmpfs',
    'existing_job','existing_worker','write_error','short_write','fork_error','wait_status_error',
    'intermediate','grandchild_exec','exec_error','setsid_error')


def require(ok, message):
    if not ok:
        raise ValueError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def safe_path(value):
    path = Path(value).absolute()
    require('..' not in path.parts and all(not p.is_symlink() for p in (path, *path.parents)),
            'Canonical nonsymlink evidence path required')
    return path


def file_proof(reference, *, maximum=None):
    require(isinstance(reference, dict) and set(reference) >= {'path', 'sha256'}
            and type(reference['path']) is str and Path(reference['path']).is_absolute()
            and type(reference['sha256']) is str and SHA.fullmatch(reference['sha256']),
            'Complete absolute artifact reference required')
    path = safe_path(reference['path'])
    with path.open('rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and (maximum is None or before.st_size <= maximum),
                'Bounded regular evidence file required')
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        after = os.fstat(stream.fileno())
    identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    require(identity(before) == identity(after) == identity(path.stat())
            and digest == reference['sha256'], 'Artifact hash or identity changed')
    return dict(path=str(path), sha256=digest, bytes=before.st_size, device=before.st_dev,
                inode=before.st_ino)


def load_reference(reference):
    proof = file_proof(reference, maximum=16 << 20)
    raw = Path(proof['path']).read_bytes()
    require(sha(raw) == proof['sha256'], 'Artifact changed while reading')
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'Duplicate JSON key')
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=pairs)
    require(isinstance(value, dict), 'JSON evidence object required')
    if 'payload_sha256' in reference:
        require(reference['payload_sha256'] == sha(canonical(value)), 'Canonical payload changed')
    return raw, value


def modeled(value):
    if isinstance(value, dict):
        return any((key in {'model_fixture_only', 'injected', 'synthetic', 'test_only'} and item is True)
                   or (key in {'provenance', 'source_kind', 'evidence_kind', 'admission'} and isinstance(item, str)
                       and any(word in item.upper() for word in ('MODEL_ONLY', 'SYNTHETIC', 'INJECTED')))
                   or modeled(item) for key, item in value.items())
    if isinstance(value, list):
        return any(modeled(item) for item in value)
    return False


def source_declaration(value):
    require(type(value.get('source_is_hardware')) is bool, 'Explicit collector source declaration required')
    require(not modeled(value) or value['source_is_hardware'] is False,
            'Modeled or injected evidence cannot declare a hardware source')
    return value['source_is_hardware']


def validate_history(binding, history, session_dir):
    require(isinstance(binding, dict) and set(binding) == {'body_sha256', 'plan_sha256', 'model'}
            and binding['model'] == 'ILCE-7M4' and all(type(binding[n]) is str and SHA.fullmatch(binding[n])
                for n in ('body_sha256', 'plan_sha256')), 'Exact installation binding required')
    folder = safe_path(session_dir)
    require(isinstance(history, list) and history and history[0].get('state') == 'PLANNED', 'Complete history must begin with PLANNED')
    previous = '0' * 64
    for i, event in enumerate(history, 1):
        require(isinstance(event, dict) and event.get('binding') == binding
                and event.get('session_id') == folder.name and event.get('seq') == i
                and event.get('prev_sha256') == previous
                and event.get('event_sha256') == sha(canonical({k: v for k, v in event.items() if k != 'event_sha256'}) + b'\n'),
                'History hash chain/session binding differs')
        previous = event['event_sha256']
    return folder


def ancestor(history, event_sha256, states):
    matches = [(i, e) for i, e in enumerate(history) if e['event_sha256'] == event_sha256 and e['state'] in states]
    require(len(matches) == 1, 'Unique appropriate journal ancestor required')
    return matches[0][0]


def known_stop(events):
    require(isinstance(events, list), 'Service event list required')
    stops = [e for e in events if isinstance(e, dict) and e.get('event') == 'STOP_RESPONSE']
    require(len(stops) == 1 and stops[0].get('mode') == 'service'
            and (stops[0].get('success') is True or stops[0].get('known_pipe_response') is True),
            'Exactly one known service STOP required')


def historical_review(reference, *, expected_sources=None, required_sources=()):
    _, review = load_reference(reference)
    root = safe_path(Path(reference['path']).parent / 'sources')
    require(review.get('source_snapshot_directory') == str(root), 'Historical source snapshot binding differs')
    sources = review.get('sources')
    require(isinstance(sources, dict) and sources and set(required_sources).issubset(sources),
            'Complete historical source closure required')
    if expected_sources is not None:
        require(all(sources.get(name) == digest for name, digest in expected_sources.items()),
                'Historical native and host sources disagree')
    for name, digest in sources.items():
        relative = Path(name)
        require(not relative.is_absolute() and '..' not in relative.parts, 'Relative snapshot name required')
        file_proof(dict(path=str(root / name), sha256=digest))
    require(any(name.startswith('Sony-PMCA-RE/pmca/') for name in sources), 'Historical SDK source closure missing')
    return review


def historical_native(reference):
    directory = safe_path(reference.get('directory', reference.get('job_dir')))
    _, manifest = load_reference(dict(path=str(directory / 'manifest.json'), sha256=reference['manifest_sha256']))
    file_proof(dict(path=str(directory / 'libJit.so'), sha256=reference['module_sha256']))
    require(type(manifest.get('hardware_operations')) is int and manifest['hardware_operations'] == 0
            and manifest.get('hardware_acceptance') is False, 'Offline assets cannot claim physical acceptance')
    require(manifest.get('nonce') == reference['nonce'], 'Historical native nonce differs')
    for name, artifact in manifest.get('artifacts', {}).items():
        relative = Path(name)
        require(not relative.is_absolute() and '..' not in relative.parts, 'Relative native artifact required')
        proof = file_proof(dict(path=str(directory / name), sha256=artifact['sha256']))
        require(proof['bytes'] == artifact['bytes'], 'Historical native artifact size differs')
    require(isinstance(manifest.get('sources'), dict) and manifest['sources'], 'Historical native sources missing')
    model_sources = {}
    for name, field in (('native-model-report.json', 'native_model_sha256'), ('bootstrap-model-report.json', 'bootstrap_model_sha256')):
        _, report = load_reference(dict(path=str(directory / name), sha256=reference[field]))
        require(type(report.get('hardware_operations')) is int and report['hardware_operations'] == 0
                and report.get('real_ARM_process',report.get('real_ARM_process_executed')) is False,
                'CPU model cannot claim hardware process execution')
        legacy_bootstrap = report.get('schema') == 'camera-install-volatile-bootstrap-actual-artifact-model/1'
        require(report.get('all_passed') is True and (report.get('coverage_complete_for_declared_matrix') is True or legacy_bootstrap)
                and report.get('source_bindings', manifest['sources']) == manifest['sources']
                and report.get('artifact_bindings', manifest['artifacts']) == manifest['artifacts']
                and report.get('manifest_sha256', report.get('input_hashes', {}).get('manifest.json')) == reference['manifest_sha256'],
                'Historical complete native model binding differs')
        for input_name, digest in report.get('input_hashes',{}).items():
            require(input_name in {'manifest.json','verification.json','libJit.so','worker.elf'}, 'Unknown historical model input')
            file_proof(dict(path=str(directory/input_name),sha256=digest))
        declared = list(LEGACY_BOOTSTRAP_CASES) if legacy_bootstrap else report.get('declared_cases')
        if legacy_bootstrap:
            require(report.get('case_count') == 16 and report.get('bootstrap_CPU_emulated') is True
                    and report.get('worker_executed') is False and report.get('original_inputs_unchanged') is True,
                    'Legacy bootstrap execution contract differs')
        require(isinstance(declared,list) and declared and len(set(declared)) == len(declared), 'Historical declared model matrix missing')
        results = report.get('results',report.get('cases'))
        require(isinstance(results,list) and len(results) == len(declared)
                and all(isinstance(result,dict) and result.get('passed') is True
                    and result.get('case',result.get('scenario')) == case for result,case in zip(results,declared)),
                'Historical model matrix is incomplete')
        for key in ('debug_worker_sha256',):
            if key in report:
                require(report[key] == manifest['artifacts']['worker.debug.elf']['sha256'], 'Historical debug worker binding differs')
        for key, candidates in (
            ('emulator_sha256',('tools/emulate_install_runtime_metadata_offline.py','tools/emulate_install_patch_read_offline.py','tools/emulate_install_volatile_offline.py')),
            ('contract_sha256',('camera_install_runtime_metadata.py','camera_install_patch_read.py','camera_install_volatile.py')),
            ('profile_sha256',('tools/install_runtime_metadata_profile.py','tools/install_patch_read_profile.py','tools/install_volatile_profile.py'))):
            if key in report:
                selected = next((path for path in candidates if path in manifest['sources']),None)
                if selected is None and key == 'emulator_sha256' and 'native/install_volatile_patch.c' in manifest['sources']:
                    require(type(report[key]) is str and SHA.fullmatch(report[key]), 'Historical emulator hash missing')
                    model_sources['tools/emulate_install_volatile_offline.py'] = report[key]
                else:
                    require(selected is not None and report[key] == manifest['sources'][selected], 'Historical explicit source binding differs')
    return manifest | dict(historical_model_sources=model_sources)


def _result(reference, receipt, index, **values):
    return dict(reference=deepcopy(reference), receipt=receipt, ancestor_index=index,
        source_is_hardware=source_declaration(receipt), provenance=PROVENANCE,
        original_mm_continuity_proven=False, **values)


def historical_reservation(reservation, keys):
    require(isinstance(reservation,dict) and set(reservation) == {'record',*keys}, 'Complete historical reservation required')
    record = reservation['record']
    require(isinstance(record,dict) and record.get('automatic_retry') is False, 'One-shot reservation record required')
    for key in keys:
        _, saved = load_reference(reservation[key])
        require(saved == record, 'Historical once-claim differs from its reservation')
    return record


def _hardware_session(receipt):
    require(any(isinstance(event,dict) and event.get('model') == 'ILCE-7M4' and event.get('body_matched') is True
                for event in receipt.get('service_events',[])), 'Same-body normal preflight event missing')


def _original_captures(receipt, root):
    from camera_firmware_capture import JOBS
    reports = receipt['native_receipt'].get('full_live_file_capture_reports')
    require(isinstance(reports,dict) and set(reports) == {'pre_app','pre_ufp'}, 'Full original library captures required')
    for name, report in reports.items():
        expected = JOBS[name]; assets = receipt['asset_reference']['captures'][name]
        folder = safe_path(root / name)
        report_file = folder / 'firmware-capture.json'
        _, saved = load_reference(dict(path=str(report_file),sha256=sha(report_file.read_bytes())))
        require(saved == report and report.get('profile') == name and report.get('name') == name
                and report.get('source_is_hardware') is True and report.get('source_kind') == 'REGULAR'
                and report.get('source_path') == report.get('targetpath') == expected.path
                and report.get('nonce') == assets['nonce'] and report.get('module_sha256') == assets['module_sha256'],
                'Original library capture identity/source differs')
        raw = file_proof(dict(path=report['capture'],sha256=expected.sha256))
        require(safe_path(report['capture']).is_relative_to(folder) and raw['bytes'] == expected.size
                and report.get('bytes') == expected.size and report.get('sha256') == report.get('expected_sha256') == expected.sha256,
                'Original full library hash/geometry differs')
        records = {}
        for filename in ('completed.json','launch-and-ready.json','capture/status.json'):
            path = safe_path(folder / filename)
            _, records[filename] = load_reference(dict(path=str(path),sha256=sha(path.read_bytes())))
        final = report['native']; ready = records['launch-and-ready.json']['ready']; completed = records['completed.json']; status = records['capture/status.json']
        for row in (ready,final):
            require(all(type(row.get(k)) is int for k in ('version','phase','error','euid','pid','ppid','loader_pid','cleanup','flags'))
                    and row['version'] == 1 and row['error'] == row['euid'] == row['cleanup'] == 0
                    and row['ppid'] == 1 and row['pid'] > 1 and row['loader_pid'] > 1 and row['pid'] != row['loader_pid'],
                    'Original capture native lifecycle differs')
        require(all(final[k] == ready[k] for k in ('pid','ppid','euid','loader_pid')) and ready['phase'] == 1 and ready['flags'] == 3
                and final['phase'] == 6 and final['flags'] == 63 and final.get('offset') == expected.size
                and final.get('chunks') == (expected.size+8388607)//8388608
                and final.get('first_sha256') == final.get('second_sha256') == expected.sha256
                and records['launch-and-ready.json'].get('loader_pid') == final['loader_pid'] and completed.get('native') == final
                and completed.get('bytes') == expected.size and completed.get('partition') == name
                and safe_path(completed['backup']) == safe_path(report['capture']), 'Original capture native completion differs')
        require(status.get('nonce') == assets['nonce'] and status.get('sha256') == expected.sha256 and status.get('partition') == name
                and status.get('bytes') == expected.size and status.get('state') == 'TWO_READS_MATCHED'
                and status.get('source_is_hardware') is True and status.get('source_reads_equal_at_capture') is True
                and status.get('hardware_source_read_verified') is True, 'Original capture double-read evidence differs')


def validate_completed_pending(reference, *, binding, history, session_dir):
    validate_history(binding, history, session_dir)
    raw, receipt = load_reference(reference)
    index = ancestor(history, receipt.get('intent_event_sha256'), ('INSTALL_PATCH_MAY_BE_ACTIVE',))
    from camera_install_patch_session import validate_pending_receipt
    validate_pending_receipt(reference, binding, history[:index + 1])
    matches = [(i, e) for i, e in enumerate(history) if e['state'] == 'INSTALL_PATCH_AWAITING_OPERATOR_RECONNECT'
               and e['details'].get('install_patch_artifact') == reference]
    require(len(matches) == 1 and matches[0][0] > index, 'Pending receipt is not recorded in this journal')
    spec = current_read.derive_target_spec(raw, body_sha256=binding['body_sha256'], plan_sha256=binding['plan_sha256'])
    if source_declaration(receipt):
        _hardware_session(receipt)
        reservation = historical_reservation(receipt['reservation'], ('global_claim','attempt_claim'))
        require(all(reservation.get(k) == v for k,v in binding.items()) and reservation.get('asset_reference') == receipt['asset_reference']
                and reservation.get('session_id') == Path(session_dir).name
                and reservation.get('evidence') == str(safe_path(Path(reference['path']).parent)) and reservation.get('lease_instance') == receipt['lease_identity']['instance'],
                'Original hardware reservation/session differs')
        _original_captures(receipt, safe_path(Path(reference['path']).parent))
    native_manifest = historical_native(receipt['asset_reference']['patch'])
    review = historical_review(receipt['review_artifact'], expected_sources=native_manifest['sources'] | native_manifest.get('historical_model_sources',{}), required_sources=('camera_install_patch.py', 'camera_install_volatile.py'))
    require(review.get('schema') == 'camera-install-patch-session-plan/1'
            and review.get('scope') == 'INSTALL_PREPARATION_VOLATILE_PATCH_ONLY'
            and review.get('asset_reference') == receipt['asset_reference']
            and review.get('body_sha256') == binding['body_sha256'], 'Original review scope/body/assets differ')
    return _result(reference, receipt, matches[0][0], spec=spec)


def _completed_terminal(receipt, *, terminal_state, exit_state):
    require(receipt.get('state') == exit_state and receipt.get('service_exit_completed') is True
            and receipt.get('original_journal_unchanged') is True, 'Known completed service exit required')
    known_stop(receipt.get('service_events'))
    _, terminal = load_reference(receipt.get('terminal_artifact'))
    expected = deepcopy(receipt)
    for name in ('terminal_artifact', 'service_events', 'original_journal_unchanged'):
        expected.pop(name)
    expected['state'] = terminal_state
    expected['service_exit_completed'] = False
    require(terminal == expected, 'Completed receipt differs from full pre-STOP terminal')


def validate_completed_current_read(reference, *, pending_reference, binding, history, session_dir):
    folder = validate_history(binding, history, session_dir)
    pending = validate_completed_pending(pending_reference, binding=binding, history=history, session_dir=folder)
    _, receipt = load_reference(reference)
    require(receipt.get('schema') == 'camera-install-patch-read-session-receipt/1'
            and receipt.get('body_sha256') == binding['body_sha256']
            and receipt.get('original_plan_sha256') == binding['plan_sha256']
            and receipt.get('original_session_id') == folder.name
            and receipt.get('original_pending_reference') == pending_reference,
            'Completed current read has a different body/plan/pending/session')
    index = ancestor(history, receipt.get('original_pending_event_sha256'), ('INSTALL_PATCH_AWAITING_OPERATOR_RECONNECT',))
    require(index == pending['ancestor_index'] and receipt.get('original_history_sha256') == sha(canonical(history[:index + 1])),
            'Current read history does not match the pending ancestor')
    _completed_terminal(receipt, terminal_state='CURRENT_READ_TERMINAL_DURABLE_BEFORE_STOP', exit_state='CURRENT_READ_KNOWN_SERVICE_EXIT')
    native = receipt.get('native_receipt')
    require(isinstance(native, dict) and receipt.get('native_receipt_sha256') == sha(canonical(native))
            and native.get('asset_reference') == receipt.get('asset_reference')
            and native.get('reservation') == receipt.get('reservation'), 'Current native receipt binding differs')
    ref = receipt['asset_reference']
    require(ref.get('pending_reference') == pending_reference and ref.get('body_sha256') == binding['body_sha256']
            and ref.get('plan_sha256') == binding['plan_sha256'] and ref.get('target_spec_sha256') == current_read.spec_sha256(pending['spec']),
            'Current read asset derivation differs')
    publications = native.get('raw_publications')
    require(isinstance(publications, dict) and set(publications) == {'ready', 'result'}, 'Complete current read raw frames required')
    proof = current_read.validate_publications(*(bytes.fromhex(publications[n]) for n in ('ready', 'result')),
        nonce=bytes.fromhex(ref['nonce']), loader_pid=native.get('loader_pid'), spec=pending['spec'])
    require(all(native.get(k) == value for k, value in proof.items() if k != 'source_is_hardware'), 'Current read semantic proof differs from raw frames')
    require(source_declaration(native) is source_declaration(receipt)
            and receipt.get('original_source_declaration') is pending['source_is_hardware']
            and (receipt['source_is_hardware'] is False or pending['source_is_hardware'] is True),
            'Current/pending source declarations differ')
    if receipt['source_is_hardware']:
        _hardware_session(receipt)
        reservation = historical_reservation(receipt['reservation'], ('global_claim','job_claim'))
        require(reservation.get('asset_reference') == ref and reservation.get('session_id') == folder.name
                and reservation.get('pending_event_sha256') == history[index]['event_sha256']
                and reservation.get('lease_identity') == receipt['lease_identity']
                and reservation.get('evidence') == str(safe_path(Path(reference['path']).parent)), 'Current hardware reservation differs')
    native_manifest = historical_native(ref)
    review = historical_review(receipt['current_review'], expected_sources=native_manifest['sources'] | native_manifest.get('historical_model_sources',{}), required_sources=('camera_install_patch_read.py', 'camera_install_patch_read_execution.py'))
    require(review.get('schema') == 'camera-install-patch-read-session-plan/1' and review.get('asset_reference') == ref
            and review.get('pending_reference') == pending_reference
            and review.get('body_sha256') == binding['body_sha256'] and review.get('original_plan_sha256') == binding['plan_sha256'],
            'Historical current-read review scope/binding differs')
    return _result(reference, receipt, index, proof=proof)


def _relative_file(folder, reference):
    require(isinstance(reference, dict) and isinstance(reference.get('path'), str), 'Relative raw file reference required')
    relative = Path(reference['path'])
    require(not relative.is_absolute() and '..' not in relative.parts, 'Bound relative raw path required')
    path = safe_path(folder / relative)
    proof = file_proof(dict(path=str(path), sha256=reference['sha256']))
    require(type(reference.get('bytes')) is int and reference['bytes'] == proof['bytes'], 'Raw file size differs')
    return path.read_bytes()


def verify_current_receiver(raw):
    """Check current P1 boot semantics against the exact package/factory inputs."""
    header, _, factory_kernel, boot_files = postinstall._reference_inputs(postinstall.PLAIN, postinstall.FACTORY_P1)
    proof = postinstall.verify_p1_semantics(raw, header=header, factory_kernel=factory_kernel, boot_files=boot_files)
    return proof | dict(current_p1_sha256=sha(raw), plaintext_sha256=postinstall.PLAIN_SHA,
        factory_p1_sha256=postinstall.FACTORY_SHA, reference_header_sha256=sha(header))


def validate_completed_runtime(reference, *, binding, history, session_dir):
    validate_history(binding, history, session_dir)
    _, receipt = load_reference(reference)
    require(receipt.get('schema') == 'camera-install-runtime-session-receipt/1'
            and all(receipt.get(k) == v for k, v in binding.items())
            and receipt.get('scope') == 'INSTALL_PRE_RUNTIME_READ_ONLY' and receipt.get('acquisition_phase') == 'PRE_INSTALL',
            'Completed PRE_INSTALL runtime binding required')
    index = ancestor(history, receipt.get('journal_event_sha256'), ('PLANNED', 'SD_STAGED'))
    _completed_terminal(receipt, terminal_state='PRE_INSTALL_RUNTIME_TERMINAL_BEFORE_STOP', exit_state='PRE_INSTALL_RUNTIME_KNOWN_SERVICE_EXIT')
    source = source_declaration(receipt)
    if source:
        _hardware_session(receipt)
        reservation = historical_reservation(receipt['metadata_reservation'], ('global_claim','job_claim'))
        context = reservation.get('context',{})
        require(context.get('lease_identity') == receipt['lease_identity'] and context.get('journal_event_sha256') == history[index]['event_sha256']
                and context.get('body_sha256') == binding['body_sha256'] and context.get('plan_sha256') == binding['plan_sha256']
                and context.get('session_dir') == str(safe_path(session_dir))
                and reservation.get('asset_reference') == receipt['asset_reference']['metadata']
                and reservation.get('evidence') == str(safe_path(Path(reference['path']).parent/'runtime-metadata')),
                'Runtime metadata historical reservation differs')
    folder = safe_path(Path(reference['path']).parent)
    for item in receipt.get('evidence_files', []):
        _relative_file(folder, item)
    require(len(receipt.get('evidence_files', [])) >= 9, 'Full runtime evidence inventory required')
    group_raw = (folder / 'group.json').read_bytes()
    group = json.loads(group_raw)
    require(all(group.get(k) == v for k, v in binding.items()) and group.get('group_nonce') == receipt.get('group_nonce')
            and group.get('journal_session') == str(safe_path(session_dir)) and group.get('acquisition_phase') == 'PRE_INSTALL',
            'Runtime raw group/session differs')
    before = receipt.get('before_reference')
    require(isinstance(before, dict) and all(before.get(k) == v for k, v in binding.items())
            and before.get('group_nonce') == receipt['group_nonce'] and before.get('nonce') == receipt.get('pdt_nonce')
            and before.get('acquisition_phase') == 'PRE_INSTALL' and before.get('source_is_hardware') is source,
            'PRE_INSTALL PDT envelope differs')
    pdt = _relative_file(folder, receipt['raw_inputs']['pdt'])
    require(before.get('sha256') == sha(pdt) and before.get('path') == receipt['raw_inputs']['pdt']['path'], 'PDT raw envelope differs')
    require(before.get('path') == 'before.bk4', 'Fixed before-PDT filename required')
    before_path = safe_path(folder/'before-reference.json')
    _, before_saved = load_reference(dict(path=str(before_path),sha256=sha(before_path.read_bytes())))
    require(before_saved == before, 'Persisted before-PDT reference differs from exit envelope')
    p1ref = receipt['p1']['reference']
    require(p1ref.get('path') == 'runtime-pre-p1/firmware-capture.json'
            and p1ref.get('acquisition_phase') == 'PRE_INSTALL' and p1ref.get('group_nonce') == receipt['group_nonce']
            and all(p1ref.get(k) == v for k,v in binding.items()), 'P1 PRE_INSTALL group/reference differs')
    p1, p1proof = postinstall._capture(folder, 'post_p1', p1ref['path'], p1ref['sha256'], binding,
        receipt['group_nonce'], source, {receipt['group_nonce'], receipt['pdt_nonce'], receipt['asset_reference']['metadata']['nonce']}, set())
    require(receipt['p1'].get('acquisition_phase') == 'PRE_INSTALL' and receipt['p1'].get('technical_profile') == 'post_p1'
            and p1proof == receipt['p1']['native_proof'], 'P1 epoch or native proof differs')
    native = receipt['metadata_receipt']
    require(source_declaration(native) is source, 'Metadata source differs from runtime source')
    proof = metadata.validate_receipt(native, reference=receipt['asset_reference']['metadata'],
        reservation=receipt['metadata_reservation'], forensic_legacy=source is False)
    require(source is False or proof['metadata_version'] == metadata.VERSION,
            'Actual runtime collection requires current boot-epoch metadata V2')
    require(receipt['metadata_artifact'].get('path') == str(folder/'runtime-metadata/metadata-receipt.json'),
            'Metadata durable artifact must belong to this runtime group')
    _, saved_native = load_reference(receipt['metadata_artifact'])
    require(saved_native == native, 'Durable metadata raw receipt differs')
    proc = _relative_file(folder, receipt['raw_inputs']['partitions'])
    aliases = _relative_file(folder, receipt['raw_inputs']['aliases'])
    require(proc.hex() == native['partitions_raw_hex'] and aliases.hex() == native['aliases_raw_hex'], 'Runtime metadata payload differs')
    native_manifest = historical_native(receipt['asset_reference']['metadata'])
    review = historical_review(receipt['current_review'], expected_sources=native_manifest['sources'] | native_manifest.get('historical_model_sources',{}), required_sources=('camera_install_runtime.py', 'camera_install_runtime_metadata.py',
        'tools/fl23_prewrite_guard.py', 'ref/sony-a7m4-custom-firmware/a7m4/fat.py'))
    require(review.get('schema') == 'camera-install-runtime-session-plan/1' and review.get('acquisition_phase') == 'PRE_INSTALL'
            and review.get('asset_reference') == receipt['asset_reference'] and review.get('body_sha256') == binding['body_sha256']
            and review.get('original_plan_sha256') == binding['plan_sha256']
            and review.get('group_nonce') == receipt['group_nonce'] and review.get('pdt_nonce') == receipt['pdt_nonce'],
            'Historical runtime review binding/nonces differ')
    decoded = runtime.decode_runtime(pdt_raw=pdt, p1_raw=p1, partitions_raw=proc, alias_targets=proof['alias_targets'],
        required_partition_sizes=review['required_partition_sizes'], normal_model_name='ILCE-7M4')
    require(decoded == receipt['decoded_values'], 'Runtime values differ from raw parsing')
    receiver_proof = verify_current_receiver(p1) if source else None
    return _result(reference, receipt, index, decoded=decoded, required_partition_sizes=review['required_partition_sizes'],
        receiver_compatible=source and receiver_proof is not None, receiver_proof=receiver_proof,
        metadata_proof=proof, boot_id=proof['boot_id'], metadata_version=proof['metadata_version'])


def validate_completed_card(reference, *, stage_reference=None, activation_reference=None, binding, history, session_dir):
    folder = validate_history(binding, history, session_dir)
    _, receipt = load_reference(reference)
    require(receipt.get('schema') == 'camera-install-active-card-observation/1'
            and all(receipt.get(k) == v for k, v in binding.items()) and receipt.get('session_id') == folder.name,
            'Active-card session/body/plan differs')
    index = ancestor(history, receipt.get('journal_event_sha256'), ('INSTALL_PATCH_AWAITING_OPERATOR_RECONNECT',))
    source_declaration(receipt)
    stage_reference = receipt['stage_reference'] if stage_reference is None else stage_reference
    activation_reference = receipt['activation_reference'] if activation_reference is None else activation_reference
    require(receipt.get('stage_reference') == stage_reference and receipt.get('activation_reference') == activation_reference,
            'Card stage/activation references differ')
    _, stage = load_reference(stage_reference)
    _, activation = load_reference(activation_reference)
    stages = [e for e in history[:index] if e['state'] == 'SD_STAGED']
    require(len(stages) == 1 and stages[0]['details'].get('stage_report') == stage_reference['path']
            and stages[0]['details'].get('stage_report_sha256') == stage_reference['sha256'], 'Card stage journal binding differs')
    require(stage.get('state') == 'STAGED_UNRECOGNIZED_FILE_VERIFIED_NOT_ACTIVATED'
            and stage.get('source_sha256') == DIGEST and stage.get('bytes') == SIZE
            and stage.get('existing_root_update_unchanged') is True
            and all(stage.get(k) is False for k in ('BODYDATA_DAT_created_or_replaced','camera_internal_firmware_modified','updater_invoked'))
            and activation.get('state') == 'ACTIVATED_PREVIEW_ONLY' and activation.get('source_sha256') == DIGEST
            and activation.get('bytes') == SIZE
            and all(activation.get(k) is False for k in ('installation_authorized','updater_invoked','camera_internal_firmware_modified')),
            'Pinned candidate stage/activation differs')
    from camera_install_cancel import STABLE_KEYS, HANDLE_KEYS, _identity
    volume = receipt.get('volume_identity')
    require(isinstance(volume,dict) and set(volume) == set(HANDLE_KEYS) and volume.get('body_sha256') == binding['body_sha256']
            and isinstance(volume.get('volume_uuid'),str) and bool(volume['volume_uuid'])
            and volume.get('filesystem') in ('exfat','msdos') and type(volume.get('volume_bytes')) is int and volume['volume_bytes'] > 0
            and isinstance(volume.get('mount'),str) and Path(volume['mount']).is_absolute(),
            'Complete normalized historical card identity required')
    require(isinstance(receipt.get('identity_observations'),list) and len(receipt['identity_observations']) >= 3 and all(item == volume for item in receipt['identity_observations']), 'Card identity changed during full read')
    require(all(volume[k] == _identity(stage['volume_identity'], binding['body_sha256'])[k]
                == _identity(activation['volume_identity'], binding['body_sha256'])[k] for k in STABLE_KEYS), 'Historical card identity differs')
    candidate = receipt.get('candidate')
    require(isinstance(candidate, dict) and candidate.get('bytes') == SIZE and candidate.get('sha256') == DIGEST
            and candidate.get('path') == str(Path(volume['mount']) / 'BODYDATA.DAT')
            and isinstance(candidate.get('descriptor_identity'), list) and len(candidate['descriptor_identity']) == 5,
            'Complete candidate full-read evidence required')
    from camera_sd_stage import staged_relative_path
    stage_volume = _identity(stage['volume_identity'],binding['body_sha256'])
    activation_volume = _identity(activation['volume_identity'],binding['body_sha256'])
    relative = staged_relative_path(stage['target'],stage_volume['mount'],DIGEST)
    require(activation.get('target') == str(Path(activation_volume['mount'])/'BODYDATA.DAT')
            and activation.get('backup') == str(Path(activation_volume['mount'])/relative.parent/'original-BODYDATA.DAT'),
            'Activation file locations differ from original stage')
    require(all(type(item) is int and item >= 0 for item in candidate['descriptor_identity'])
            and candidate['descriptor_identity'][2] == SIZE, 'Candidate descriptor geometry differs')
    old = stage['existing_root_update']
    backup = receipt['original_backup']
    require(backup.get('path') == str(Path(volume['mount'])/relative.parent/'original-BODYDATA.DAT'), 'Original backup location differs')
    require(activation.get('original_root_update') == old and activation.get('slot1_manually_confirmed') is True,
            'Original root/slot observation differs')
    if old['exists']:
        require(type(old.get('bytes')) is int and old['bytes'] >= 0 and isinstance(old.get('sha256'),str) and SHA.fullmatch(old['sha256'])
                and old['sha256'] != DIGEST and backup.get('bytes') == old['bytes'] and backup.get('sha256') == old['sha256']
                and isinstance(backup.get('descriptor_identity'), list) and len(backup['descriptor_identity']) == 5
                and all(type(item) is int and item >= 0 for item in backup['descriptor_identity'])
                and backup['descriptor_identity'][2] == old['bytes']
                and backup['descriptor_identity'][0] == candidate['descriptor_identity'][0]
                and backup['descriptor_identity'][1] != candidate['descriptor_identity'][1],
                'Preserved original full-read proof differs')
    else:
        require(old == {'exists': False} and backup.get('exists') is False, 'Absent original baseline differs')
    require(receipt.get('candidate_active_at_observation') is True and receipt.get('original_preserved_at_observation') is True
            and all(receipt.get(k) is False for k in ('explicit_card_writes','updater_invoked','installation_authorized',
                'ready_for_confirmation','journal_cleared','future_card_state_proven')), 'Observation-only card evidence required')
    expected = {k: v for k, v in receipt.items() if k != 'evidence_sha256'}
    require(receipt.get('evidence_sha256') == sha(canonical(expected)), 'Card observation canonical hash differs')
    return _result(reference, receipt, index)
