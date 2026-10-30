"""Collect a post-completion group; caller owns authentication and known STOP.

No flashing, reboot, restoration or automatic CONTENT_VERIFIED transition.
Injected transports are paired and always produce non-hardware evidence.
"""
from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import time

import camera_postinstall_verify as verifier
from camera_backup_records import record_map
from camera_capture_session import read_pdt_bounded
from camera_device_lease import DEFAULT_LOCK
from camera_firmware_capture import checked_capture_assets, capture_one_authenticated, CLAIMS as CAPTURE_CLAIMS
from camera_install_journal import InstallJournal
from camera_install_io import JournalSnapshotPin
from camera_install_patch_session import (_held_lease, _safe_path, _json, _known_stop,
    _source_only_runtime, canonical_sha256, SOURCE_ONLY_RUNTIME, review_source_paths as host_sources)
from camera_install_runtime_session import _PinnedDriver, _save_raw, _file_reference, _check_files
from camera_operation_guard import DEFAULT_SESSIONS, assert_operation_allowed
from camera_stream_execution import durable_new
from camera_toolchain import PACKAGE_SHA, PLAIN_SHA, original_plan_body

ROOT = Path(__file__).resolve().parent
ATTEMPTS = ROOT / 'output/install-post-session-attempts'
PROFILES = ('post_app', 'post_cp', 'post_p1')
PDT_BYTES = 2369436
SCOPE = 'POST_COMPLETION_CONTENT_AND_SETTINGS_CAPTURE_ONLY'
REVIEW_SCHEMA = 'camera-install-post-session-plan/1'
SHA = re.compile(r'[0-9a-f]{64}\Z')
NONCE = re.compile(r'[0-9a-f]{32}\Z')
FALSE_CLAIMS = ('installation_authorized', 'write_admission', 'READY', 'ready_for_confirmation',
    'firmware_installation_proven', 'whole_device_functional_installation_verified',
    'photo_verified', 'video_verified', 'actual_NOR_verified', 'other_MCU_verified', 'restoration_proven')


def require(value, message):
    if not value:
        raise ValueError(message)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def _reference(path):
    path = _safe_path(path)
    return dict(path=str(path), sha256=_sha(path.read_bytes()))


def _read_reference(reference):
    require(type(reference) is dict and set(reference) == {'path', 'sha256'}
            and type(reference['sha256']) is str and SHA.fullmatch(reference['sha256']), 'Exact artifact reference required')
    path = _safe_path(reference['path'])
    require(str(path) == reference['path'], 'Canonical artifact reference required')
    raw, value = _json(path)
    require(_sha(raw) == reference['sha256'], 'Referenced artifact changed')
    return raw, value


@dataclass(frozen=True)
class PostAssets:
    directory: Path
    post_app_manifest_sha256: str
    post_cp_manifest_sha256: str
    post_p1_manifest_sha256: str


@dataclass(frozen=True)
class PreparedPostAssets:
    assets: PostAssets
    reference_json: str
    manifest_json: str

    @property
    def reference(self):
        return json.loads(self.reference_json)

    @property
    def manifest(self):
        return json.loads(self.manifest_json)


def _unused(reference):
    for name in PROFILES:
        row = reference['profiles'][name]
        for namespace in ('firmware-file-capture-nonce-claims', 'install-volatile-patch-nonce-claims',
                          'install-patch-read-nonce-claims', 'install-runtime-metadata-nonce-claims'):
            root = CAPTURE_CLAIMS if namespace == 'firmware-file-capture-nonce-claims' else ROOT / 'output' / namespace
            claim = root / (row['nonce'] + '.json')
            require(not claim.exists() and not claim.is_symlink(), 'Post capture nonce already consumed: ' + name)
        for part in ('', 'prod', 'tiny', 'bootstrap'):
            folder = Path(reference['directory']) / name / part
            for marker in ('physical-attempt.json', 'host-entry-intent.json', 'module-attempt.json', 'claim.json'):
                require(not (folder / marker).exists() and not (folder / marker).is_symlink(), 'Post capture already attempted')


def preflight_assets(assets):
    """Validate fresh fixed capture jobs locally, before caller authentication."""
    require(isinstance(assets, PostAssets), 'Explicit reviewed PostAssets required')
    directory = _safe_path(assets.directory, directory=True)
    require(directory.is_relative_to(ROOT / 'output'), 'Workspace output post assets required')
    rows, sources = {}, {}
    for name in PROFILES:
        expected = getattr(assets, name + '_manifest_sha256')
        require(type(expected) is str and SHA.fullmatch(expected), 'Reviewed capture manifest SHA required')
        manifest_path = _safe_path(directory / name / 'bootstrap/bootstrap.json')
        require(_sha(manifest_path.read_bytes()) == expected, 'Post bootstrap manifest changed')
        job = checked_capture_assets(name, directory)
        production = _json(directory / name / 'prod/job.json')[1]
        for path, digest in production['sources'].items():
            require(path not in sources or sources[path] == digest, 'Post native source closures disagree')
            sources[path] = digest
        rows[name] = dict(nonce=job['nonce'].hex(), module_sha256=job['module_sha256'], manifest_sha256=expected)
        require(_sha(manifest_path.read_bytes()) == expected, 'Post manifest changed during preflight')
    require(len({r['nonce'] for r in rows.values()}) == 3, 'Post native nonces must differ')
    reference = dict(schema='camera-install-post-assets/1', directory=str(directory), profiles=rows)
    _unused(reference)
    return PreparedPostAssets(assets, _canonical(reference), _canonical(dict(sources=sources)))


def review_source_paths(prepared):
    return tuple(sorted(set(host_sources(prepared)) | {
        'camera_install_post_session.py', 'camera_install_post_plan.py', 'camera_capture_session.py',
        'camera_postinstall_verify.py', 'camera_install_requirements.py', 'camera_install_runtime_session.py',
        'ref/sony-a7m4-custom-firmware/a7m4/fat.py', 'ref/sony-a7m4-custom-firmware/a7m4/common.py'}))


def before_evidence(group, binding):
    """Revalidate the original runtime group's immutable PRE_INSTALL bytes."""
    group = _safe_path(group, directory=True)
    references = {name: _reference(group / name) for name in
                  ('group.json', 'before-reference.json', 'runtime-session-exit.json')}
    descriptor = _read_reference(references['group.json'])[1]
    before = _read_reference(references['before-reference.json'])[1]
    exit_receipt = _read_reference(references['runtime-session-exit.json'])[1]
    require(descriptor.get('schema') == 'camera-capture-group/1'
            and all(descriptor.get(k) == v for k, v in binding.items()), 'Original group binding differs')
    nonce = descriptor.get('group_nonce')
    require(type(nonce) is str and NONCE.fullmatch(nonce) and any(bytes.fromhex(nonce)), 'Original group nonce required')
    require(all(before.get(k) == v for k, v in binding.items()) and before.get('group_nonce') == nonce
            and before.get('acquisition_phase') == 'PRE_INSTALL'
            and type(before.get('source_is_hardware')) is bool
            and type(before.get('nonce')) is str and NONCE.fullmatch(before['nonce']), 'Original PRE_INSTALL PDT reference required')
    path = _safe_path(group / before['path'])
    require(path.is_relative_to(group), 'Before PDT outside original group')
    raw = path.read_bytes()
    require(len(raw) == PDT_BYTES and _sha(raw) == before['sha256'], 'Original before PDT changed')
    record_map(raw)
    require(exit_receipt.get('schema') == 'camera-install-runtime-session-receipt/1'
            and exit_receipt.get('state') == 'PRE_INSTALL_RUNTIME_KNOWN_SERVICE_EXIT'
            and all(exit_receipt.get(k) == v for k, v in binding.items())
            and exit_receipt.get('group_nonce') == nonce and exit_receipt.get('before_reference') == before
            and exit_receipt.get('source_is_hardware') is before['source_is_hardware']
            and exit_receipt.get('normal_body_verified') is True
            and exit_receipt.get('service_exit_completed') is True, 'Known original runtime exit required')
    _known_stop(exit_receipt.get('service_events'))
    terminal_ref = exit_receipt['terminal_artifact']
    require(_safe_path(terminal_ref['path']) == group / 'runtime-terminal.json', 'Original terminal outside before group')
    terminal_raw, terminal = _json(terminal_ref['path'])
    require(_sha(terminal_raw) == terminal_ref['sha256']
            and canonical_sha256(terminal) == terminal_ref['payload_sha256'], 'Original runtime terminal changed')
    expected = deepcopy(exit_receipt)
    for name in ('terminal_artifact', 'service_events', 'original_journal_unchanged'):
        expected.pop(name)
    expected.update(state='PRE_INSTALL_RUNTIME_TERMINAL_BEFORE_STOP', service_exit_completed=False)
    require(terminal == expected, 'Original runtime terminal payload differs')
    _check_files(group, exit_receipt['evidence_files'])
    references['before.bk4'] = _reference(path)
    return dict(group=str(group), descriptor=descriptor, before=before, references=references,
                source_is_hardware=before['source_is_hardware'])


def _completion(reference, binding, journal, injected):
    raw, report = _read_reference(reference)
    require(journal.events[-1]['details'].get('device_completion_artifact') == reference,
            'Journal must reference the exact completion proof')
    if not (injected and report.get('model_fixture_only') is True):
        from camera_install_completion import validate_completion_receipt
        return validate_completion_receipt(reference, binding, journal.events[:-1], journal.session_dir)
    require(report.get('model_fixture_only') is True and report.get('schema') == 'camera-install-device-completion/1'
            and all(report.get(k) == v for k, v in binding.items())
            and report.get('state') == 'DEVICE_COMPLETION_REPORTED'
            and report.get('session_id') == journal.session_dir.name
            and report.get('reported_complete') is True and report.get('updater_stopped_confirmed') is True
            and report.get('normal_service_reentry_authorized') is True,
            'Explicit model-only completion fixture required for injected transport')
    return report


def validate_review(path, digest, prepared, binding, group, completion_reference):
    raw, review = _json(path)
    require(_sha(raw) == digest and review.get('schema') == REVIEW_SCHEMA and review.get('scope') == SCOPE
            and all(review.get(k) == v for k, v in binding.items())
            and review.get('asset_reference') == prepared.reference and review.get('before_evidence') == before_evidence(group, binding)
            and review.get('completion_reference') == completion_reference
            and review.get('source_only_runtime') == SOURCE_ONLY_RUNTIME
            and review.get('package_reference') == _reference(verifier.PLAIN)
            and review.get('factory_reference') == _reference(verifier.FACTORY_P1)
            and all(review.get(k) is False for k in FALSE_CLAIMS), 'Complete reviewed post scope differs')
    original = _read_reference(review['original_plan_reference'])[1]
    require(review['original_plan_reference']['sha256'] == binding['plan_sha256']
            and original_plan_body(original) == binding['body_sha256'],
            'Original fixed-package plan differs')
    require(_sha(_safe_path(verifier.PLAIN).read_bytes()) == verifier.PLAIN_SHA
            and _sha(_safe_path(verifier.FACTORY_P1).read_bytes()) == verifier.FACTORY_SHA, 'Pinned package/factory changed')
    seen = {review['before_evidence']['descriptor']['group_nonce'], review['before_evidence']['before']['nonce']}
    after_nonce = review.get('after_nonce')
    require(type(after_nonce) is str and NONCE.fullmatch(after_nonce) and any(bytes.fromhex(after_nonce))
            and after_nonce not in seen, 'Fresh after PDT nonce required')
    seen.add(after_nonce)
    for item in prepared.reference['profiles'].values():
        require(item['nonce'] not in seen, 'Before/after/native nonce reuse')
        seen.add(item['nonce'])
    sources = review.get('sources')
    require(type(sources) is dict and set(review_source_paths(prepared)).issubset(sources)
            and all(sources.get(k) == v for k, v in prepared.manifest['sources'].items()), 'Complete post source closure required')
    snapshots = Path(path).absolute().parent / 'sources'
    require(review.get('source_snapshot_directory') == str(snapshots), 'Post source snapshot directory differs')
    for name, value in sources.items():
        require(not Path(name).is_absolute() and '..' not in Path(name).parts
                and type(value) is str and SHA.fullmatch(value), 'Invalid post source reference')
        require(_sha(_safe_path(ROOT / name).read_bytes()) == value
                and _sha(_safe_path(snapshots / name).read_bytes()) == value, 'Post source or snapshot changed')
    return review, dict(path=str(Path(path).absolute()), sha256=digest, payload_sha256=canonical_sha256(review))


def run_post_session(expected_body_sha256, group, *, plan_sha256, review_path, review_sha256,
        completion_reference, journal, lease, assets, post_capture_authorized=False,
        run_session=None, capture_fn=None, pdt_reader=None, preflight_fn=None,
        clock=time.monotonic, sleep=time.sleep):
    """Collect after verified completion, then publish known-exit and content results.

    No CONTENT_VERIFIED transition is performed. Only a separate controller can
    record acceptance. Unknown I/O never triggers STOP, retry, reset or reboot.
    """
    folder = Path(group).absolute();attempted = False;installed = None;packet_pin = None;stage = 'LOCAL_PREFLIGHT'
    try:
        require(post_capture_authorized is True, 'Explicit post-completion capture consent required')
        callbacks = (run_session, capture_fn, pdt_reader)
        injected = any(x is not None for x in callbacks)
        require(not injected or all(callable(x) for x in callbacks), 'All post transport callbacks must be injected together')
        require(preflight_fn is None or (injected and callable(preflight_fn)), 'Preflight injection requires paired model transport')
        identity = _held_lease(lease)
        require(isinstance(journal, InstallJournal), 'Completion-bound InstallJournal required')
        binding = dict(body_sha256=expected_body_sha256, plan_sha256=plan_sha256, model='ILCE-7M4')
        history = journal.events
        def pin():
            require(_held_lease(lease) == identity, 'Post lease changed')
            if packet_pin is not None:
                packet_pin.check()
                return
            current = InstallJournal.open(journal.session_dir)
            require(current.events == history == journal.events and current.state == 'DEVICE_COMPLETION_REPORTED'
                    and current.binding == binding, 'Fresh same-body completion history required')
            assert_operation_allowed(journal, allowed_states=('DEVICE_COMPLETION_REPORTED',))
            if journal.session_dir.parent.resolve() != DEFAULT_SESSIONS.resolve():
                assert_operation_allowed(sessions_root=DEFAULT_SESSIONS)
        pin()
        if not injected:
            require(Path(lease.path).absolute() == DEFAULT_LOCK.absolute()
                    and journal.session_dir.parent.absolute() == DEFAULT_SESSIONS.absolute(), 'Canonical post context required')
            _safe_path(lease.path);_safe_path(journal.session_dir, directory=True);_source_only_runtime()
        before = before_evidence(folder, binding)
        require(before['descriptor']['journal_session'] == str(journal.session_dir.absolute())
                and before['source_is_hardware'] is (not injected), 'Original before group/source differs')
        completion = _completion(completion_reference, binding, journal, injected)
        require(completion.get('runtime_reference') == before['references']['runtime-session-exit.json'],
                'Completion does not bind original runtime group')
        preflight = preflight_fn or preflight_assets
        prepared = preflight(assets)
        review, review_ref = validate_review(review_path, review_sha256, prepared, binding, folder, completion_reference)
        forbidden_outputs = ('post-terminal.json', 'post-session-exit.json', 'capture-run.json', 'verification.json', 'post-attempt.json', 'after.bk4')
        require(not any((folder / n).exists() or (folder / n).is_symlink() for n in (*PROFILES, *forbidden_outputs)), 'Post group already attempted')
        def guard():
            pin();_completion(completion_reference, binding, journal, injected)
            require(validate_review(review_path, review_sha256, prepared, binding, folder, completion_reference)[1] == review_ref,
                    'Post review changed during collection')
            if not injected:_source_only_runtime()
        guard();_unused(prepared.reference)
        require(preflight(assets) == prepared, 'Post assets changed before entry')
        attempt = ATTEMPTS / (review_sha256 + '.json')
        _safe_path(ATTEMPTS.parent, directory=True)
        require(all(not p.is_symlink() for p in (ATTEMPTS, *ATTEMPTS.parents)) and not attempt.exists(), 'Post review already attempted')
        ATTEMPTS.mkdir(mode=0o700, parents=True, exist_ok=True)
        durable_new(attempt, dict(scope=SCOPE, review=review_ref, completion_reference=completion_reference,
                                 before_evidence=before, lease_identity=identity, automatic_retry=False))
        durable_new(folder / 'post-attempt.json', dict(scope=SCOPE, review=review_ref, automatic_retry=False))
        if not injected:
            from camera_stream_usb_session import run_normal_session
            run_session, capture_fn, pdt_reader = run_normal_session, capture_one_authenticated, read_pdt_bounded
            packet_pin = JournalSnapshotPin(journal, lease)
        events=[];calls=0;accepted=None;terminal_reference=None
        def work(device):
            nonlocal calls, installed, accepted, terminal_reference
            calls += 1
            require(calls == 1 and any(e.get('model') == 'ILCE-7M4' and e.get('body_matched') is True for e in events), 'One fresh same-body callback required')
            guard()
            if hasattr(device, 'driver'):
                original = device.driver;device.driver = _PinnedDriver(original, pin);installed=(device, original)
            else:require(injected, 'Actual post service driver required')
            references={};files=[];seen={before['descriptor']['group_nonce'],before['before']['nonce'],review['after_nonce']}
            for name in PROFILES:
                guard()
                report=capture_fn(device,name,folder/name,source_is_hardware=not injected,
                                  assets=assets.directory,clock=clock,sleep=sleep)
                guard();path=folder/name/'firmware-capture.json';raw,saved=_json(path)
                require(saved==report and report.get('nonce')==prepared.reference['profiles'][name]['nonce']
                        and report.get('module_sha256')==prepared.reference['profiles'][name]['module_sha256'], 'Post capture callback or job differs')
                _,proof=verifier._capture(folder,name,str(path.relative_to(folder)),_sha(raw),binding,
                    before['descriptor']['group_nonce'],not injected,seen,set())
                for p in (path,Path(report['capture']),path.parent/'launch-and-ready.json',path.parent/'completed.json',path.parent/'capture/status.json'):
                    files.append(_file_reference(folder,p))
                references[name]=dict(binding,path=str(path.relative_to(folder)),sha256=_sha(raw),group_nonce=before['descriptor']['group_nonce'])
            guard();raw=pdt_reader(device,clock=clock)
            require(type(raw) is bytes and len(raw)==PDT_BYTES,'Complete after PDT required');record_map(raw)
            pdt_file=_save_raw(folder/'after.bk4',raw)
            after=dict(binding,path=pdt_file['path'],sha256=pdt_file['sha256'],group_nonce=before['descriptor']['group_nonce'],
                       nonce=review['after_nonce'],source_is_hardware=not injected,acquisition_phase='POST_INSTALL')
            durable_new(folder/'after-reference.json',after)
            files.extend(_file_reference(folder,folder/n)for n in ('after.bk4','after-reference.json'))
            capture_run=dict(binding,schema='camera-postinstall-capture-run/1',group_nonce=before['descriptor']['group_nonce'],
                normal_body_verified=True,source_is_hardware=not injected,captures=references,
                critical_settings=dict(before=before['before'],after=after),known_service_STOP=False,
                photo_verified=False,video_verified=False,actual_NOR_verified=False)
            accepted=dict(schema='camera-install-post-session-receipt/1',state='POST_TERMINAL_DURABLE_BEFORE_STOP',scope=SCOPE,
                **binding,review=review_ref,completion_reference=completion_reference,lease_identity=identity,
                capture_run=capture_run,evidence_files=files,source_is_hardware=not injected,service_exit_completed=False,
                **dict.fromkeys(FALSE_CLAIMS,False))
            _check_files(folder,files);guard();path=folder/'post-terminal.json';durable_new(path,accepted)
            raw,saved=_json(path);require(saved==accepted,'Post terminal host readback differs')
            terminal_reference=dict(path=str(path),sha256=_sha(raw),payload_sha256=canonical_sha256(accepted))
            guard();_check_files(folder,files)
            return deepcopy(accepted)
        stage='POST_SERVICE_ENTRY_MAY_HAVE_STARTED';attempted=True
        returned=run_session(expected_body_sha256,work,record_event=events.append,set_stage=lambda value:None)
        pin();require(calls==1 and returned==accepted and terminal_reference is not None,'Original post callback result required');_known_stop(events)
        raw,terminal=_json(terminal_reference['path'])
        require(_sha(raw)==terminal_reference['sha256'] and canonical_sha256(terminal)==terminal_reference['payload_sha256'],'Post terminal changed after STOP')
        _check_files(folder,terminal['evidence_files']);guard()
        exit_receipt=terminal|dict(state='POST_KNOWN_SERVICE_EXIT',terminal_artifact=terminal_reference,service_events=deepcopy(events),service_exit_completed=True)
        durable_new(folder/'post-session-exit.json',exit_receipt)
        capture_run=deepcopy(terminal['capture_run']);capture_run['known_service_STOP']=True
        durable_new(folder/'capture-run.json',capture_run)
        result=verifier.verify_capture_run(folder/'capture-run.json',**binding,group_nonce=before['descriptor']['group_nonce'],source_is_hardware=not injected,
            plain_path=verifier.PLAIN,factory_p1_path=verifier.FACTORY_P1)
        durable_new(folder/'verification.json',result);guard()
        return dict(state='POST_CONTENT_VERIFICATION_RECORDED_ONLY',verification=result,
                    verification_artifact=_reference(folder/'verification.json'),session_exit_artifact=_reference(folder/'post-session-exit.json'),
                    journal_unchanged=True,CONTENT_VERIFIED_recorded=False,source_is_hardware=not injected,
                    content_checks_passed=result['all_passed'] is True,**dict.fromkeys(FALSE_CLAIMS,False))
    except BaseException as error:
        if attempted and isinstance(journal,InstallJournal):
            try:journal.advance('STOPPED_UNKNOWN',details=dict(operation='post-capture',stage=stage,error_type=type(error).__name__,automatic_retry=False))
            except BaseException:pass
        try:
            if folder.is_dir() and all(not p.is_symlink()for p in (folder,*folder.parents)):
                durable_new(folder/'post-session-unknown.json',dict(stage=stage,error_type=type(error).__name__,authentication_may_have_started=attempted,automatic_STOP=False,automatic_retry=False,automatic_reboot=False))
        except BaseException:pass
        raise
    finally:
        if installed is not None:installed[0].driver=installed[1]
        if packet_pin is not None:packet_pin.close()
