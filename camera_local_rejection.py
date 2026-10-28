"""Validate local rejection before the pinned historical menu entry point.

This records execution evidence, never hardware verification or permission to
resume. Original evidence must remain available for future ledger scans.
"""
import json
from pathlib import Path
import re
import stat

from camera_install_journal import JournalError, _no_duplicates, _read_json, _require, _sha

SOURCE_SHAS = {
    'camera_workflow.py': 'e070dcb8c88147363610d374f478b3a1446bf583a5aead3643f20b0517410c5f',
    'camera_menu_session.py': 'c1fa487eaa34a222bcf5774862519a115007cac2d41d110b575f774e2dd6d46e',
}


def _path(value, *, within=None):
    _require(isinstance(value, str), 'Local evidence path must be a string')
    path = Path(value)
    _require(path.is_absolute() and '..' not in path.parts, 'Absolute evidence path required')
    if within is not None:
        _require(path.is_relative_to(within), 'Evidence outside its historical scope')
    for item in (path, *path.parents):
        _require(not item.is_symlink(), 'Symlink in local rejection evidence path')
    return path


def _raw_reference(reference, *, expected=None, within=None):
    _require(isinstance(reference, dict) and set(reference) == {'path', 'sha256'},
             'Hashed local evidence reference required')
    path = _path(reference['path'], within=within)
    _require(expected is None or path == expected, 'Different historical evidence path')
    _require(stat.S_ISREG(path.stat().st_mode), 'Regular local evidence file required')
    raw = path.read_bytes()
    _require(_sha(raw) == reference['sha256'], 'Local rejection evidence changed')
    return path, raw


def _reference(reference, *, expected=None, within=None):
    path, raw = _raw_reference(reference, expected=expected, within=within)
    value = json.loads(raw, object_pairs_hook=_no_duplicates)
    _require(isinstance(value, dict), 'Local rejection evidence must be an object')
    return path, value


def _trace(execution, raw_records, root, session_id):
    records = execution.get('records')
    lines = raw_records.splitlines(keepends=True)
    _require(isinstance(records, list) and len(records) == len(lines) == 2,
             'Original call and output records required')
    previous_number = 0
    for record, raw in zip(records, lines):
        original = json.loads(raw)
        number = record.get('line_number')
        _require(type(number) is int and number > previous_number and
                 record.get('original_line_sha256') == _sha(raw), 'Wrong original transcript line binding')
        previous_number = number
        _require(record.get('timestamp') == original.get('timestamp') and
                 record.get('type') == original.get('type') == 'response_item', 'Wrong original tool record')
        payload = record.get('payload')
        _require(isinstance(payload, dict) and all(
            original['payload'].get(key) == value for key, value in payload.items()),
            'Captured tool record differs from retained original record')
    call, result = (record['payload'] for record in records)
    command = ('sudo -n ./camera-workflow device window --workflow output/camera-workflows/' + session_id +
               ' --authorize-step --camera-ready --firmware-never-started')
    expected_input = ('text(await tools.exec_command({cmd:' + json.dumps(command) +
                      ',"max_output_tokens":1500,"yield_time_ms":1000}));\n')
    call_id = call.get('call_id')
    _require(call.get('type') == 'custom_tool_call' and call.get('name') == 'exec' and
             isinstance(call_id, str) and bool(call_id) and result.get('call_id') == call_id and
             call.get('input') == expected_input and result.get('type') == 'custom_tool_call_output',
             'Different historical workflow tool call')
    output = result.get('output')
    _require(isinstance(output, list) and len(output) == 2, 'Complete original tool output required')
    receipt = json.loads(output[1]['text'])
    _require(type(receipt.get('exit_code')) is int and receipt['exit_code'] == 1,
             'Original local failure exit required')
    trace = receipt.get('output', '')
    filename = str(root / 'camera_workflow.py')
    expected_tail = (
        f'  File "{filename}", line 307, in device_action\n'
        '    check_current_staged_card(staged)\n'
        f'  File "{filename}", line 225, in check_current_staged_card\n'
        '    require(all(current.get(k)==previous.get(k) for k in\n'
        f'  File "{filename}", line 26, in require\n'
        '    raise ValueError(message)\n'
        'ValueError: Current camera/card differs from staged evidence\n')
    _require(trace.startswith('Traceback (most recent call last):\n') and trace.endswith(expected_tail),
             'Different local error site')


def _unclaimed_prepared_jobs(root):
    claims = [root / 'output/menu-stock-window-offline-01/physical-attempt.json']
    assets = root / 'output/firmware-file-capture-offline-03'
    for name in ('post_p1', 'post_cp', 'pre_ufp', 'pre_app', 'post_app'):
        path = _path(str(assets / name / 'prod/job.json'), within=assets)
        _, job = _read_json(path)
        nonce = job.get('nonce')
        _require(isinstance(nonce, str) and re.fullmatch('[0-9a-f]{32}', nonce), 'Prepared worker nonce missing')
        claims.append(root / 'output/firmware-file-capture-nonce-claims' / (nonce + '.json'))
    for path in claims:
        _path(str(path))
        _require(not path.exists(), 'Prepared worker claim exists')


def validate_local_rejection(reference, binding, history, session_dir, *, check_current_claims):
    """Read proof and original inputs on append and every ledger replay."""
    try:
        _validate(reference, binding, history, Path(session_dir), check_current_claims)
    except (OSError, TypeError, KeyError, IndexError, UnicodeError, ValueError) as error:
        if isinstance(error, JournalError):
            raise
        raise JournalError('Unreadable local rejection evidence') from error


def _validate(reference, binding, history, session_dir, check_current_claims):
    _require([event['state'] for event in history] ==
             ['PLANNED', 'SD_STAGE_INTENT', 'SD_STAGED', 'STOPPED_UNKNOWN'],
             'Local rejection requires exactly the historical pre-device phases')
    stopped = history[-1]
    _require(stopped['details'] == dict(operation='window', error_type='ValueError',
             automatic_retry=False, automatic_STOP=False, automatic_reboot=False),
             'Different stopped operation')
    _path(str(session_dir))
    _require(session_dir.parent.name == 'full-install-sessions' and session_dir.parent.parent.name == 'output',
             'Historical session must be in the dedicated sessions root')
    root = session_dir.parents[2]
    session_id = session_dir.name
    _, proof = _reference(reference, within=root / 'output')
    _require(set(proof) == {'schema', 'binding', 'session_id', 'stopped_event_sha256',
                          'workflow_directory', 'plan_artifact', 'workflow_artifact',
                          'window_intent_artifact', 'tool_execution_artifact', 'original_records_artifact'},
             'Invalid local rejection proof fields')
    _require(proof['schema'] == 'camera-local-rejection-before-device-entry/1' and
             proof['binding'] == binding and proof['session_id'] == session_id == stopped['session_id'] and
             proof['stopped_event_sha256'] == stopped['event_sha256'], 'Local rejection binding mismatch')
    folder = root / 'output/camera-workflows' / session_id
    _require(_path(proof['workflow_directory']) == folder and folder.is_dir(),
             'Different original workflow directory')
    plan_path, plan = _reference(proof['plan_artifact'], within=root / 'output/offline-toolchain')
    _require(proof['plan_artifact']['sha256'] == binding['plan_sha256'], 'Different original plan bytes')
    _require(plan.get('reference_body_sha256') == binding['body_sha256'] and
             plan.get('model') == binding['model'], 'Original plan body/model mismatch')
    snapshots = plan_path.with_suffix('.sources')
    _require(_path(plan['source_snapshot_directory']) == snapshots, 'Different source snapshot directory')
    _require(all(plan['sources'].get(name) == digest for name, digest in SOURCE_SHAS.items()),
             'Unsupported historical source version')
    for name, digest in plan['sources'].items():
        path = _path(str(snapshots / name), within=snapshots)
        _require(stat.S_ISREG(path.stat().st_mode) and _sha(path.read_bytes()) == digest,
                 'Original source snapshot changed')
    lines = (snapshots / 'camera_workflow.py').read_text().splitlines()
    _require(lines[306].strip() == 'check_current_staged_card(staged)' and
             lines[308].strip() == "evidence=folder/'menu';evidence.mkdir(mode=0o700)" and
             lines[309].strip().startswith('result=run_menu_session('), 'Different historical device entry order')
    _, workflow = _reference(proof['workflow_artifact'], expected=folder / 'workflow.json')
    _require(workflow.get('schema') == 'camera-guided-rehearsal/1' and
             workflow.get('plan') == str(plan_path) and workflow.get('journal') == str(session_dir) and
             all(workflow.get(key) == value for key, value in binding.items()), 'Original workflow binding mismatch')
    _, intent = _reference(proof['window_intent_artifact'], expected=folder / 'window-intent.json')
    _require(set(intent) == {'action', 'plan_sha256', 'firmware_never_started_operator_confirmed', 'automatic_retry'} and
             intent['action'] == 'window' and intent['plan_sha256'] == binding['plan_sha256'] and
             intent['firmware_never_started_operator_confirmed'] is True and intent['automatic_retry'] is False,
             'Different original window intent')
    _, execution = _reference(proof['tool_execution_artifact'], within=root / 'output')
    _, raw_records = _raw_reference(proof['original_records_artifact'], within=root / 'output')
    _trace(execution, raw_records, root, session_id)
    for name in ('menu', 'window-result.json', 'restoration', 'restore-intent.json', 'restore-result.json'):
        path = _path(str(folder / name))
        _require(not path.exists(), 'Device entry artifact exists')
    if check_current_claims:
        _unclaimed_prepared_jobs(root)
