"""Terminate a failed first card rename without resuming or editing its flow.

prepare seals local input/source identities only. terminate requires a separate
reviewed approval, rereads the inactive card, and appends a host cancellation.
Neither command changes card contents, enters service mode, or clears UNKNOWN.
"""
import argparse
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import camera_install_flow as flow
import camera_install_cancel as inactive
import camera_sd_stage as sd
from camera_device_lease import CameraDeviceLease
from camera_install_journal import InstallJournal
from camera_install_io import JournalSnapshotPin
from camera_operation_guard import assert_operation_allowed
from camera_install_receipts import validate_completed_runtime
from camera_stream_execution import durable_new

PROPOSAL_SCHEMA = 'camera-card-no-change-proposal/1'
APPROVAL_SCHEMA = 'camera-card-no-change-approval/1'
PROOF_SCHEMA = 'camera-card-no-change-terminal-proof/1'
SCOPE = 'TERMINATE_FIRST_FAILED_CARD_ACTIVATION_ONLY'
SEQUENCE = [('runtime', 'INTENT'), ('runtime', 'COMPLETED'),
            ('stage', 'INTENT'), ('stage', 'COMPLETED'),
            ('activate', 'INTENT'), ('activate', 'UNKNOWN')]


def require(value, message):
    if not value:
        raise ValueError(message)


def reference(path):
    return flow.reference(path)


def read(reference_value):
    require(isinstance(reference_value, dict) and 'path' in reference_value,
            'Workspace artifact reference required')
    flow.local(reference_value['path'])
    return inactive._json_reference(reference_value)[2]


def _sources(config):
    paths = set(config['sources']) | {'tools/reconcile_card_activation.py',
                                     'camera_install_cancel.py', 'camera_install_io.py'}
    result = {}
    for name in sorted(paths):
        path = inactive._safe_path(ROOT / name)
        require(path.is_file(), 'Regular reviewed source required')
        result[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def _context(folder):
    folder, header, config, events, journal = flow._open(folder)
    require(header.get('injected_execution') is False
            and config.get('model_fixture_only', False) is False,
            'Production flow required; injected execution cannot be terminated here')
    require(journal.session_dir.parent == flow.DEFAULT_SESSIONS,
            'Canonical production journal required')
    require([(e['step'], e['phase']) for e in events] == SEQUENCE
            and all(e['attempt'] == 1 for e in events),
            'Only runtime, stage, and first unknown activation are eligible')
    require(journal.state == 'SD_STAGED'
            and [e['state'] for e in journal.events] == ['PLANNED', 'SD_STAGE_INTENT', 'SD_STAGED'],
            'Exact pre-RAM, pre-FLASH journal required')
    stage_ref = flow._artifact(events, 'stage')
    stage = read(stage_ref)
    require(journal.events[-1]['details'].get('stage_report') == stage_ref['path']
            and journal.events[-1]['details'].get('stage_report_sha256') == stage_ref['sha256'],
            'Journal must bind the original staged artifact')
    runtime_ref = flow._artifact(events, 'runtime')
    runtime = validate_completed_runtime(runtime_ref, binding=journal.binding,
                                         history=journal.events, session_dir=journal.session_dir)
    require(runtime.get('source_is_hardware') is True and runtime.get('receiver_compatible') is True,
            'Actual completed runtime read required')
    report = Path(stage_ref['path']).parent
    intent_ref, stopped_ref = reference(report / 'activation-intent.json'), reference(report / 'activation-stopped.json')
    intent, stopped = read(intent_ref), read(stopped_ref)
    original = stage.get('existing_root_update', {})
    require(original.get('exists') is True and original.get('sha256') != sd.DIGEST,
            'A distinct existing original BODYDATA is required')
    mount, target = Path(stage['volume_identity']['mount']), Path(stage['target'])
    sd.staged_relative_path(str(target), str(mount), sd.DIGEST)
    expected_paths = dict(source=str(target), target=str(mount / 'BODYDATA.DAT'),
                          backup=str(target.parent / 'original-BODYDATA.DAT'))
    require(intent.get('state') == 'CARD_FILENAME_ACTIVATION_INTENT'
            and all(intent.get(k) == v for k, v in expected_paths.items())
            and intent.get('existing_root_update') == original
            and all(intent.get('volume_identity', {}).get(k) == stage['volume_identity'][k]
                    for k in inactive.HANDLE_KEYS)
            and intent.get('updater_invoked') is False,
            'Exact first activation intent required')
    require(stopped.get('state') == 'ACTIVATION_STOPPED_UNKNOWN'
            and stopped.get('phase') == 'ORIGINAL_BACKUP_RENAME_MAY_HAVE_OCCURRED'
            and stopped.get('error_type') == 'OSError'
            and stopped.get('updater_invoked') is False,
            'Only first-backup-rename failure is eligible; errno is not inferred')
    for key, path in [('candidate', expected_paths['source']), ('target', expected_paths['target'])]:
        value = stopped.get(key, {})
        require(value.get('path') == path and value.get('exists') is True
                and value.get('regular') is True and value.get('symlink') is False,
                'Failure receipt must retain both file paths')
    require(stopped.get('backup') == dict(path=expected_paths['backup'], exists=False),
            'Failure receipt must record absent backup')
    pinned = [reference(folder / 'flow.json'), header['config_reference'], stage_ref, runtime_ref,
              intent_ref, stopped_ref]
    pinned += [reference(folder / 'events' / f'{i:08d}.json') for i in range(1, len(events) + 1)]
    pinned += [reference(journal.session_dir / f'{i:08d}.json') for i in range(1, len(journal.events) + 1)]
    for event in events:
        if 'receipt_reference' in event:
            pinned.append(event['receipt_reference'])
    snapshot = dict(flow_directory=str(folder), binding=journal.binding, journal_session=str(journal.session_dir),
                    journal_tail=journal.events[-1]['event_sha256'], flow_unknown=events[-1]['event_sha256'],
                    pinned_references=pinned, stage_reference=stage_ref,
                    activation_intent_reference=intent_ref, activation_stopped_reference=stopped_ref)
    return snapshot, config, journal


def prepare(flow_directory, output):
    """Seal source and local history without reading a card or approving termination."""
    snapshot, config, _ = _context(flow_directory)
    output = flow.local(output)
    require(not output.exists(), 'Fresh proposal directory required')
    sources = _sources(config)
    output.mkdir(mode=0o700, parents=True)
    for name, digest in sources.items():
        raw = (ROOT / name).read_bytes()
        require(hashlib.sha256(raw).hexdigest() == digest, 'Source changed while sealing')
        target = output / 'sources' / name
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with target.open('xb') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    for directory in sorted((p for p in (output / 'sources').rglob('*') if p.is_dir()),
                            key=lambda p: len(p.parts), reverse=True) + [output / 'sources']:
        fd = os.open(directory, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    value = dict(schema=PROPOSAL_SCHEMA, scope=SCOPE, context=snapshot, sources=sources,
                 approved=False, termination_authorized=False, installation_authorized=False,
                 card_observation_performed=False, original_UNKNOWN_preserved=True,
                 resume_old_flow_allowed=False)
    durable_new(output / 'proposal.json', value)
    return reference(output / 'proposal.json')


def _source_snapshots(proposal_reference, proposal):
    sources = Path(proposal_reference['path']).parent / 'sources'
    for name, digest in proposal['sources'].items():
        require(not Path(name).is_absolute() and '..' not in Path(name).parts,
                'Relative sealed source path required')
        path = inactive._safe_path(sources / name)
        require(path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() == digest,
                'Sealed reconciliation source snapshot differs')


def _approval(approval_reference, proposal_reference, proposal):
    approval = read(approval_reference)
    require(approval.get('schema') == APPROVAL_SCHEMA and approval.get('scope') == SCOPE
            and approval.get('proposal_reference') == proposal_reference
            and approval.get('reviewed_sources') == proposal['sources']
            and approval.get('source_review_accepted') is True
            and approval.get('termination_authorized') is True
            and approval.get('operator_never_started_confirmed') is True
            and approval.get('operator_health_confirmed') is True
            and approval.get('installation_authorized') is False,
            'Separate exact source review and operator termination approval required')
    require(isinstance(approval.get('statement'), str) and approval['statement'].strip(),
            'Actual operator statement required')
    return approval


def _check_backup(volume, relative):
    parent = inactive._safe_path(Path(volume['mount']) / relative.parent)
    with ExitStack() as stack:
        fd = os.open(parent, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0) | getattr(os, 'O_NOFOLLOW', 0))
        stack.callback(os.close, fd)
        before = os.fstat(fd)
        try:
            os.stat('original-BODYDATA.DAT', dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ValueError('Backup appeared; card no-change proof is unavailable')
        after = parent.stat()
        require(not parent.is_symlink() and (before.st_dev, before.st_ino) == (after.st_dev, after.st_ino),
                'Backup parent changed during absence check')


def _card(stage_reference, body):
    stage = read(stage_reference)
    relative = sd.staged_relative_path(stage['target'], stage['volume_identity']['mount'], sd.DIGEST)

    def discover():
        volume = sd.discover()
        _check_backup(volume, relative)
        return volume

    observation = inactive.observe_inactive_card(stage_reference, body_sha256=body, discover=discover)
    return observation, relative


def _final_card_check(observation, relative):
    current = sd.discover()
    require(all(current.get(k) == observation['volume_identity'][k] for k in inactive.HANDLE_KEYS),
            'Card identity changed before terminal append')
    _check_backup(current, relative)
    for name in ('candidate', 'root_update'):
        row = observation[name]
        path = inactive._safe_path(row['path'])
        require(list(inactive._stat_identity(path.stat())) == row['descriptor_identity'],
                'Observed file identity changed before terminal append')


def terminate(proposal_reference, approval_reference, *, termination_authorized=False):
    """Perform read-only card checks and append one cancellation; no automatic retry."""
    require(termination_authorized is True, 'Explicit terminal recording call required')
    proposal = read(proposal_reference)
    require(proposal.get('schema') == PROPOSAL_SCHEMA and proposal.get('scope') == SCOPE
            and proposal.get('approved') is False and proposal.get('termination_authorized') is False,
            'Unapproved sealed proposal required')
    _approval(approval_reference, proposal_reference, proposal)
    _source_snapshots(proposal_reference, proposal)
    flow._source_only_runtime()
    with CameraDeviceLease('card-no-change-terminal') as lease:
        identity = flow._held_lease(lease)
        snapshot, config, journal = _context(proposal['context']['flow_directory'])
        assert_operation_allowed(journal, allowed_states=('SD_STAGED',))
        require(snapshot == proposal['context'] and _sources(config) == proposal['sources'],
                'Sealed context or source changed before card observation')
        pin = JournalSnapshotPin(journal, lease)
        try:
            observation, relative = _card(snapshot['stage_reference'], journal.binding['body_sha256'])
            pin.check()
            fresh, fresh_config, reopened = _context(snapshot['flow_directory'])
            require(fresh == snapshot and _sources(fresh_config) == proposal['sources']
                    and reopened.events == journal.events, 'Context changed during card observation')
            proof_path = Path(proposal_reference['path']).parent / 'terminal-proof.json'
            proof = dict(schema=PROOF_SCHEMA, scope=SCOPE, **journal.binding,
                         proposal_reference=proposal_reference, approval_reference=approval_reference,
                         context=snapshot, source_identity=proposal['sources'], lease_identity=identity,
                         card_observation=observation, default_discover_function='camera_sd_stage.discover',
                         native_execution=False, filesystem_read_performed=True, backup_absent=True,
                         no_RAM_or_FLASH_history=True, old_flow_UNKNOWN_preserved=True,
                         card_contents_or_names_modified=False, resume_old_flow_allowed=False,
                         installation_authorized=False)
            durable_new(proof_path, proof)
            proof_ref = reference(proof_path)
            require(read(proof_ref) == proof, 'Durable terminal proof differs')
            require(read(proposal_reference) == proposal, 'Proposal changed before terminal append')
            _approval(approval_reference, proposal_reference, proposal)
            _source_snapshots(proposal_reference, proposal)
            pin.check()
            fresh, fresh_config, _ = _context(snapshot['flow_directory'])
            require(fresh == snapshot and _sources(fresh_config) == proposal['sources']
                    and flow._held_lease(lease) == identity, 'Tail/source/lease changed before append')
            _final_card_check(observation, relative)
            pin.check()
            journal.advance('CANCELLED_BEFORE_DEVICE_WRITE', details=dict(
                operation='terminate-failed-card-activation-no-change', reconciliation_proof=proof_ref,
                original_flow_UNKNOWN=snapshot['flow_unknown'], original_journal_tail=snapshot['journal_tail'],
                explicit_termination_authorized=True, no_card_writes=True, no_device_commands=True,
                original_UNKNOWN_preserved=True, resume_old_flow_allowed=False))
        finally:
            pin.close()
        terminal = InstallJournal.open(journal.session_dir)
        require(terminal.events == journal.events and terminal.state == 'CANCELLED_BEFORE_DEVICE_WRITE',
                'Terminal append result is uncertain; never retry automatically')
        current_flow_files = [reference(Path(snapshot['flow_directory']) / 'events' / f'{i:08d}.json')
                              for i in range(1, 7)]
        require(all(ref in snapshot['pinned_references'] for ref in current_flow_files),
                'Original UNKNOWN flow files changed')
        return dict(state='TERMINAL_CANCELLED_UNKNOWN_FLOW_RETAINED', journal_state=terminal.state,
                    proof_reference=proof_ref, old_flow_resumable=False, activation_completed=False,
                    card_contents_or_names_modified=False, installation_authorized=False)


def status(proposal_reference):
    """Inspect the host terminal record without discovering or reading a card."""
    proposal = read(proposal_reference)
    require(proposal.get('schema') == PROPOSAL_SCHEMA and proposal.get('scope') == SCOPE,
            'Sealed reconciliation proposal required')
    _source_snapshots(proposal_reference, proposal)
    snapshot = proposal['context']
    _, header, config, events, journal = flow._open(snapshot['flow_directory'])
    require(header.get('injected_execution') is False and _sources(config) == proposal['sources'],
            'Reconciliation source or execution mode changed')
    require([(e['step'], e['phase']) for e in events] == SEQUENCE,
            'Original UNKNOWN flow must remain unchanged')
    for ref in snapshot['pinned_references']:
        require(reference(ref['path']) == ref, 'Sealed history input changed')
    if journal.state == 'SD_STAGED':
        current, _, _ = _context(snapshot['flow_directory'])
        require(current == snapshot, 'Original pending context changed')
        return dict(state='STILL_UNKNOWN', journal_state=journal.state,
                    termination_recorded=False, old_flow_resumable=False, installation_authorized=False)
    require(journal.state == 'CANCELLED_BEFORE_DEVICE_WRITE' and len(journal.events) == 4
            and journal.events[-2]['event_sha256'] == snapshot['journal_tail'],
            'No matching card-only terminal record')
    detail = journal.events[-1]['details']
    proof_ref = detail.get('reconciliation_proof')
    proof = read(proof_ref)
    require(detail.get('operation') == 'terminate-failed-card-activation-no-change'
            and detail.get('original_flow_UNKNOWN') == snapshot['flow_unknown']
            and proof.get('schema') == PROOF_SCHEMA and proof.get('scope') == SCOPE
            and proof.get('context') == snapshot and proof.get('source_identity') == proposal['sources']
            and proof.get('proposal_reference') == proposal_reference
            and all(proof.get(k) == v for k, v in journal.binding.items()),
            'Terminal proof does not bind this failed attempt')
    _approval(proof['approval_reference'], proposal_reference, proposal)
    return dict(state='TERMINAL_CANCELLED_UNKNOWN_FLOW_RETAINED', journal_state=journal.state,
                proof_reference=proof_ref, termination_recorded=True, old_flow_resumable=False,
                activation_completed=False, installation_authorized=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    seal = commands.add_parser('prepare', help='Seal local sources and history only; no card access')
    seal.add_argument('--flow', required=True)
    seal.add_argument('--output', required=True)
    cancel = commands.add_parser('terminate', help='One explicitly reviewed, authorized terminal attempt')
    for name in ('proposal', 'approval'):
        cancel.add_argument('--' + name, required=True)
        cancel.add_argument('--' + name + '-sha256', required=True)
    cancel.add_argument('--termination-authorized', action='store_true')
    show = commands.add_parser('status', help='Read host terminal evidence only; no card access')
    show.add_argument('--proposal', required=True)
    show.add_argument('--proposal-sha256', required=True)
    args = parser.parse_args()
    flow._source_only_runtime()
    if args.command == 'prepare':
        result = prepare(args.flow, args.output)
    elif args.command == 'status':
        result = status(dict(path=args.proposal, sha256=args.proposal_sha256))
    else:
        result = terminate(dict(path=args.proposal, sha256=args.proposal_sha256),
                           dict(path=args.approval, sha256=args.approval_sha256),
                           termination_authorized=args.termination_authorized)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
