"""Fail-closed, host-only audit ledger for non-atomic full SDK installs.

This module performs no device actions. Persist MAY states *before* the related
RAM/flash action; if persistence fails, do not perform that action. A successful
append is an audit boundary, never an atomic device rollback guarantee. Neither
hash chains nor an artifact's source_is_hardware declaration prove provenance.
No PID, lock lifetime, elapsed time, or device completion clears an uncertainty.
Manual reconciliation accepts explicit operator approval and referenced hardware
reports; it performs no recovery and cannot eliminate partial-write risk. Its
terminal state permits a fresh inspection, not automatic resume or a claim that
the target firmware was installed successfully.
The sessions root is a dedicated local directory; every child is a session.
"""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import re
import stat


class JournalError(ValueError):
    """Invalid, stale, damaged, or unresolved install ledger."""


STATES = frozenset({
    'PLANNED', 'SD_STAGE_INTENT', 'SD_STAGED', 'RAM_MAY_BE_ACTIVE', 'RAM_AWAITING_OPERATOR_RECONNECT',
    'READY_FOR_CONFIRMATION', 'FLASH_MAY_HAVE_STARTED',
    'DEVICE_COMPLETION_REPORTED', 'CONTENT_VERIFIED', 'STOPPED_UNKNOWN',
    'CANCELLED_BEFORE_DEVICE_WRITE', 'MANUALLY_RECONCILED_SAFE', 'RAM_RESTORATION_VERIFIED',
    'LOCAL_REJECTED_BEFORE_DEVICE_ENTRY',
    'INSTALL_PATCH_MAY_BE_ACTIVE', 'INSTALL_PATCH_AWAITING_OPERATOR_RECONNECT',
    'INSTALL_READY_FOR_OPERATOR_START', 'INSTALL_PREPARATION_CANCELLED',
})
TERMINAL_SAFE = frozenset({'CONTENT_VERIFIED', 'CANCELLED_BEFORE_DEVICE_WRITE',
                           'MANUALLY_RECONCILED_SAFE', 'RAM_RESTORATION_VERIFIED',
                           'LOCAL_REJECTED_BEFORE_DEVICE_ENTRY', 'INSTALL_PREPARATION_CANCELLED'})
NEXT = {
    'PLANNED': {'SD_STAGE_INTENT'},
    'SD_STAGE_INTENT': {'SD_STAGED'},
    'SD_STAGED': {'RAM_MAY_BE_ACTIVE', 'READY_FOR_CONFIRMATION', 'INSTALL_PATCH_MAY_BE_ACTIVE'},
    'INSTALL_PATCH_MAY_BE_ACTIVE': {'INSTALL_PATCH_AWAITING_OPERATOR_RECONNECT'},
    'INSTALL_PATCH_AWAITING_OPERATOR_RECONNECT': {'INSTALL_READY_FOR_OPERATOR_START', 'INSTALL_PREPARATION_CANCELLED'},
    'INSTALL_READY_FOR_OPERATOR_START': {'FLASH_MAY_HAVE_STARTED'},
    'RAM_MAY_BE_ACTIVE': {'READY_FOR_CONFIRMATION', 'RAM_AWAITING_OPERATOR_RECONNECT'},
    'READY_FOR_CONFIRMATION': set(),
    'FLASH_MAY_HAVE_STARTED': {'DEVICE_COMPLETION_REPORTED'},
    'DEVICE_COMPLETION_REPORTED': {'CONTENT_VERIFIED'},
}
SHA = re.compile(r'[0-9a-f]{64}\Z')
NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z')
ZERO_SHA = '0' * 64


def _require(ok, message):
    if not ok:
        raise JournalError(message)


def _canonical(value):
    try:
        return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                           ensure_ascii=True, allow_nan=False) + '\n').encode('ascii')
    except (ValueError, TypeError) as exc:
        raise JournalError('Data must be finite JSON') from exc


def _sha(value):
    return hashlib.sha256(value).hexdigest()


def _no_duplicates(pairs):
    value = {}
    for key, item in pairs:
        _require(key not in value, 'Duplicate JSON field')
        value[key] = item
    return value


def _read_json(path):
    _require(not path.is_symlink() and stat.S_ISREG(path.stat().st_mode),
             'Expected a regular local file: ' + str(path))
    raw = path.read_bytes()
    try:
        value = json.loads(raw, object_pairs_hook=_no_duplicates)
    except (ValueError, UnicodeError) as exc:
        raise JournalError('Damaged JSON: ' + str(path)) from exc
    return raw, value


def _directory(path):
    _require(not path.is_symlink() and path.is_dir(), 'Unsafe session directory: ' + str(path))


def _fsync_dir(path):
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _binding(binding):
    _require(isinstance(binding, dict) and set(binding) == {'plan_sha256', 'body_sha256', 'model'},
             'Invalid plan/body/model binding')
    for key in ('plan_sha256', 'body_sha256'):
        _require(isinstance(binding[key], str) and SHA.fullmatch(binding[key]), 'Invalid ' + key)
    _require(isinstance(binding['model'], str) and bool(binding['model'].strip()), 'Invalid model')


def _transition(history, state):
    if not history:
        _require(state == 'PLANNED', 'First event must be PLANNED')
        return
    previous = history[-1]['state']
    if state == 'LOCAL_REJECTED_BEFORE_DEVICE_ENTRY':
        _require(previous == 'STOPPED_UNKNOWN', 'Local rejection requires STOPPED_UNKNOWN')
        return
    if state == 'RAM_RESTORATION_VERIFIED':
        _require(not any(e['state'] == 'FLASH_MAY_HAVE_STARTED' for e in history),
                 'RAM restoration cannot clear possible flash writes')
        _require(previous in {'RAM_MAY_BE_ACTIVE', 'READY_FOR_CONFIRMATION', 'RAM_AWAITING_OPERATOR_RECONNECT'},
                 'RAM restoration requires an active RAM-only phase')
        return
    if state == 'MANUALLY_RECONCILED_SAFE':
        _require(previous == 'STOPPED_UNKNOWN', 'Manual reconciliation requires STOPPED_UNKNOWN')
        return
    _require(previous not in TERMINAL_SAFE and previous != 'STOPPED_UNKNOWN', 'Session is closed')
    if state == 'STOPPED_UNKNOWN':
        return
    if state == 'CANCELLED_BEFORE_DEVICE_WRITE':
        _require(not any(e['state'] in {'RAM_MAY_BE_ACTIVE', 'FLASH_MAY_HAVE_STARTED',
                                       'INSTALL_PATCH_MAY_BE_ACTIVE',
                                       'INSTALL_PATCH_AWAITING_OPERATOR_RECONNECT'} for e in history),
                 'Cannot cancel after a possible device write')
        return
    _require(state in NEXT.get(previous, set()), 'Invalid phase transition: ' + previous + ' -> ' + str(state))


def _verification(reference, binding):
    _require(isinstance(reference, dict) and set(reference) == {'path', 'sha256'},
             'CONTENT_VERIFIED requires a verification artifact reference')
    _require(isinstance(reference['path'], str) and Path(reference['path']).is_absolute(),
             'Verification artifact path must be absolute')
    _require(isinstance(reference['sha256'], str) and SHA.fullmatch(reference['sha256']),
             'Invalid verification artifact SHA')
    raw, report = _read_json(Path(reference['path']))
    _require(_sha(raw) == reference['sha256'], 'Verification artifact changed')
    _require(isinstance(report, dict), 'Verification artifact must be an object')
    _require(report.get('source_is_hardware') is True, 'Verification source must declare hardware')
    _require(report.get('all_passed') is True, 'Verification checks did not all pass')
    _require(all(report.get(key) == value for key, value in binding.items()),
             'Verification artifact plan/body/model mismatch')
    return report


def _ram_restoration(reference, binding, history):
    _transition(history, 'RAM_RESTORATION_VERIFIED')
    report = _verification(reference, binding)
    _require(report.get('scope') == 'VOLATILE_RAM_WINDOW_ONLY',
             'RAM restoration scope must be VOLATILE_RAM_WINDOW_ONLY')
    _require(report.get('both_RAM_targets_proven_safe') is True,
             'Both volatile RAM targets must be proven safe')
    _require(report.get('firmware_flash_was_never_started') is True,
             'RAM restoration requires proof flash was never started')
    return report


def _install_patch_pending(reference, binding, history):
    from camera_install_patch_session import validate_pending_receipt
    try:
        return validate_pending_receipt(reference, binding, history)
    except (ValueError, OSError, TypeError, KeyError) as error:
        raise JournalError('Invalid install-patch pending receipt') from error


def _install_patch_details(details, binding, history):
    from camera_install_patch_session import canonical_sha256
    report = _install_patch_pending(details.get('install_patch_artifact'), binding, history)
    _require(details.get('complete_receipt_sha256') == canonical_sha256(report),
             'Complete install-patch receipt payload changed')
    return report


FORMAL_ARTIFACTS = {
    'INSTALL_READY_FOR_OPERATOR_START': 'admission_artifact',
    'FLASH_MAY_HAVE_STARTED': 'start_intent_artifact',
    'DEVICE_COMPLETION_REPORTED': 'device_completion_artifact',
    'INSTALL_PREPARATION_CANCELLED': 'cancellation_artifact',
}


def _formal_details(state, details, binding, history, session_dir):
    if state not in FORMAL_ARTIFACTS:
        return
    try:
        return _validate_formal_details(state, details, binding, history, session_dir)
    except JournalError:
        raise
    except (ValueError, OSError, KeyError, TypeError) as error:
        raise JournalError('Invalid formal installation evidence: ' + str(error)) from error


def _validate_formal_details(state, details, binding, history, session_dir):
    from camera_install_receipts import load_reference, canonical, sha
    reference = details.get(FORMAL_ARTIFACTS[state])
    _, report = load_reference(reference)
    _require(details.get('complete_receipt_sha256') == sha(canonical(report)),
             'Complete formal receipt payload changed')
    if state == 'INSTALL_READY_FOR_OPERATOR_START':
        from camera_install_admission import validate_admission_receipt
        validate_admission_receipt(reference, binding, history, session_dir)
    elif state == 'FLASH_MAY_HAVE_STARTED':
        from camera_install_admission import validate_start_intent
        validate_start_intent(reference, binding, history, session_dir)
    elif state == 'DEVICE_COMPLETION_REPORTED':
        from camera_install_completion import validate_completion_receipt
        validate_completion_receipt(reference, binding, history, session_dir)
    else:
        _require(details.get('explicit_user_approval') is True, 'Explicit preparation cancellation approval required')
        from camera_install_cancel_session import validate_cancellation_receipt
        validate_cancellation_receipt(reference, binding, history, session_dir)


def _manual_reconciliation(reference, binding, history):
    report = _verification(reference, binding)
    _require(bool(history) and history[-1]['state'] == 'STOPPED_UNKNOWN',
             'Manual reconciliation requires STOPPED_UNKNOWN')
    stopped = history[-1]
    _require(report.get('session_id') == stopped['session_id'] and
             report.get('stopped_event_sha256') == stopped['event_sha256'],
             'Reconciliation must bind this session and stopped event')
    _require(report.get('prior_on_device_writer_stopped') is True,
             'Prior on-device writer must be verified stopped')
    note = report.get('operator_review_note')
    _require(isinstance(note, str) and bool(note.strip()), 'Operator review note is required')
    scope = report.get('scope')
    _require(scope in ('ram-only', 'full-install'), 'Invalid reconciliation scope')
    if scope == 'ram-only':
        _require(not any(e['state'] == 'FLASH_MAY_HAVE_STARTED' for e in history),
                 'RAM-only scope cannot reconcile possible flash writes')
        _require(report.get('firmware_flash_was_never_started') is True and
                 report.get('RAM_original_state_verified') is True,
                 'RAM-only reconciliation requires verified original RAM and no flash writes')
    else:
        # Both reports are separately frozen and bound to this stopped event.
        # Freshness/source remain producer assertions, not facts proven by the ledger.
        for field, assertion in (('fresh_readback_artifact', 'fresh_readback'),
                                 ('writer_stopped_artifact', 'on_device_writer_stopped')):
            evidence = _verification(report.get(field), binding)
            _require(evidence.get(assertion) is True, 'Missing hardware assertion: ' + assertion)
            _require(evidence.get('session_id') == stopped['session_id'] and
                     evidence.get('stopped_event_sha256') == stopped['event_sha256'],
                     'Reconciliation evidence must bind this stopped event')
    return report


class InstallJournal:
    """A snapshot of a session. Concurrent/stale snapshots cannot overwrite events.

    Use a new, unique session_id for each attempt. ``advance`` persists an intent
    before its associated action. Never execute an action if append raises,
    including fsync failure. Do not automatically resume a reopened journal.
    """

    def __init__(self, session_dir, events):
        self.session_dir = Path(session_dir)
        self._events = events

    @property
    def events(self):
        return deepcopy(self._events)

    @property
    def state(self):
        return self._events[-1]['state']

    @property
    def binding(self):
        return deepcopy(self._events[0]['binding'])

    @classmethod
    def create(cls, root, session_id, *, plan_sha256, body_sha256, model):
        _require(isinstance(session_id, str) and NAME.fullmatch(session_id)
                 and session_id not in {'.', '..'}, 'Invalid session_id')
        binding = dict(plan_sha256=plan_sha256, body_sha256=body_sha256, model=model)
        _binding(binding)
        root = Path(root).absolute()
        if not root.exists():
            root.mkdir(mode=0o700)
            _fsync_dir(root.parent)
        _directory(root)
        # Cross-session exclusion belongs to the caller's host lease. This
        # preflight is fail-closed discovery, not a global interprocess lock.
        assert_no_pending_installs(root)
        folder = root / session_id
        folder.mkdir(mode=0o700)
        _fsync_dir(root)
        journal = cls(folder, [])
        journal._append('PLANNED', {}, binding)
        return journal

    @classmethod
    def open(cls, session_dir):
        folder = Path(session_dir).absolute()
        try:
            _directory(folder)
            files = sorted(folder.iterdir())
            _require(bool(files), 'Empty/incomplete install session')
            events = []
            for index, path in enumerate(files, 1):
                _require(path.name == f'{index:08d}.json', 'Missing sequence or unexpected session file')
                raw, event = _read_json(path)
                _require(isinstance(event, dict) and set(event) == {
                    'schema', 'session_id', 'seq', 'prev_sha256', 'binding', 'state', 'details', 'event_sha256'
                }, 'Invalid event fields')
                _require(raw == _canonical(event), 'Noncanonical/partial event')
                _require(event['schema'] == 1 and type(event['schema']) is int, 'Invalid schema')
                _require(type(event['seq']) is int and event['seq'] == index, 'Invalid event sequence')
                _require(event['session_id'] == folder.name, 'Session identity mismatch')
                _binding(event['binding'])
                _require(not events or event['binding'] == events[0]['binding'], 'Plan/body/model binding changed')
                expected = events[-1]['event_sha256'] if events else ZERO_SHA
                _require(event['prev_sha256'] == expected, 'Broken previous-event chain')
                payload = {k: v for k, v in event.items() if k != 'event_sha256'}
                _require(event['event_sha256'] == _sha(_canonical(payload)), 'Event checksum mismatch')
                _require(isinstance(event['state'], str) and event['state'] in STATES, 'Invalid state')
                _require(isinstance(event['details'], dict), 'Invalid details')
                _transition(events, event['state'])
                _formal_details(event['state'], event['details'], event['binding'], events, folder)
                if event['state'] == 'CONTENT_VERIFIED':
                    _verification(event['details'].get('verification_artifact'), event['binding'])
                if event['state'] == 'RAM_RESTORATION_VERIFIED':
                    _ram_restoration(event['details'].get('ram_restoration_artifact'),
                                     event['binding'], events)
                if event['state'] == 'INSTALL_PATCH_AWAITING_OPERATOR_RECONNECT':
                    _install_patch_details(event['details'], event['binding'], events)
                if event['state'] == 'MANUALLY_RECONCILED_SAFE':
                    _require(event['details'].get('explicit_user_approval') is True,
                             'Explicit user approval is required')
                    _manual_reconciliation(event['details'].get('reconciliation_artifact'),
                                           event['binding'], events)
                if event['state'] == 'LOCAL_REJECTED_BEFORE_DEVICE_ENTRY':
                    from camera_local_rejection import validate_local_rejection
                    validate_local_rejection(event['details'].get('local_rejection_artifact'),
                                             event['binding'], events, folder, check_current_claims=False)
                events.append(event)
            return cls(folder, events)
        except (OSError, TypeError, KeyError) as exc:
            raise JournalError('Unreadable/damaged install session: ' + str(folder)) from exc

    def advance(self, state, *, details=None):
        """Append a durable phase boundary; returns a detached event dict.

        CONTENT_VERIFIED must use record_content_verified(). Manual reconciliation
        requires record_manual_reconciliation(); this API performs no recovery.
        """
        _require(state != 'CONTENT_VERIFIED', 'Use record_content_verified with an artifact')
        _require(state != 'MANUALLY_RECONCILED_SAFE', 'Use record_manual_reconciliation with explicit approval')
        _require(state != 'RAM_RESTORATION_VERIFIED', 'Use record_ram_restoration_verified with an artifact')
        _require(state != 'LOCAL_REJECTED_BEFORE_DEVICE_ENTRY', 'Use record_local_rejection with an artifact')
        _require(state != 'INSTALL_PATCH_AWAITING_OPERATOR_RECONNECT',
                 'Use record_install_patch_awaiting_reconnect with a complete artifact')
        _require(state not in FORMAL_ARTIFACTS, 'Use the dedicated artifact method for formal installation phases')
        return self._append(state, {} if details is None else details)

    def _record_formal(self, state, artifact_path, **extra):
        from camera_install_receipts import safe_path, load_reference, canonical, sha
        path = safe_path(artifact_path)
        raw = path.read_bytes()
        reference = dict(path=str(path), sha256=sha(raw))
        _, report = load_reference(reference)
        details = {FORMAL_ARTIFACTS[state]: reference,
                   'complete_receipt_sha256': sha(canonical(report)), **extra}
        return self._append(state, details)

    def record_install_admission(self, artifact_path):
        """Record validated full-install admission; no operator start has occurred."""
        return self._record_formal('INSTALL_READY_FOR_OPERATOR_START', artifact_path)

    def record_flash_may_have_started(self, artifact_path):
        """Persist the approved manual-start boundary before displaying its instruction."""
        return self._record_formal('FLASH_MAY_HAVE_STARTED', artifact_path)

    def record_device_completion(self, artifact_path):
        """Record explicit operator completion and normal-service re-entry permission."""
        return self._record_formal('DEVICE_COMPLETION_REPORTED', artifact_path)

    def record_install_preparation_cancelled(self, artifact_path, *, explicit_user_approval=False):
        """Close preparation by current-state evidence, without claiming old-mm restoration."""
        _require(explicit_user_approval is True, 'Explicit preparation cancellation approval required')
        return self._record_formal('INSTALL_PREPARATION_CANCELLED', artifact_path,
                                   explicit_user_approval=True)

    def record_install_patch_awaiting_reconnect(self, artifact_path):
        """Record a complete preparation receipt while keeping all work blocked."""
        path = Path(artifact_path).absolute()
        from camera_install_patch_session import canonical_sha256
        raw, report = _read_json(path)
        reference = dict(path=str(path), sha256=_sha(raw))
        _transition(self._events, 'INSTALL_PATCH_AWAITING_OPERATOR_RECONNECT')
        _install_patch_pending(reference, self.binding, self._events)
        return self._append('INSTALL_PATCH_AWAITING_OPERATOR_RECONNECT', dict(
            install_patch_artifact=reference,
            complete_receipt_sha256=canonical_sha256(report)))

    def record_local_rejection(self, artifact_path):
        """Close the pinned historical local failure; permit only a fresh session.

        This records local execution evidence, without hardware assertions,
        device actions, rollback, recovery, or permission to resume this attempt.
        """
        from camera_local_rejection import validate_local_rejection
        path = Path(artifact_path).absolute()
        raw, _ = _read_json(path)
        reference = {'path': str(path), 'sha256': _sha(raw)}
        validate_local_rejection(reference, self.binding, self._events, self.session_dir,
                                 check_current_claims=True)
        return self._append('LOCAL_REJECTED_BEFORE_DEVICE_ENTRY', {'local_rejection_artifact': reference})

    def record_content_verified(self, artifact_path):
        path = Path(artifact_path).absolute()
        raw, _ = _read_json(path)
        reference = {'path': str(path), 'sha256': _sha(raw)}
        _verification(reference, self.binding)
        return self._append('CONTENT_VERIFIED', {'verification_artifact': reference})

    def record_ram_restoration_verified(self, artifact_path):
        """Close a normal volatile RAM attempt using referenced hardware evidence.

        This does not execute restoration or certify firmware installation,
        photography, or whole-device function. It only records that this
        temporary RAM window ended safely. Source authenticity still depends
        on the trusted producer, not the JSON declaration or this ledger.
        """
        path = Path(artifact_path).absolute()
        raw, _ = _read_json(path)
        reference = {'path': str(path), 'sha256': _sha(raw)}
        _ram_restoration(reference, self.binding, self._events)
        return self._append('RAM_RESTORATION_VERIFIED', {'ram_restoration_artifact': reference})

    def record_manual_reconciliation(self, artifact_path, *, explicit_user_approval=False):
        """Accept manually reviewed evidence; never execute recovery or resume.

        Strict True approval must come from an explicit user decision. The caller
        must obtain it independently; storing this boolean does not authenticate
        the approver. Historical events remain intact and new inspections need
        their own authorization. This is distinct from CONTENT_VERIFIED.
        """
        _require(explicit_user_approval is True, 'Explicit user approval is required')
        path = Path(artifact_path).absolute()
        raw, _ = _read_json(path)
        reference = {'path': str(path), 'sha256': _sha(raw)}
        _manual_reconciliation(reference, self.binding, self._events)
        return self._append('MANUALLY_RECONCILED_SAFE', {
            'reconciliation_artifact': reference, 'explicit_user_approval': True})

    def _append(self, state, details, initial_binding=None):
        _require(isinstance(state, str) and state in STATES, 'Invalid state')
        _require(isinstance(details, dict), 'Details must be an object')
        _transition(self._events, state)
        if self._events:
            current = self.open(self.session_dir)
            _require(current._events == self._events, 'Stale journal instance; refusing automatic advance')
        binding = self.binding if self._events else initial_binding
        _formal_details(state, details, binding, self._events, self.session_dir)
        event = dict(schema=1, session_id=self.session_dir.name, seq=len(self._events) + 1,
                     prev_sha256=self._events[-1]['event_sha256'] if self._events else ZERO_SHA,
                     binding=binding, state=state, details=deepcopy(details))
        if state == 'CONTENT_VERIFIED':
            _verification(event['details'].get('verification_artifact'), binding)
        if state == 'RAM_RESTORATION_VERIFIED':
            _ram_restoration(details.get('ram_restoration_artifact'), binding, self._events)
        if state == 'INSTALL_PATCH_AWAITING_OPERATOR_RECONNECT':
            _install_patch_details(details, binding, self._events)
        if state == 'MANUALLY_RECONCILED_SAFE':
            _require(details.get('explicit_user_approval') is True, 'Explicit user approval is required')
            _manual_reconciliation(details.get('reconciliation_artifact'), binding, self._events)
        if state == 'LOCAL_REJECTED_BEFORE_DEVICE_ENTRY':
            from camera_local_rejection import validate_local_rejection
            validate_local_rejection(details.get('local_rejection_artifact'), binding,
                                     self._events, self.session_dir, check_current_claims=True)
        event['event_sha256'] = _sha(_canonical(event))
        raw = _canonical(event)
        target = self.session_dir / f"{event['seq']:08d}.json"
        # Failed writes intentionally leave a blocking partial record. Never
        # unlink, truncate, retry, or infer that an uncertain append succeeded.
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
        fd = os.open(target, flags, 0o600)
        with os.fdopen(fd, 'wb') as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        _fsync_dir(self.session_dir)
        self._events.append(event)
        return deepcopy(event)


def assert_no_pending_installs(root):
    """Scan only the caller-specified local session root; never probe devices.

    Absence means no recorded attempt. Every present child must be a complete,
    valid, safe terminal session; completion-reported and unknown both block.
    Call while holding the caller's host lease before creating new operations.
    """
    root = Path(root).absolute()
    if not root.exists() and not root.is_symlink():
        return
    try:
        _directory(root)
        for child in sorted(root.iterdir()):
            journal = InstallJournal.open(child)
            _require(journal.state in TERMINAL_SAFE,
                     'Pending install ' + child.name + ': ' + journal.state)
    except OSError as exc:
        raise JournalError('Cannot inspect sessions root') from exc
