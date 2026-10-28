"""Local pending-install barrier. Must be evaluated while holding host ownership.

The current, explicitly supplied journal may continue only in declared phases.
No released PID/lock or elapsed time clears another session's uncertainty.
"""
from pathlib import Path
from camera_install_journal import InstallJournal,JournalError,TERMINAL_SAFE

DEFAULT_SESSIONS=Path(__file__).resolve().parent/'output/full-install-sessions'


def assert_operation_allowed(journal=None,*,allowed_states=(),sessions_root=None):
    if journal is not None:
        if not isinstance(journal,InstallJournal):raise JournalError('InstallJournal required')
        current=InstallJournal.open(journal.session_dir)
        if current.events!=journal.events or current.state not in allowed_states:
            raise JournalError('Current session is stale or not in an allowed phase')
        root=Path(sessions_root) if sessions_root is not None else journal.session_dir.parent
        if journal.session_dir.parent.resolve()!=root.resolve():raise JournalError('Current session root mismatch')
    else:
        current=None;root=Path(sessions_root) if sessions_root is not None else DEFAULT_SESSIONS
    if not root.exists() and not root.is_symlink():return
    if root.is_symlink() or not root.is_dir():raise JournalError('Regular local session root required')
    for folder in root.iterdir():
        candidate=InstallJournal.open(folder)
        if current is not None and folder.resolve()==journal.session_dir.resolve():continue
        if candidate.state not in TERMINAL_SAFE:
            raise JournalError('Another install session is pending; no new device operation')
