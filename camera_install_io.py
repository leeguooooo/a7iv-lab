"""Pin one validated local journal snapshot across packet-level driver calls.

Construction performs full journal semantics once. check() observes only the
held host lease and immutable local ledger files; it does not rehash artifacts,
validate admission, authenticate hardware or authorize START. Callers retain
full semantic/source/artifact checks at operation boundaries. Changes reverted
between observations cannot be excluded by this software snapshot.
"""
from copy import deepcopy
import os
from pathlib import Path
import stat

from camera_install_journal import InstallJournal, _canonical
from camera_install_patch_session import _held_lease

MAX_EVENTS = 10000
MAX_EVENT_BYTES = 1 << 20
MAX_LEDGER_BYTES = 64 << 20


def require(ok, message):
    if not ok:
        raise ValueError(message)


def _safe(path):
    path = Path(path).absolute()
    require('..' not in path.parts and all(not p.is_symlink() for p in (path, *path.parents)),
            'Canonical nonsymlink journal location required')
    return path


def _directory_identity(value):
    require(stat.S_ISDIR(value.st_mode), 'Pinned journal directory required')
    return value.st_dev, value.st_ino


def _file_identity(value):
    require(stat.S_ISREG(value.st_mode), 'Pinned regular journal event required')
    return (value.st_dev, value.st_ino, value.st_mode, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns)


class JournalSnapshotPin:
    """Own read-only FDs for a bounded, fully validated historical prefix.

    The supplied InstallJournal must stay unchanged for this pin's lifetime.
    Closing or a failed check permanently invalidates the pin. Construct a new
    pin only at a separately validated collector boundary; this is not a retry.
    """
    def __init__(self, journal, lease):
        self._directory_fd = None
        self._files = []
        self._closed = False
        self._failed = False
        self._journal = journal
        self._lease = lease
        try:
            # Ownership is checked before the potentially expensive semantic open.
            self._lease_identity = _held_lease(lease)
            require(isinstance(journal, InstallJournal), 'Caller InstallJournal required')
            self._path = _safe(journal.session_dir)
            self._events = deepcopy(journal.events)
            require(0 < len(self._events) <= MAX_EVENTS, 'Bounded nonempty journal required')
            self._names = tuple(f'{i:08d}.json' for i in range(1, len(self._events) + 1))
            flags = os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0) | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0)
            self._directory_fd = os.open(self._path, flags)
            self._directory_id = _directory_identity(os.fstat(self._directory_fd))
            self._check_directory()
            # Bound ledger input before asking the existing reader to parse it.
            total = 0
            for name in self._names:
                value = os.stat(name, dir_fd=self._directory_fd, follow_symlinks=False)
                _file_identity(value)
                require(0 < value.st_size <= MAX_EVENT_BYTES, 'Journal event exceeds byte bound')
                total += value.st_size
            require(total <= MAX_LEDGER_BYTES, 'Journal exceeds total byte bound')
            validated = InstallJournal.open(self._path)
            require(validated.events == self._events == journal.events, 'Stale caller journal instance')
            for name, event in zip(self._names, self._events):
                raw = _canonical(event)
                require(0 < len(raw) <= MAX_EVENT_BYTES, 'Canonical journal event exceeds byte bound')
                fd = os.open(name, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
                             | getattr(os, 'O_CLOEXEC', 0) | getattr(os, 'O_NONBLOCK', 0),
                             dir_fd=self._directory_fd)
                # Register immediately so every constructor failure closes this FD.
                item = dict(name=name, fd=fd, raw=raw)
                self._files.append(item)
                item['identity'] = _file_identity(os.fstat(fd))
                require(item['identity'][3] == len(raw), 'Journal event canonical size differs')
                self._check_file(item)
            self.check()
        except BaseException:
            self._failed = True
            self.close()
            raise

    def _check_directory(self):
        _safe(self._path)
        require(_directory_identity(os.stat(self._path, follow_symlinks=False))
                == _directory_identity(os.fstat(self._directory_fd)) == self._directory_id,
                'Journal directory identity changed')
        require(tuple(sorted(os.listdir(self._directory_fd))) == self._names,
                'Journal event set changed')

    def _check_file(self, item):
        fd, expected = item['fd'], item['identity']
        location = os.stat(item['name'], dir_fd=self._directory_fd, follow_symlinks=False)
        require(_file_identity(location) == _file_identity(os.fstat(fd)) == expected,
                'Journal event inode or metadata changed')
        # The extra byte rejects growth; a short read is never accepted/truncated.
        require(os.pread(fd, len(item['raw']) + 1, 0) == item['raw'],
                'Journal event raw bytes changed')
        require(_file_identity(os.fstat(fd)) == expected
                and _file_identity(os.stat(item['name'], dir_fd=self._directory_fd,
                                           follow_symlinks=False)) == expected,
                'Journal event changed during packet check')

    def check(self):
        """Check small ledger bytes and live lease only; return no admission flag."""
        require(not self._closed and not self._failed, 'Journal snapshot pin is closed or failed')
        try:
            require(_held_lease(self._lease) == self._lease_identity,
                    'Pinned lease identity changed')
            require(self._journal.events == self._events, 'Caller journal snapshot changed')
            self._check_directory()
            for item in self._files:
                self._check_file(item)
            self._check_directory()
            require(_held_lease(self._lease) == self._lease_identity
                    and self._journal.events == self._events,
                    'Lease or journal changed during packet check')
        except BaseException:
            self._failed = True
            raise

    def close(self):
        """Idempotently release only this pin's descriptors, never the lease."""
        if self._closed:
            return
        self._closed = True
        failure = None
        for item in reversed(self._files):
            try:
                os.close(item['fd'])
            except OSError as error:
                failure = failure or error
        self._files.clear()
        if self._directory_fd is not None:
            try:
                os.close(self._directory_fd)
            except OSError as error:
                failure = failure or error
            self._directory_fd = None
        if failure is not None:
            raise failure

    def __enter__(self):
        require(not self._closed and not self._failed, 'Cannot enter a closed or failed snapshot pin')
        self.check()
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.close()


class PinnedDriver:
    """Guard delegated driver calls and poison this proxy after the first error."""
    def __init__(self, original, guard):
        require(callable(guard), 'Callable packet ownership guard required')
        self.original, self.guard, self.failed = original, guard, False

    def __getattr__(self, name):
        value = getattr(self.original, name)
        if not callable(value):
            return value
        def invoke(*args, **kwargs):
            require(not self.failed, 'Pinned driver already failed')
            try:
                self.guard()
                return value(*args, **kwargs)
            except BaseException:
                self.failed = True
                raise
        return invoke
