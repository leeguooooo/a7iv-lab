"""Explicit single-writer backup-copy and atomic replacement protocol.

This is not an exclusive rename fallback. It cannot prevent an unrelated writer
from replacing the target between the final preimage check and POSIX rename.
No camera, SDK, firmware, journal, or automatic retry interface is provided.
"""
from dataclasses import dataclass
from enum import Enum
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import fcntl


PROTOCOL = 'BACKUP_COPY_ATOMIC_REPLACE'


class Assurance(Enum):
    NO_CLOBBER = 'NO_CLOBBER'
    SINGLE_WRITER_BACKUP_REPLACE = PROTOCOL
    SINGLE_WRITER_BACKUP_RESTORE = 'BACKUP_COPY_ATOMIC_RESTORE'


class ReplacementError(RuntimeError):
    def __init__(self, phase, evidence_directory):
        super().__init__('Replacement stopped in ' + phase + '; inspect ' + str(evidence_directory))
        self.phase = phase
        self.evidence_directory = Path(evidence_directory)


@dataclass(frozen=True)
class FileExpectation:
    path: Path
    size: int
    sha256: str


@dataclass(frozen=True)
class ReplacementPlan:
    candidate: FileExpectation
    original: FileExpectation
    backup: Path


@dataclass(frozen=True)
class WithdrawalPlan:
    active: FileExpectation
    original_backup: FileExpectation
    inactive_candidate: Path


@dataclass(frozen=True)
class _Transaction:
    source: FileExpectation
    target: FileExpectation
    preserved: Path
    assurance: Assurance


@dataclass(frozen=True)
class _FileIdentity:
    device: int
    inode: int
    size: int
    mtime_ns: int
    ctime_ns: int


@dataclass(frozen=True)
class _IO:
    read: object = os.read
    write: object = os.write
    fsync: object = os.fsync
    replace: object = os.replace


def _path(value):
    value = Path(value).absolute()
    if '..' in value.parts or any(p.is_symlink() for p in (value, *value.parents)):
        raise ValueError('Canonical nonsymlink paths required')
    return value


def _file_identity(value):
    if not stat.S_ISREG(value.st_mode):
        raise ValueError('Regular file required')
    return _FileIdentity(value.st_dev, value.st_ino, value.st_size,
                         value.st_mtime_ns, value.st_ctime_ns)


def _open_directory(path):
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        current = path.stat(follow_symlinks=False)
        held = os.fstat(fd)
        if (current.st_dev, current.st_ino) != (held.st_dev, held.st_ino):
            raise ValueError('Directory changed while opening')
        return fd
    except BaseException:
        os.close(fd)
        raise


def _check_directory(path, fd):
    _path(path)
    named, held = path.stat(follow_symlinks=False), os.fstat(fd)
    if not stat.S_ISDIR(named.st_mode) or (named.st_dev, named.st_ino) != (held.st_dev, held.st_ino):
        raise ValueError('Directory identity changed')


def _open_file(expected, directory_fd, cache_requests):
    fd = os.open(expected.path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                 dir_fd=directory_fd)
    try:
        held = os.fstat(fd)
        identity = _file_identity(held)
        if held.st_nlink != 1 or identity.size != expected.size:
            raise ValueError('File size or link count differs')
        cache = dict(path=str(expected.path), requested=sys.platform == 'darwin', applied_by_api=False,
                     actual_media_cache_bypass_proven=False)
        cache_requests.append(cache)
        if sys.platform == 'darwin':
            if not hasattr(fcntl, 'F_NOCACHE'):
                raise ValueError('Darwin F_NOCACHE is unavailable')
            try:
                fcntl.fcntl(fd, fcntl.F_NOCACHE, 1)
            except OSError as error:
                cache['errno'] = error.errno
                raise
            cache['applied_by_api'] = True
        return fd, identity
    except BaseException:
        os.close(fd)
        raise


def _check_file(expected, fd, identity, directory_fd):
    named = os.stat(expected.path.name, dir_fd=directory_fd, follow_symlinks=False)
    if _file_identity(named) != identity or _file_identity(os.fstat(fd)) != identity:
        raise ValueError('Pinned file changed')


def _hash_file(expected, fd, identity, directory_fd, operations):
    _check_file(expected, fd, identity, directory_fd)
    os.lseek(fd, 0, os.SEEK_SET)
    digest, length = hashlib.sha256(), 0
    while True:
        chunk = operations.read(fd, 1 << 20)
        if not chunk:
            break
        length += len(chunk)
        if length > expected.size:
            raise ValueError('Unexpected trailing file content')
        digest.update(chunk)
    _check_file(expected, fd, identity, directory_fd)
    if length != expected.size or digest.hexdigest() != expected.sha256:
        raise ValueError('File content differs from approved identity')


def _write_all(fd, data, operations):
    position = 0
    while position < len(data):
        count = operations.write(fd, data[position:])
        if not isinstance(count, int) or count <= 0 or count > len(data) - position:
            raise OSError('Invalid short write')
        position += count


def _save(directory_fd, name, value, operations):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o600, dir_fd=directory_fd)
    try:
        _write_all(fd, (json.dumps(value, sort_keys=True, indent=2) + '\n').encode(), operations)
        operations.fsync(fd)
    finally:
        os.close(fd)
    operations.fsync(directory_fd)


def _validated_transaction(source, target, preserved, assurance):
    for expected in (source, target):
        if (not isinstance(expected, FileExpectation) or type(expected.size) is not int
                or expected.size <= 0 or not isinstance(expected.sha256, str)
                or re.fullmatch('[0-9a-f]{64}', expected.sha256) is None):
            raise ValueError('Positive file size and exact SHA256 required')
    source = FileExpectation(_path(source.path), source.size, source.sha256)
    target = FileExpectation(_path(target.path), target.size, target.sha256)
    preserved = _path(preserved)
    activating = assurance is Assurance.SINGLE_WRITER_BACKUP_REPLACE
    source_name, preserved_name = (('candidate.staged', 'original-BODYDATA.DAT') if activating
                                    else ('original-BODYDATA.DAT', 'candidate.staged'))
    candidate_sha256 = source.sha256 if activating else target.sha256
    if (target.path.name != 'BODYDATA.DAT' or source.path.name != source_name
            or preserved.name != preserved_name or preserved.parent != source.path.parent
            or source.path.parent.parent != target.path.parent / '.camera-use-staging'
            or re.fullmatch(r'fl23-' + candidate_sha256[:16] + r'-[0-9a-f]{16}', source.path.parent.name) is None
            or source.sha256 == target.sha256):
        raise ValueError('Exact distinct staged candidate, original and owned backup layout required')
    return _Transaction(source, target, preserved, assurance)


def replace_with_backup(plan, evidence_directory, *, expected_card_identity, identity_reader,
                        assurance=Assurance.NO_CLOBBER, single_writer_acknowledged=False,
                        _operations=None):
    """Publish a complete candidate while retaining an exact old-file copy.

    The caller must separately validate authorization, body/card identity and
    exclusive cooperative ownership. The mandatory identity_reader must query
    that same body/card and return its stable mapping on every call. It grants
    no authority to this module. NO_CLOBBER is rejected, never downgraded.

    Evidence is exclusive and single-use. Any failure after evidence creation
    raises ReplacementError and preserves card files without rollback or retry.
    Missing completed evidence is UNKNOWN, even if writing stopped.json fails.
    Injected I/O is tagged as a model and cannot claim production execution.
    """
    if not isinstance(plan, ReplacementPlan):
        raise ValueError('ReplacementPlan required')
    transaction = _validated_transaction(plan.candidate, plan.original, plan.backup,
                                        Assurance.SINGLE_WRITER_BACKUP_REPLACE)
    return _run_transaction(transaction, evidence_directory, expected_card_identity=expected_card_identity,
                            identity_reader=identity_reader, assurance=assurance,
                            single_writer_acknowledged=single_writer_acknowledged, _operations=_operations)


def withdraw_with_backup(plan, evidence_directory, *, expected_card_identity, identity_reader,
                         assurance=Assurance.NO_CLOBBER, single_writer_acknowledged=False,
                         _operations=None):
    """Preserve the active candidate, then restore the complete original backup.

    This has the same exclusive cooperative writer limitation as publication.
    It does not restore RAM, clear a journal or authorize another transaction.
    The old backup name is consumed only by the final atomic replacement.
    """
    if not isinstance(plan, WithdrawalPlan):
        raise ValueError('WithdrawalPlan required')
    transaction = _validated_transaction(plan.original_backup, plan.active, plan.inactive_candidate,
                                        Assurance.SINGLE_WRITER_BACKUP_RESTORE)
    return _run_transaction(transaction, evidence_directory, expected_card_identity=expected_card_identity,
                            identity_reader=identity_reader, assurance=assurance,
                            single_writer_acknowledged=single_writer_acknowledged, _operations=_operations)


def _run_transaction(plan, evidence_directory, *, expected_card_identity, identity_reader,
                     assurance, single_writer_acknowledged, _operations):
    if assurance is not plan.assurance or single_writer_acknowledged is not True:
        raise ValueError('Explicit single-writer backup-replace contract required; no no-clobber guarantee')
    if not callable(identity_reader) or not isinstance(expected_card_identity, dict) or not expected_card_identity:
        raise ValueError('Mandatory nonempty caller-bound card identity required')
    identity_json = json.dumps(expected_card_identity, sort_keys=True, allow_nan=False)
    evidence = _path(evidence_directory)
    if evidence.exists():
        raise FileExistsError('Evidence directory is single-use')
    if evidence == plan.target.path.parent or evidence.is_relative_to(plan.target.path.parent):
        raise ValueError('Evidence must be outside the card tree')
    operations = _IO() if _operations is None else _operations
    fds, directory_fds, cache_requests = [], {}, []
    phase, evidence_fd = 'PRECHECK', None
    common = dict(protocol=plan.assurance.value, atomic_no_clobber=False, single_writer_acknowledged=True,
                  external_writers_excluded_by_module=False, requires_exclusive_cooperative_writer=True,
                  execution_kind='PRODUCTION_HOST_FILESYSTEM' if _operations is None else 'INJECTED_IO_MODEL',
                  camera_native_execution_proven=False, firmware_update_authorized=False,
                  automatic_retry=False, automatic_rollback=False, card_identity=json.loads(identity_json),
                  readback_cache_bypass_requests=cache_requests,
                  operation='ACTIVATE' if plan.assurance is Assurance.SINGLE_WRITER_BACKUP_REPLACE else 'WITHDRAW',
                  source_path=str(plan.source.path), target_path=str(plan.target.path),
                  preserved_path=str(plan.preserved), source_sha256=plan.source.sha256,
                  previous_target_sha256=plan.target.sha256)

    def check_card():
        if json.dumps(identity_reader(), sort_keys=True, allow_nan=False) != identity_json:
            raise ValueError('Body/card identity differs')
        for path, fd in directory_fds.items():
            _check_directory(path, fd)

    def backup_absent():
        try:
            os.stat(plan.preserved.name, dir_fd=staged_dir, follow_symlinks=False)
        except FileNotFoundError:
            return
        raise ValueError('Backup destination already exists')

    def close_card_handles():
        while fds:
            os.close(fds.pop())
        while directory_fds:
            _, fd = directory_fds.popitem()
            os.close(fd)

    def save_evidence(name, value):
        _check_directory(evidence, evidence_fd)
        _save(evidence_fd, name, value, operations)
        _check_directory(evidence, evidence_fd)

    try:
        check_card()
        for path in (plan.target.path.parent, plan.source.path.parent):
            directory_fds[path] = _open_directory(path)
        root_dir, staged_dir = (directory_fds[p] for p in (plan.target.path.parent, plan.source.path.parent))
        original_fd, original_identity = _open_file(plan.target, root_dir, cache_requests); fds.append(original_fd)
        candidate_fd, candidate_identity = _open_file(plan.source, staged_dir, cache_requests); fds.append(candidate_fd)
        if len({original_identity.device, candidate_identity.device, os.fstat(root_dir).st_dev,
                os.fstat(staged_dir).st_dev}) != 1 or original_identity.inode == candidate_identity.inode:
            raise ValueError('Distinct same-volume files required')
        _hash_file(plan.target, original_fd, original_identity, root_dir, operations)
        _hash_file(plan.source, candidate_fd, candidate_identity, staged_dir, operations)
        backup_absent(); check_card()
        evidence.mkdir(mode=0o700)
        evidence_fd = _open_directory(evidence)
        phase = 'BACKUP_MAY_BE_PARTIAL'
        save_evidence('intent.json', dict(common, state=phase,
                      source_bytes=plan.source.size, previous_target_bytes=plan.target.size))
        backup_absent(); check_card()
        _check_file(plan.target, original_fd, original_identity, root_dir)
        backup_fd = os.open(plan.preserved.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                            0o600, dir_fd=staged_dir)
        try:
            if os.fstat(backup_fd).st_dev != original_identity.device:
                raise ValueError('Backup device differs')
            os.lseek(original_fd, 0, os.SEEK_SET)
            copied, copied_hash = 0, hashlib.sha256()
            while True:
                chunk = operations.read(original_fd, 1 << 20)
                if not chunk:
                    break
                copied += len(chunk)
                if copied > plan.target.size:
                    raise ValueError('Original grew during backup')
                copied_hash.update(chunk); _write_all(backup_fd, chunk, operations)
            if copied != plan.target.size or copied_hash.hexdigest() != plan.target.sha256:
                raise ValueError('Backup source content changed')
            _check_file(plan.target, original_fd, original_identity, root_dir)
            operations.fsync(backup_fd)
        finally:
            os.close(backup_fd)
        backup_expected = FileExpectation(plan.preserved, plan.target.size, plan.target.sha256)
        backup_fd, backup_identity = _open_file(backup_expected, staged_dir, cache_requests); fds.append(backup_fd)
        _hash_file(backup_expected, backup_fd, backup_identity, staged_dir, operations)
        operations.fsync(staged_dir)
        phase = 'BACKUP_VERIFIED'
        check_card()
        _hash_file(plan.target, original_fd, original_identity, root_dir, operations)
        _hash_file(plan.source, candidate_fd, candidate_identity, staged_dir, operations)
        _hash_file(backup_expected, backup_fd, backup_identity, staged_dir, operations)
        phase = 'REPLACE_MAY_HAVE_OCCURRED'
        save_evidence('replace-intent.json', dict(common, state=phase,
                      preserved_sha256=plan.target.sha256))
        check_card()
        _check_file(plan.target, original_fd, original_identity, root_dir)
        _check_file(plan.source, candidate_fd, candidate_identity, staged_dir)
        _check_file(backup_expected, backup_fd, backup_identity, staged_dir)
        operations.replace(plan.source.path.name, plan.target.path.name,
                           src_dir_fd=staged_dir, dst_dir_fd=root_dir)
        phase = 'REPLACED_NOT_FULLY_VERIFIED'
        operations.fsync(root_dir); operations.fsync(staged_dir)
        check_card()
        published = FileExpectation(plan.target.path, plan.source.size, plan.source.sha256)
        published_fd, published_identity = _open_file(published, root_dir, cache_requests); fds.append(published_fd)
        if (published_identity.device, published_identity.inode) != (candidate_identity.device, candidate_identity.inode):
            raise ValueError('Published object differs from pinned candidate')
        _hash_file(published, published_fd, published_identity, root_dir, operations)
        _hash_file(backup_expected, backup_fd, backup_identity, staged_dir, operations)
        try:
            os.stat(plan.source.path.name, dir_fd=staged_dir, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ValueError('Candidate source still exists after replacement')
        check_card()
        close_card_handles()
        result = dict(common, state='COMPLETED', root_path=str(plan.target.path), updater_invoked=False,
                      target_name_continuously_present_by_posix_contract=True,
                      power_loss_atomicity_proven=False)
        if plan.assurance is Assurance.SINGLE_WRITER_BACKUP_REPLACE:
            result.update(candidate_sha256=plan.source.sha256, backup_sha256=plan.target.sha256,
                          backup_path=str(plan.preserved))
        else:
            result.update(original_sha256=plan.source.sha256, inactive_candidate_sha256=plan.target.sha256,
                          inactive_candidate_path=str(plan.preserved), original_backup_source_absent=True)
        save_evidence('completed.json', result)
        return result
    except BaseException as error:
        if evidence_fd is None:
            raise
        try:
            save_evidence('stopped.json', dict(common, state='UNKNOWN', phase=phase,
                          error_type=type(error).__name__))
        except BaseException:
            pass
        raise ReplacementError(phase, evidence) from error
    finally:
        for fd in (*reversed(fds), *directory_fds.values(), *(() if evidence_fd is None else (evidence_fd,))):
            try:
                os.close(fd)
            except OSError:
                pass
