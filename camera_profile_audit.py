"""Explicit registered-package byte/CRC audit, with no device or install API.

Legacy audit_candidate and the installation actors remain unchanged. This
module does not validate a live device, signature acceptance or permission.
"""
import hashlib
import os
import struct

from camera_candidate_profiles import profile_for_digest
from camera_package_audit import regular_path, require, scan_plaintext


def audit_registered_plaintext(path, *, candidate_sha256):
    profile = profile_for_digest(candidate_sha256)
    path = regular_path(path)
    with path.open('rb') as stream:
        before = os.fstat(stream.fileno())
        require(_identity(before) == _identity(path.stat()), 'Opened plaintext differs from pathname')
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        require(digest == profile.plaintext_sha256 and before.st_size == profile.plaintext_bytes,
                'Plaintext differs from registered candidate')
        report = scan_plaintext(path)
        stream.seek(0)
        header = stream.read(512)
        require(_identity(before) == _identity(os.fstat(stream.fileno()))
                == _identity(path.stat()), 'Plaintext changed during profile audit')
    require(report['plaintext_sha256'] == profile.plaintext_sha256
            and report['plaintext_bytes'] == profile.plaintext_bytes,
            'Plaintext differs from registered candidate')
    require(report['table_count'] == profile.checksum_tables
            and report['regular_CRC_rows'] == profile.regular_CRC_rows,
            'Registered candidate checksum coverage differs')
    require(len(header) == 512 and struct.unpack_from('<II', header, 36)
            == (profile.model_code, profile.region), 'Registered candidate model/region differs')
    return dict(report, profile=profile.name, candidate_sha256=profile.package_sha256,
                role=profile.role, registered_plaintext_verified=True,
                installation_authorized=False, device_admission=False)


def audit_registered_pair(package, plaintext, *, candidate_sha256):
    profile = profile_for_digest(candidate_sha256)
    path = regular_path(package)
    with path.open('rb') as stream:
        before = os.fstat(stream.fileno())
        require(_identity(before) == _identity(path.stat()), 'Opened package differs from pathname')
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        after = os.fstat(stream.fileno())
    require(_identity(before) == _identity(after) == _identity(path.stat())
            and digest == profile.package_sha256
            and before.st_size == profile.package_bytes, 'Registered signed package differs')
    report = audit_registered_plaintext(plaintext, candidate_sha256=candidate_sha256)
    return dict(report, package_sha256=digest, package_bytes=before.st_size,
                encrypted_identity_verified=True, signature_policy=profile.signing_identity,
                signature_checked_this_call=False, publisher_authentication_proven=False)


def _identity(value):
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
