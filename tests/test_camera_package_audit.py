import hashlib
import io
from pathlib import Path
import struct
import tarfile
import tempfile
import unittest
import zlib

from camera_package_audit import audit_candidate, scan_plaintext


class PackageAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name).resolve()/'plain.bin'

    def package(self, *, data=b'payload', expected=b'payload', target='a.bin',
                duplicate=False, extra=False, kind=None, bad_header=False):
        payload = io.BytesIO()
        with tarfile.open(fileobj=payload, mode='w') as tar:
            def add(name, raw):
                item=tarfile.TarInfo(name);item.size=len(raw)
                tar.addfile(item,io.BytesIO(raw))
            if kind:
                item=tarfile.TarInfo('0100_config/a.bin');item.type=kind
                item.linkname='elsewhere';tar.addfile(item)
            else:
                add('0100_config/a.bin',data)
            if duplicate:add('./0100_config/a.bin',data)
            if extra:add('0100_config/unlisted.bin',b'unlisted')
            row=f'0,{zlib.crc32(expected):08x},{len(expected):08x},0,0,0,root,root,-1,-1,{target},\n'
            add('0101_config_sum/config.sum',row.encode())
        body=payload.getvalue()
        header=bytearray(512);header[:8]=b'UDTRFIRM';header[12:16]=b'0100'
        struct.pack_into('<II',header,48,512,len(body))
        struct.pack_into('<I',header,8,zlib.crc32(header[12:]))
        if bad_header:header[100]^=1
        self.path.write_bytes(header+body)

    def test_reports_actual_crc_sha_and_full_input_digest(self):
        self.package()
        r=scan_plaintext(self.path)
        self.assertEqual(r['component_sums']['0100_config/a.bin'],(f'{zlib.crc32(b"payload"):08x}',zlib.crc32(b'payload')))
        self.assertEqual(r['plaintext_sha256'],hashlib.sha256(self.path.read_bytes()).hexdigest())
        self.assertEqual(r['tables'][0]['rows'][0]['sha256'],hashlib.sha256(b'payload').hexdigest())
        self.assertFalse(r['installation_authorized'])

    def test_corrupt_payload_crc_rejected(self):
        self.package(data=b'payloae')
        with self.assertRaisesRegex(ValueError,'CRC mismatch'):scan_plaintext(self.path)

    def test_corrupt_header_rejected(self):
        self.package(bad_header=True)
        with self.assertRaisesRegex(ValueError,'Header CRC'):scan_plaintext(self.path)

    def test_duplicate_normalized_tar_name_rejected(self):
        self.package(duplicate=True)
        with self.assertRaisesRegex(ValueError,'Duplicate tar'):scan_plaintext(self.path)

    def test_missing_regular_checksum_coverage_rejected(self):
        self.package(extra=True)
        with self.assertRaisesRegex(ValueError,'Incomplete regular'):scan_plaintext(self.path)

    def test_manifest_path_traversal_rejected(self):
        self.package(target='../elsewhere')
        with self.assertRaisesRegex(ValueError,'Unsafe archive'):scan_plaintext(self.path)

    def test_symlink_cannot_substitute_regular_file(self):
        self.package(kind=tarfile.SYMTYPE)
        with self.assertRaisesRegex(ValueError,'type mismatch'):scan_plaintext(self.path)

    def test_hardlink_rejected(self):
        self.package(kind=tarfile.LNKTYPE)
        with self.assertRaisesRegex(ValueError,'Unsupported tar'):scan_plaintext(self.path)

    def test_length_mismatch_rejected(self):
        self.package(expected=b'longer payload')
        with self.assertRaisesRegex(ValueError,'length mismatch'):scan_plaintext(self.path)

    def test_symlink_input_rejected(self):
        self.package();link=self.path.with_name('link');link.symlink_to(self.path)
        with self.assertRaisesRegex(ValueError,'Symlink'):scan_plaintext(link)

    def test_other_valid_package_not_promoted_to_fixed_candidate(self):
        self.package()
        with self.assertRaisesRegex(ValueError,'Fixed FL23 plaintext differs'):audit_candidate(self.path)


if __name__ == '__main__':unittest.main()
