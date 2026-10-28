"""Synthetic local files only; no device, SDK, ioreg, or capture execution."""
from contextlib import ExitStack
import hashlib
import io
import json
import os
from pathlib import Path
import struct
import tarfile
import tempfile
import unittest
from unittest import mock
import zlib

import camera_postinstall_verify as verify
from camera_backup_records import COLOUR_KEYS, SLOTS, record_map


def bk4(values, attrs=0x60):
    groups = max(values) >> 16
    counts = [0] * (groups + 1)
    for key in values:
        counts[key >> 16] = max(counts[key >> 16], (key & 65535) + 1)
    items = sum(counts)
    body = 0x100 + 6 * len(counts) + 6 * items
    raw = bytearray(body)
    raw[4:8], raw[12:16] = b'\xaa' * 4, b'BK4\0'
    struct.pack_into('<III', raw, 16, len(counts), items, body)
    first = 0
    for group, amount in enumerate(counts):
        struct.pack_into('<HI', raw, 0x100 + 6 * group, amount, first)
        for slot in range(amount):
            at = 0x100 + 6 * len(counts) + 6 * (first + slot)
            value = values.get((group << 16) | slot)
            if value is None:
                struct.pack_into('<HI', raw, at, 0, 0xffffffff)
                continue
            offset = len(raw)
            if len(value) >= 255:
                raw.extend(struct.pack('<H', len(value)))
                packed = offset | 0xff000000
            else:
                packed = offset | len(value) << 24
            raw.extend(value)
            struct.pack_into('<HI', raw, at, attrs, packed)
        first += amount
    struct.pack_into('<I', raw, 0x1c, len(raw) - body)
    struct.pack_into('<I', raw, 0x20, sum(raw[:0x20]) + sum(raw[0x24:]))
    empty = bytearray(256)
    empty[4:8], empty[12:16] = b'\xaa' * 4, b'BK4\0'
    struct.pack_into('<III', empty, 16, 0, 0, 256)
    struct.pack_into('<I', empty, 32, sum(empty[:32]) + sum(empty[36:]))
    return bytes(raw + empty)


def fat_image(initrd, kernel, dat2=b'MODL', dat3=b'REGN'):
    raw = bytearray(128 * 512)
    raw[510:512] = b'\x55\xaa'
    struct.pack_into('<HBHBHHBHH', raw, 11, 512, 1, 1, 1, 32, 128, 0xf8, 1, 1)
    raw[512:515] = b'\xf8\xff\xff'
    def eoc(cluster):
        at = 512 + cluster * 3 // 2
        value = struct.unpack_from('<H', raw, at)[0]
        value = (value & 0x000f) | 0xfff0 if cluster & 1 else (value & 0xf000) | 0x0fff
        struct.pack_into('<H', raw, at, value)
    def entry(at, short, cluster, payload=b'', directory=False):
        raw[at:at + 11] = short
        raw[at + 11] = 16 if directory else 32
        struct.pack_into('<HI', raw, at + 26, cluster, len(payload))
        eoc(cluster)
        if payload:
            offset = 2048 + (cluster - 2) * 512
            raw[offset:offset + len(payload)] = payload
    sums = (hashlib.md5(kernel).hexdigest() + '  ./boot/vmlinux.bin\n' +
            hashlib.md5(initrd).hexdigest() + '  ./boot/initrd.img\n').encode()
    entry(1024, b'BOOT       ', 2, directory=True)
    entry(1056, b'P1CHKSUM   ', 5, sums)
    entry(1088, b'DAT2       ', 6, dat2)
    entry(1120, b'DAT3       ', 7, dat3)
    entry(2048, b'INITRD  IMG', 3, initrd)
    entry(2080, b'VMLINUX BIN', 4, kernel)
    return bytes(raw)


class PostinstallTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.host = Path(self.temp.name).resolve()
        self.group = self.host / 'group'
        self.group.mkdir()
        self.binding = dict(plan_sha256='a' * 64, body_sha256='b' * 64, model='ILCE-7M4')
        self.nonce = '01' * 16
        self.initrd, self.kernel = b'target-initrd', b'factory-kernel'
        self.p1 = fat_image(self.initrd, self.kernel)
        self.factory = self.host / 'factory.bin'
        self.factory.write_bytes(self.p1)
        self.values = {0x004b0001: b'\x02', COLOUR_KEYS[0]: b'new-cc', COLOUR_KEYS[1]: b'new-matrix',
                       **{key: bytes([index]) for index, key in enumerate(SLOTS)}}
        self.template = bk4(self.values)
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode='w') as tar:
            member = tarfile.TarInfo(verify.TEMPLATE)
            member.size = len(self.template)
            tar.addfile(member, io.BytesIO(self.template))
        payload = archive.getvalue()
        header = bytearray(512)
        header[:8], header[36:40], header[40:44] = b'UDTRFIRM', b'MODL', b'REGN'
        struct.pack_into('<II', header, 48, 512, len(payload))
        struct.pack_into('<I', header, 8, zlib.crc32(header[12:]))
        self.plain = self.host / 'plain.bin'
        self.plain.write_bytes(header + payload)
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        for name, value in [('PLAIN_SHA', verify.sha(self.plain.read_bytes())),
                            ('FACTORY_SHA', verify.sha(self.p1)), ('INITRD_SHA', verify.sha(self.initrd))]:
            self.stack.enter_context(mock.patch.object(verify, name, value))
        self.payloads = {'post_app': b'app-content', 'post_cp': b'cp-content', 'post_p1': self.p1}
        profiles = {name: (len(raw), verify.sha(raw) if name != 'post_p1' else None,
                           verify.PROFILES[name][2], verify.PROFILES[name][3])
                    for name, raw in self.payloads.items()}
        self.stack.enter_context(mock.patch.object(verify, 'PROFILES', profiles))
        self.run = dict(self.binding, schema='camera-postinstall-capture-run/1', group_nonce=self.nonce,
                        normal_body_verified=True, source_is_hardware=False, captures={}, critical_settings={})
        for number, (name, raw) in enumerate(self.payloads.items(), 2):
            self.make_capture(name, raw, f'{number:02x}' * 16)
        for number, name in enumerate(('before', 'after'), 5):
            raw = self.template if name == 'after' else bk4(dict(self.values, **{}))
            path = self.group / (name + '.bk4')
            path.write_bytes(raw)
            self.run['critical_settings'][name] = dict(
                self.binding, path=path.name, sha256=verify.sha(raw), group_nonce=self.nonce,
                nonce=f'{number:02x}' * 16, source_is_hardware=False,
                acquisition_phase='PRE_INSTALL' if name == 'before' else 'POST_INSTALL')
        self.run_path = self.group / 'capture-run.json'
        self.save_run()

    def save_run(self):
        self.run_path.write_text(json.dumps(self.run))

    def make_capture(self, name, raw, nonce):
        folder = self.group / name
        (folder / 'capture').mkdir(parents=True)
        target = folder / 'capture' / (name + '.bin')
        target.write_bytes(raw)
        count, expected, source_path, kind = verify.PROFILES[name]
        digest = verify.sha(raw)
        native = dict(version=1, phase=6, error=0, euid=0, pid=30, ppid=1, loader_pid=20,
                      cleanup=0, flags=63, offset=count, chunks=(count + 8388607) // 8388608,
                      first_sha256=digest, second_sha256=digest)
        ready = dict(native, phase=1, flags=3)
        report = dict(profile=name, name=name, capture=str(target), bytes=count, sha256=digest,
                      nonce=nonce, source_is_hardware=False, native=native,
                      source_path=source_path, targetpath=source_path, source_kind=kind, expected_sha256=expected)
        (folder / 'firmware-capture.json').write_text(json.dumps(report))
        (folder / 'completed.json').write_text(json.dumps(dict(partition=name, bytes=count,
                                                               backup=str(target), native=native)))
        (folder / 'launch-and-ready.json').write_text(json.dumps(dict(loader_pid=20, ready=ready)))
        (folder / 'capture/status.json').write_text(json.dumps(dict(
            nonce=nonce, sha256=digest, partition=name, bytes=count, state='TWO_READS_MATCHED',
            source_is_hardware=False, source_reads_equal_at_capture=True, hardware_source_read_verified=False)))
        self.refresh_report(name)

    def refresh_report(self, name):
        relative = name + '/firmware-capture.json'
        self.run['captures'][name] = dict(self.binding, path=relative,
                                         sha256=verify.sha((self.group / relative).read_bytes()), group_nonce=self.nonce)

    def call(self, **kwargs):
        options = dict(self.binding, group_nonce=self.nonce, plain_path=self.plain, factory_p1_path=self.factory)
        options.update(kwargs)
        return verify.verify_capture_run(self.run_path, **options)

    def rejected(self, **kwargs):
        report = self.call(**kwargs)
        self.assertFalse(report['all_passed'], report)
        self.assertTrue(report['pending'])
        return report

    def test_real_stdlib_fat_bk4_tar_pipeline_passes_model_without_hardware_upgrade(self):
        result = self.call()
        self.assertTrue(result['all_passed'], result)
        self.assertFalse(result['source_is_hardware'])
        self.assertEqual(result['verification_scope'], 'FIRMWARE_FILES_AND_CRITICAL_SETTINGS')
        for field in ('photo_verified', 'video_verified', 'actual_NOR_verified', 'other_MCU_verified',
                      'whole_device_functional_installation_verified'):
            self.assertFalse(result[field])
        self.assertFalse(result['checks']['critical_settings']['all_calibration_verified'])
        self.assertFalse(result['checks']['critical_settings']['all_attribute_merge_semantics_verified'])

    def test_missing_capture_and_wrong_group_or_body_are_pending(self):
        for key, value in [('group_nonce', 'ff' * 16), ('plan_sha256', 'c' * 64),
                           ('body_sha256', 'c' * 64), ('model', 'other'), ('normal_body_verified', False)]:
            original = self.run[key]
            self.run[key] = value
            self.save_run()
            self.rejected()
            self.run[key] = original
        self.run['captures'].pop('post_p1')
        self.save_run()
        self.rejected()

    def test_run_cannot_promote_model_source_to_hardware(self):
        self.run['source_is_hardware'] = True
        self.save_run()
        report = self.rejected()
        self.assertFalse(report['source_is_hardware'])
        self.rejected(source_is_hardware=True)  # Per-capture model flags still disagree.

    def test_nonce_reuse_and_stale_group_reference_fail(self):
        self.run['critical_settings']['after']['nonce'] = '02' * 16
        self.save_run()
        self.rejected()
        self.run['critical_settings']['after']['nonce'] = '06' * 16
        self.run['captures']['post_app']['group_nonce'] = 'ff' * 16
        self.save_run()
        self.rejected()

    def test_missing_wrong_or_swapped_settings_acquisition_phase_rejected(self):
        references = self.run['critical_settings']
        for name in ('before', 'after'):
            original = references[name]['acquisition_phase']
            for phase in (None, 'UNKNOWN', 'POST_INSTALL' if name == 'before' else 'PRE_INSTALL'):
                with self.subTest(name=name, phase=phase):
                    if phase is None:
                        references[name].pop('acquisition_phase', None)
                    else:
                        references[name]['acquisition_phase'] = phase
                    self.save_run()
                    result = self.rejected()
                    self.assertIn('Settings acquisition phase mismatch', result['pending'][0]['reason'])
            references[name]['acquisition_phase'] = original
        references['before']['acquisition_phase'], references['after']['acquisition_phase'] = (
            references['after']['acquisition_phase'], references['before']['acquisition_phase'])
        self.save_run()
        result = self.rejected()
        self.assertIn('Settings acquisition phase mismatch', result['pending'][0]['reason'])

    def test_native_phase_identity_and_two_source_hashes_rejected(self):
        path = self.group / 'post_app/firmware-capture.json'
        original = json.loads(path.read_bytes())
        completed = self.group / 'post_app/completed.json'
        completed_original = json.loads(completed.read_bytes())
        for key, value in [('phase', 5), ('flags', 31), ('pid', 20), ('pid', 99),
                           ('euid', 1), ('ppid', 2), ('second_sha256', '0' * 64)]:
            with self.subTest(key=key, value=value):
                report = json.loads(json.dumps(original))
                report['native'][key] = value
                path.write_text(json.dumps(report))
                completed.write_text(json.dumps(dict(completed_original, native=report['native'])))
                self.refresh_report('post_app')
                self.save_run()
                self.rejected()

    def test_capture_report_digest_and_file_corruption_fail(self):
        path = self.group / 'post_app/capture/post_app.bin'
        path.write_bytes(b'APP-content')
        self.rejected()
        self.refresh_report('post_app')
        self.run['captures']['post_app']['sha256'] = '0' * 64
        self.save_run()
        self.rejected()

    def test_capture_path_escape_symlink_and_candidate_hardlink_fail(self):
        target = self.group / 'post_app/capture/post_app.bin'
        outside = self.host / 'offline-app.bin'
        outside.write_bytes(target.read_bytes())
        target.unlink()
        target.symlink_to(outside)
        self.rejected()
        target.unlink()
        os.link(outside, target)
        self.rejected(offline_candidates=[outside])
        report_path = self.group / 'post_app/firmware-capture.json'
        report = json.loads(report_path.read_bytes())
        report['capture'] = str(outside)
        report_path.write_text(json.dumps(report))
        self.refresh_report('post_app')
        self.save_run()
        self.rejected()

    def test_p1_content_semantics_reject_wrong_initrd_kernel_checksum_or_region(self):
        images = [fat_image(b'wrong-initrd', self.kernel), fat_image(self.initrd, b'wrong-kernel'),
                  fat_image(self.initrd, self.kernel, dat3=b'FAIL')]
        broken = bytearray(self.p1)
        fs = verify._fat(self.p1)
        at = fs.offset(fs.locate('P1CHKSUM')[1])
        broken[at] ^= 1
        images.append(bytes(broken))
        for raw in images:
            with self.subTest(digest=verify.sha(raw)):
                folder = self.group / 'post_p1'
                import shutil
                shutil.rmtree(folder)
                self.make_capture('post_p1', raw, '04' * 16)
                self.save_run()
                self.rejected()

    def test_critical_condition_slots_colour_attrs_and_structure_rejected(self):
        mutations = [dict(self.values, **{}) for _ in range(4)]
        mutations[0][0x004b0001] = b'\x01'
        mutations[1][SLOTS[0]] = b'\xff'
        mutations[2][COLOUR_KEYS[0]] = b'bad-cc'
        mutations[3][0x004b0001] = b'\x02\x00'
        after = self.group / 'after.bk4'
        for values in mutations:
            after.write_bytes(bk4(values))
            self.run['critical_settings']['after']['sha256'] = verify.sha(after.read_bytes())
            self.save_run()
            self.rejected()
        after.write_bytes(bk4(self.values, attrs=8))
        self.run['critical_settings']['after']['sha256'] = verify.sha(after.read_bytes())
        self.save_run()
        self.rejected()

    def test_bk4_checksum_damage_is_not_accepted(self):
        bad = bytearray(self.template)
        bad[-1] ^= 1
        with self.assertRaises(ValueError):
            record_map(bytes(bad))

    def test_pinned_inputs_missing_or_changed_never_fake_acceptance(self):
        self.plain.write_bytes(b'not a package')
        self.rejected()
        self.factory.unlink()
        self.rejected()


if __name__ == '__main__':
    unittest.main()
