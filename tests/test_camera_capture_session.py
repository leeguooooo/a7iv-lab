"""Temporary local groups and injected models; no SDK or device actions."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import camera_capture_session as capture
from camera_device_lease import CameraDeviceLease
from camera_install_journal import InstallJournal
from install_model_fixture import formal_complete


def pdt_fixture():
    raw = bytearray(capture.PDT_BYTES)
    for base in (0, 512):
        raw[base + 4:base + 8] = b'\xaa' * 4
        raw[base + 12:base + 16] = b'BK4\0'
        struct.pack_into('<III', raw, base + 16, 0, 0, 256)
        checksum = sum(raw[base:base + 32]) + sum(raw[base + 36:base + 256])
        struct.pack_into('<I', raw, base + 32, checksum)
    return bytes(raw)


RAW = pdt_fixture()


class CaptureSessionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.group = self.root / 'group'
        self.plan, self.body = 'a' * 64, 'b' * 64
        self.journal = InstallJournal.create(self.root / 'journals', 'attempt',
            plan_sha256=self.plan, body_sha256=self.body, model='ILCE-7M4')
        self.lease = CameraDeviceLease('capture-model', lock_path=self.root / 'model.lock')
        self.lease.__enter__()
        self.addCleanup(self.lease.__exit__, None, None, None)
        self.trace = []
        self.device = object()
        self.reader = Mock(side_effect=self.read)
        self.capturer = Mock(side_effect=self.collect)
        self.stop_error = None
        self.emit_stop = True
        self.emit_normal = True

    def read(self, device, **kwargs):
        self.assertIs(device, self.device)
        self.trace.append('pdt')
        return RAW

    def collect(self, device, name, evidence, **kwargs):
        self.assertIs(device, self.device)
        self.assertFalse(kwargs['source_is_hardware'])
        self.trace.append(name)
        evidence.mkdir()
        nonce = {'post_app': '11', 'post_cp': '22', 'post_p1': '33'}[name] * 16
        result = dict(profile=name, name=name, nonce=nonce, source_is_hardware=False)
        (evidence / 'firmware-capture.json').write_text(json.dumps(result))
        return result

    def model_session(self, expected, callback, *, record_event, set_stage):
        self.assertEqual(expected, self.body)
        self.trace.append('session')
        if self.emit_normal:
            record_event({'model': 'ILCE-7M4', 'body_matched': True})
        result = callback(self.device)
        self.trace.append('STOP')
        if self.stop_error:
            raise self.stop_error
        if self.emit_stop:
            record_event({'event': 'STOP_RESPONSE', 'mode': 'service', 'success': True})
        return result

    def before(self, **overrides):
        options = dict(plan_sha256=self.plan, journal=self.journal, lease=self.lease,
                       run_session=self.model_session, pdt_reader=self.reader, group_nonce='cc' * 16)
        options.update(overrides)
        return capture.capture_settings_before(self.body, self.group, **options)

    def complete(self):
        formal_complete(self, self.journal)

    def after(self, **overrides):
        options = dict(plan_sha256=self.plan, journal=self.journal, lease=self.lease,
                       run_session=self.model_session, pdt_reader=self.reader, capture_fn=self.capturer)
        options.update(overrides)
        return capture.capture_after_install(self.body, self.group, **options)

    def test_order_bindings_phase_and_publish_only_after_known_stop(self):
        before = self.before()
        self.assertEqual(before['before']['acquisition_phase'], 'PRE_INSTALL')
        self.assertEqual(self.journal.state, 'PLANNED')
        self.complete()
        self.trace.clear()
        result = self.after()
        self.assertEqual(self.trace, ['session', 'post_app', 'post_cp', 'post_p1', 'pdt', 'STOP'])
        self.assertEqual(self.journal.state, 'DEVICE_COMPLETION_REPORTED')
        manifest = json.loads(Path(result['path']).read_text())
        self.assertEqual(manifest['schema'], 'camera-postinstall-capture-run/1')
        self.assertFalse(manifest['source_is_hardware'])
        self.assertTrue(manifest['normal_body_verified'])
        self.assertEqual(manifest['critical_settings']['after']['acquisition_phase'], 'POST_INSTALL')
        nonces = {manifest['group_nonce']}
        for name, reference in manifest['captures'].items():
            self.assertFalse(Path(reference['path']).is_absolute())
            report = self.group / reference['path']
            self.assertEqual(reference['sha256'], hashlib.sha256(report.read_bytes()).hexdigest())
            self.assertEqual(reference['plan_sha256'], self.plan)
            self.assertEqual(reference['body_sha256'], self.body)
            self.assertEqual(reference['group_nonce'], manifest['group_nonce'])
            nonce = json.loads(report.read_text())['nonce']
            self.assertNotIn(nonce, nonces); nonces.add(nonce)
        for reference in manifest['critical_settings'].values():
            self.assertNotIn(reference['nonce'], nonces); nonces.add(reference['nonce'])
        self.assertEqual(len(nonces), 6)

    def test_capture_exception_makes_no_further_capture_pdt_or_stop(self):
        self.before(); self.complete(); self.trace.clear()
        error = OSError('model unknown transport outcome')
        self.capturer.side_effect = lambda device, name, *a, **k: self.collect(device, name, *a, **k) if name == 'post_app' else (_ for _ in ()).throw(error)
        with self.assertRaises(OSError) as caught:
            self.after()
        self.assertIs(caught.exception, error)
        self.assertEqual(self.trace, ['session', 'post_app'])
        self.assertEqual(self.journal.state, 'STOPPED_UNKNOWN')
        self.assertFalse((self.group / 'capture-run.json').exists())
        self.assertTrue((self.group / 'capture-after-stopped.json').exists())

    def test_unknown_stop_never_publishes_capture_run(self):
        self.before(); self.complete(); self.trace.clear()
        self.stop_error = OSError('model STOP unknown')
        with self.assertRaises(OSError) as caught:
            self.after()
        self.assertIs(caught.exception, self.stop_error)
        self.assertEqual(self.journal.state, 'STOPPED_UNKNOWN')
        self.assertFalse((self.group / 'capture-run.json').exists())

    def test_return_without_known_stop_is_rejected(self):
        self.emit_stop = False
        with self.assertRaisesRegex(ValueError, 'Known service STOP'):
            self.before()
        self.assertFalse((self.group / 'before-reference.json').exists())
        self.assertEqual(self.journal.state, 'STOPPED_UNKNOWN')

    def test_unverified_normal_context_prevents_every_read(self):
        self.emit_normal = False
        with self.assertRaisesRegex(ValueError, 'verified normal-body'):
            self.before()
        self.reader.assert_not_called()
        self.assertEqual(self.trace, ['session'])

    def test_before_forbidden_once_ram_window_ready(self):
        for state in ('SD_STAGE_INTENT', 'SD_STAGED', 'READY_FOR_CONFIRMATION'):
            self.journal.advance(state)
        original = self.journal.events
        with self.assertRaisesRegex(ValueError, 'declared journal phase'):
            self.before()
        self.assertEqual(self.journal.events, original)
        self.assertEqual(self.trace, [])
        self.assertFalse((self.group / 'capture-before-stopped.json').exists())
        self.assertEqual(self.journal.state, 'READY_FOR_CONFIRMATION')

    def test_after_forbidden_before_device_completion(self):
        self.before(); self.trace.clear()
        original = self.journal.events
        with self.assertRaisesRegex(ValueError, 'declared journal phase'):
            self.after()
        self.assertEqual(self.trace, [])
        self.assertEqual(self.journal.events, original)

    def test_wrong_plan_is_zero_session_and_preserves_journal(self):
        original = self.journal.events
        with self.assertRaisesRegex(ValueError, 'plan/body/model mismatch'):
            self.before(plan_sha256='d' * 64)
        self.assertEqual(self.trace, [])
        self.assertEqual(self.journal.events, original)
        self.assertEqual(InstallJournal.open(self.journal.session_dir).events, original)
        self.assertFalse(self.group.exists())

    def test_after_wrong_plan_is_zero_session_and_preserves_journal(self):
        self.before(); self.complete(); self.trace.clear()
        original = self.journal.events
        files = {p.name: p.read_bytes() for p in self.group.iterdir()}
        with self.assertRaisesRegex(ValueError, 'plan/body/model mismatch'):
            self.after(plan_sha256='d' * 64)
        self.assertEqual(self.trace, [])
        self.assertEqual(self.journal.events, original)
        self.assertEqual({p.name: p.read_bytes() for p in self.group.iterdir()}, files)

    def test_existing_after_intent_is_zero_session_and_never_removed(self):
        self.before(); self.complete(); self.trace.clear()
        intent = self.group / 'after-attempt.json'
        intent.write_bytes(b'{"partial":')
        original = self.journal.events
        files = {p.name: p.read_bytes() for p in self.group.iterdir()}
        with self.assertRaises(FileExistsError):
            self.after()
        self.assertEqual(self.trace, [])
        self.assertEqual(self.journal.events, original)
        self.assertEqual({p.name: p.read_bytes() for p in self.group.iterdir()}, files)

    def test_existing_group_is_zero_session_and_untouched(self):
        self.group.mkdir()
        marker = self.group / 'legal-evidence.json'
        marker.write_bytes(b'preserve exact bytes')
        original = self.journal.events
        with self.assertRaises(FileExistsError):
            self.before()
        self.assertEqual(self.trace, [])
        self.assertEqual(self.journal.events, original)
        self.assertEqual(list(self.group.iterdir()), [marker])
        self.assertEqual(marker.read_bytes(), b'preserve exact bytes')

    def test_after_local_binding_rejection_preserves_group_and_journal(self):
        self.before(); self.complete(); self.trace.clear()
        descriptor = self.group / 'group.json'
        value = json.loads(descriptor.read_text())
        value['plan_sha256'] = 'd' * 64
        descriptor.write_text(json.dumps(value))
        original_files = {str(p.relative_to(self.group)): p.read_bytes() for p in self.group.rglob('*') if p.is_file()}
        original = self.journal.events
        with self.assertRaisesRegex(ValueError, 'Group binding mismatch'):
            self.after()
        self.assertEqual(self.trace, [])
        self.assertEqual(self.journal.events, original)
        self.assertEqual({str(p.relative_to(self.group)): p.read_bytes() for p in self.group.rglob('*') if p.is_file()}, original_files)

    def test_partial_intent_write_is_retained_without_journal_poison(self):
        original = self.journal.events
        actual = capture.durable_new
        error = OSError('model fsync failure with partial local intent')
        def fail(path, value):
            if Path(path).name == 'before-attempt.json':
                Path(path).write_bytes(b'{"partial":')
                raise error
            return actual(path, value)
        with patch.object(capture, 'durable_new', side_effect=fail):
            with self.assertRaises(OSError) as caught:
                self.before()
        self.assertIs(caught.exception, error)
        self.assertEqual(self.trace, [])
        self.assertEqual(self.journal.events, original)
        self.assertEqual((self.group / 'before-attempt.json').read_bytes(), b'{"partial":')
        self.assertTrue((self.group / 'group.json').is_file())
        self.assertFalse((self.group / 'capture-before-stopped.json').exists())

    def test_saved_json_cannot_promote_a_model_to_hardware(self):
        self.before(); self.complete(); self.trace.clear()
        path = self.group / 'before-reference.json'
        value = json.loads(path.read_text()); value['source_is_hardware'] = True
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, 'trusted source context'):
            self.after()
        self.assertEqual(self.trace, [])

    def test_before_digest_tamper_blocks_all_after_requests(self):
        self.before(); self.complete(); self.trace.clear()
        (self.group / 'before.bk4').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'Before PDT changed'):
            self.after()
        self.assertEqual(self.trace, [])

    def test_bk4_parse_failure_never_sends_stop(self):
        self.reader.side_effect = None
        self.reader.return_value = bytes(capture.PDT_BYTES)
        with self.assertRaisesRegex(ValueError, 'BK4'):
            self.before()
        self.assertEqual(self.trace, ['session'])
        self.assertFalse((self.group / 'before-reference.json').exists())

    def test_report_nonce_reuse_stops_before_next_profile(self):
        self.before(); self.complete(); self.trace.clear()
        collect = self.collect
        def reused(device, name, evidence, **kwargs):
            value = collect(device, name, evidence, **kwargs)
            value['nonce'] = 'cc' * 16
            (evidence / 'firmware-capture.json').write_text(json.dumps(value))
            return value
        self.capturer.side_effect = reused
        with self.assertRaisesRegex(ValueError, 'nonce invalid/reused'):
            self.after()
        self.assertEqual(self.trace, ['session', 'post_app'])


class BoundedPDTTests(unittest.TestCase):
    def test_exact_wire_command_bounded_sink_and_restore_only_host_pointer(self):
        original = object()
        device = SimpleNamespace(driver=original)
        def send(got, pfunc, data, sink):
            self.assertIs(got, device)
            self.assertEqual((pfunc, data, sink.maximum),
                             (0x40, struct.pack('<HH', 0x603, 5) + b'\x01', capture.PDT_BYTES))
            self.assertIsNot(got.driver, original)
            sink.write(RAW)
            return 0, None
        self.assertEqual(capture.read_pdt_bounded(device, send_packet=send), RAW)
        self.assertIs(device.driver, original)

    def test_wrong_response_size_oversize_or_parser_fail_are_terminal(self):
        for response, raw in ((1, RAW), (0, RAW[:-1]), (0, RAW + b'x'), (0, bytes(len(RAW)))):
            with self.subTest(response=response, size=len(raw)):
                device = SimpleNamespace(driver=object())
                original = device.driver
                calls = []
                def send(*args):
                    calls.append('packet')
                    args[-1].write(raw)
                    return response, None
                with self.assertRaises(ValueError):
                    capture.read_pdt_bounded(device, send_packet=send)
                self.assertEqual(calls, ['packet'])
                self.assertIs(device.driver, original)

    def test_declared_oversize_stops_before_payload_read(self):
        class Header:
            size = 8
            @staticmethod
            def pack(**kw):
                return struct.pack('<IHH', kw['size'], kw['sequence'], kw['response'])
            @staticmethod
            def unpack(raw):
                size, sequence, response = struct.unpack('<IHH', raw)
                return SimpleNamespace(size=size, sequence=sequence, response=response)
        class Driver:
            def __init__(self):
                self.reads, self.writes = 0, 0
            def getId(self):
                return 0x054c, 0x0336
            def write(self, raw):
                self.writes += 1
                return len(raw)
            def read(self, count):
                self.reads += 1
                if self.reads != 1:
                    raise AssertionError('Payload must never be requested')
                return Header.pack(size=capture.PDT_BYTES + 1, sequence=0, response=0)
        driver = Driver()
        device = SimpleNamespace(driver=driver, _sequence=0, SenserPacketHeader=Header,
            SenserMaxSize=1048576, SenserMinSize=8, SenserChunkSize=32768)
        with self.assertRaisesRegex(ValueError, 'Declared response exceeds'):
            capture.read_pdt_bounded(device)
        self.assertEqual((driver.reads, driver.writes), (1, 1))
        self.assertIs(device.driver, driver)


if __name__ == '__main__':
    unittest.main()
