"""Temporary host fixtures, explicit simulated channel; no SDK or device actions."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from camera_device_lease import CameraDeviceLease
from camera_install_journal import InstallJournal, JournalError, assert_no_pending_installs
from camera_operation_guard import assert_operation_allowed
import camera_readonly_identity as ro

CONTRACT = b'"""Pure host bounded decoder. No camera/SDK/device imports."""\nimport re,struct\nPATHS=(\'/proc/version\',\'/proc/cmdline\',\'/proc/modules\',\'/proc/interrupts\',\'/proc/self/status\',\'/proc/iomem\',\'/sys/module/liro/parameters/adr\',\'/sys/module/liro/initstate\',\'/proc/sys/kernel/modules_disabled\',\'/proc/sys/kernel/module_sig_enforce\',\'/sys/devices/system/cpu/online\')\nLIMITS=(4096,8192,32768,65536,8192,65536,4096,256,64,64,4096)\nHEADER=struct.Struct(\'<8s16sIIqqII36s36s\');ENTRY=struct.Struct(\'<IiII\')\ndef require(ok,message):\n if not ok:raise ValueError(message)\ndef decode(raw,nonce):\n require(isinstance(raw,bytes) and len(raw)<=200000 and len(raw)>=HEADER.size,\'bounded complete header required\')\n require(isinstance(nonce,str) and re.fullmatch(\'[0-9a-f]{32}\',nonce),\'explicit nonce required\')\n magic,n,v,phase,err,euid,count,res,before,after=HEADER.unpack_from(raw)\n require(magic==b\'ROID0001\' and n.hex()==nonce and v==1 and phase==7 and err==0 and euid==0 and count==11 and res==0,\'schema/nonce/success inconsistency\')\n valid=lambda b:re.fullmatch(b\'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\',b) and b!=b\'00000000-0000-0000-0000-000000000000\'\n require(valid(before) and before==after,\'required exact boot epoch absent/changed\')\n offset=HEADER.size;entries=[];seen=set()\n for _ in range(count):\n  require(offset+ENTRY.size<=len(raw),\'truncated entry\');index,status,length,limit=ENTRY.unpack_from(raw,offset);offset+=ENTRY.size\n  require(index<len(PATHS) and index not in seen,\'unknown/duplicate path\');seen.add(index)\n  require(limit==LIMITS[index] and length<=limit and (status==0 or (-4095<=status<0 and length==0)),\'entry status/limit inconsistency\')\n  require(offset+length<=len(raw),\'truncated value\');value=raw[offset:offset+length];offset+=length\n  entries.append(dict(index=index,path=PATHS[index],status=status,known=status==0,raw_hex=value.hex()))\n require(offset==len(raw),\'trailing bytes\')\n return dict(scope=\'RO_METADATA\',nonce=nonce,boot_epoch=before.decode(),entries=entries,physical_origin_proven=False,full_image_admission=False)\n'


class SimulatedChannel:
    def __init__(self, device, result):
        self.device = device
        self.nonce = bytes.fromhex(ro.NONCE)
        self.directory = '/tmp_wbshd/roid_' + ro.NONCE
        self.healthy = True
        self.module_attempted = self.start_attempted = False
        self.calls = []
        self.result = result
        self.fault = None

    def assert_job_absent(self):
        self.calls.append('job')
        if self.fault == 'job':
            raise ValueError('occupied')

    def read_loader(self, name):
        self.calls.append(name)
        if self.fault == 'loader':
            raise OSError('unknown read')
        if name == ro.SLOT:
            return b'occupied' if self.fault == 'slot' else None
        return b'synthetic-library'

    def upload_once(self, module, expected, path):
        self.calls.append('upload')
        self.module_attempted = True
        ro.durable_new(path, dict(simulated=True))
        if self.fault == 'upload':
            raise OSError('unknown upload')

    def start_once(self, folder):
        self.calls.append('START')
        self.start_attempted = True
        if self.fault == 'START':
            raise OSError('unknown START')

    def read(self, name, missing=False):
        self.calls.append(name)
        if self.fault == 'read':
            raise OSError('unknown read')
        if name == 'exec_failure':
            return b'failed' if self.fault == 'exec' else None
        if name == 'launch':
            return ro.struct.pack('<8s16s10q', b'M4BOOT01', self.nonce, 1, 3, 0, 0, 123, 0, 55, 55, 0, 8 * 1024 * 1024)
        if name == 'ready':
            nonce = bytes(16) if self.fault == 'nonce' else self.nonce
            raw = ro.HEADER.pack(b'ROID0001', nonce, 1, 1, 0, 0, 0, 0, bytes(36), bytes(36))
            return raw[:-1] if self.fault == 'ready' else raw
        if name == 'result':
            if self.fault == 'early':
                return self.result
            if not self.start_attempted or self.fault == 'timeout':
                return None
            return self.result[:-1] if self.fault == 'result' else self.result
        raise AssertionError(name)


class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.evidence = self.root / 'evidence'
        self.evidence.mkdir()
        self.kit = self.root / 'kit'
        self.kit.mkdir()
        (self.kit / 'contract.py').write_bytes(CONTRACT)
        self.assertEqual(ro.sha(CONTRACT), '2fdcb6bd741970d5c86f6c93867393b085cc14b10f50c8dd4fb8ee286ee12c7e')
        self.assets = ro.Assets(self.kit, self.root)
        reference = dict(scope=ro.SCOPE, nonce=ro.NONCE, job_dir='/tmp_wbshd/roid_' + ro.NONCE,
                         kit_dir=str(self.kit), source_root=str(self.root), freeze_sha256=ro.FREEZE_SHA256,
                         worker_sha256=ro.WORKER_SHA256, module_sha256=ro.MODULE_SHA256,
                         contract_sha256=ro.sha(CONTRACT), host_sha256=ro.sha(Path(ro.__file__).read_bytes()), host_sources=ro.host_source_bindings())
        # Artifact transport is simulated; preflight is mocked explicitly. The
        # pinned real decoder bytes are used to test the actual raw contract.
        self.prepared = ro.Prepared(self.assets, ro.canonical(reference), b'synthetic-module', CONTRACT)
        self.journal = InstallJournal.create(self.root / 'sessions', 'ro-model',
                                            plan_sha256='a'*64, body_sha256='b'*64, model='synthetic-RO')
        self.lease = CameraDeviceLease('ro-simulation', lock_path=self.root / 'lease')
        self.lease.__enter__()
        self.addCleanup(lambda: self.lease.__exit__(None, None, None) if self.lease.fd is not None else None)
        self.context = ro.CaptureContext('synthetic-camera')
        self.device = object()
        boot = b'11111111-2222-3333-4444-555555555555'
        self.result = ro.HEADER.pack(b'ROID0001', bytes.fromhex(ro.NONCE), 1, 7, 0, 0, 11, 0, boot, boot)
        limits = (4096,8192,32768,65536,8192,65536,4096,256,64,64,4096)
        self.result += b''.join(ro.struct.pack('<IiII', i, -2, 0, limit) for i, limit in enumerate(limits))
        self.channel = SimulatedChannel(self.device, self.result)
        for p in (patch.object(ro, 'CLAIMS', self.root / 'claims'),
                  patch.object(ro, 'DEFAULT_SESSIONS', self.root / 'global-sessions'),
                  patch.object(ro, 'preflight_assets', return_value=self.prepared),
                  patch.dict(ro.LIBRARIES, {'/lib/synthetic': ro.sha(b'synthetic-library')}, clear=True)):
            p.start()
            self.addCleanup(p.stop)
        bound = ro.context_binding(self.context, self.device, self.lease, self.journal, ('PLANNED',))
        self.approval = dict(operator='SIMULATED TEST OPERATOR', explicit_approval=True,
                             binding=ro.approval_payload(self.prepared, bound))
        self.reservation = None
        self.ticks = 0

    def reserve(self):
        self.reservation = ro.reserve_assets(self.prepared, self.evidence, lease=self.lease,
                journal=self.journal, device=self.device, context=self.context, approval=self.approval)

    def invoke(self, **changes):
        if self.reservation is None:
            self.reserve()
        def sleep(value):
            self.ticks += value
        args = dict(assets=self.assets, reservation=self.reservation, lease=self.lease,
                    journal=self.journal, context=self.context, approval=self.approval,
                    channel=self.channel, clock=lambda: self.ticks, sleep=sleep)
        args.update(changes)
        return ro.capture_authenticated(self.device, self.evidence, **args)

    def test_simulated_success_is_only_observation(self):
        receipt = self.invoke()
        self.assertEqual(self.journal.state, ro.OBSERVED)
        self.assertFalse(receipt['source_is_hardware'])
        self.assertFalse(receipt['identity_admission'])
        self.assertFalse(receipt['firmware_admission'])
        self.assertTrue(all(not e['known'] for e in receipt['decoded']['entries']))
        self.assertEqual(InstallJournal.open(self.journal.session_dir).state, ro.OBSERVED)
        assert_no_pending_installs(self.root / 'sessions')
        self.assertEqual(self.channel.calls.count('upload'), 1)
        self.assertEqual(self.channel.calls.count('START'), 1)

    def test_bad_approval_has_no_io_or_may(self):
        for approval in ({}, dict(self.approval, explicit_approval=1),
                         dict(self.approval, binding={}), dict(self.approval, operator='')):
            with self.subTest(approval=approval):
                with self.assertRaises(ValueError):
                    ro.reserve_assets(self.prepared, self.evidence, lease=self.lease,
                            journal=self.journal, device=self.device, context=self.context, approval=approval)
        self.assertEqual(self.channel.calls, [])
        self.assertEqual(self.journal.state, 'PLANNED')

    def test_bad_nonce_rejected_before_io(self):
        for nonce in ('0'*32, 'A'*32, 'a'*30, 'a'*34, None):
            with self.assertRaises(ValueError):
                ro.valid_nonce(nonce)
        self.assertEqual(self.channel.calls, [])

    def test_bad_target_or_history_rejected_before_io(self):
        self.reserve()
        with self.assertRaises(ValueError):
            self.invoke(context=ro.CaptureContext('another-target'))
        self.assertEqual(self.channel.calls, [])

    def test_approval_is_stable_across_lease_identity(self):
        stable = self.approval['binding']
        self.assertNotIn('lease_identity', stable['context'])
        self.reserve()
        self.assertIn('lease_identity', self.reservation['record']['context'])

    def test_changed_host_binding_rejected_before_io(self):
        self.reserve()
        reference = self.prepared.reference
        reference['host_sha256'] = '0' * 64
        changed = ro.Prepared(self.assets, ro.canonical(reference), self.prepared.module, CONTRACT)
        with patch.object(ro, 'preflight_assets', return_value=changed):
            with self.assertRaises(ValueError):
                self.invoke()
        self.assertEqual(self.channel.calls, [])

    def test_stale_journal_rejected_before_io(self):
        self.reserve()
        reopened = InstallJournal.open(self.journal.session_dir)
        reopened.advance('STOPPED_UNKNOWN')
        with self.assertRaises(ValueError):
            self.invoke()
        self.assertEqual(self.channel.calls, [])

    def test_json_cannot_assert_hardware(self):
        with self.assertRaises(ValueError):
            self.invoke(context={'source_is_hardware': True})
        self.assertEqual(self.channel.calls, [])

    def test_fake_hardware_rejected_by_canonical_context(self):
        with self.assertRaises(ValueError):
            self.invoke(context=ro.CaptureContext('synthetic-camera', 'HARDWARE', lambda *_: True))
        self.assertEqual(self.channel.calls, [])

    def test_nonce_can_only_be_reserved_once(self):
        self.reserve()
        with self.assertRaises(ValueError):
            self.reserve()
        self.assertEqual(self.channel.calls, [])

    def test_tampered_reservation_has_no_io(self):
        self.reserve()
        self.reservation['record']['context']['target_id'] = 'mixed-target'
        with self.assertRaises(ValueError):
            self.invoke()
        self.assertEqual(self.channel.calls, [])

    def test_symlink_evidence_rejected_before_io(self):
        self.reserve()
        link = self.root / 'link'
        link.symlink_to(self.evidence, target_is_directory=True)
        with self.assertRaises(ValueError):
            ro.capture_authenticated(self.device, link, assets=self.assets, reservation=self.reservation,
                    lease=self.lease, journal=self.journal, context=self.context, approval=self.approval,
                    channel=self.channel)
        self.assertEqual(self.channel.calls, [])

    def test_uncertain_operations_stop_without_retry_and_keep_global_barrier(self):
        self.channel.fault = 'upload'
        with self.assertRaises(OSError):
            self.invoke()
        self.assertEqual(self.journal.state, ro.UNKNOWN)
        self.lease.__exit__(None, None, None)
        for check in (lambda: assert_no_pending_installs(self.root / 'sessions'),
                      lambda: assert_operation_allowed(sessions_root=self.root / 'sessions'),
                      lambda: InstallJournal.create(self.root / 'sessions', 'later',
                               plan_sha256='c'*64, body_sha256='d'*64, model='synthetic')):
            with self.assertRaises(JournalError):
                check()
        self.assertEqual(self.channel.calls.count('upload'), 1)
        with self.assertRaises(ValueError):
            self.invoke()
        self.assertEqual(self.channel.calls.count('upload'), 1)

    def test_may_durable_before_first_read(self):
        original = self.channel.assert_job_absent
        def check():
            self.assertEqual(InstallJournal.open(self.journal.session_dir).state, ro.MAY)
            original()
        self.channel.assert_job_absent = check
        self.invoke()

    def test_invalid_publication_preserved_before_decode(self):
        self.channel.fault = 'nonce'
        with self.assertRaises(ValueError):
            self.invoke()
        files = list(self.evidence.glob('*-ready-raw.json'))
        self.assertEqual(len(files), 1)
        self.assertEqual(bytes.fromhex(json.loads(files[0].read_text())['raw_hex'])[8:24], bytes(16))
        self.assertEqual(self.journal.state, ro.UNKNOWN)
        self.assertNotIn('START', self.channel.calls)

    def test_raw_publication_failure_blocks_start(self):
        original = ro.durable_new
        def fail(path, value):
            if str(path).endswith('-ready-raw.json'):
                raise OSError('host persistence failure')
            return original(path, value)
        with patch.object(ro, 'durable_new', side_effect=fail):
            with self.assertRaises(OSError):
                self.invoke()
        self.assertEqual(self.journal.state, ro.UNKNOWN)
        self.assertNotIn('START', self.channel.calls)

    def test_may_append_failure_does_no_io(self):
        self.reserve()
        with patch.object(self.journal, 'advance', side_effect=OSError('fsync')):
            with self.assertRaises(OSError):
                self.invoke()
        self.assertEqual(self.channel.calls, [])

    def test_observed_receipt_cannot_be_relabelled_hardware(self):
        receipt = self.invoke()
        receipt['source_is_hardware'] = True
        with self.assertRaises(ValueError):
            ro.validate_receipt(receipt, receipt['operation'])

    def test_changed_bound_decoder_cannot_reopen_observed(self):
        self.invoke()
        (self.kit / 'contract.py').write_bytes(b'changed')
        with self.assertRaises(ValueError):
            InstallJournal.open(self.journal.session_dir)

    def test_ro_unknown_cannot_escape_through_old_cancel_or_reconciliation(self):
        self.channel.fault = 'upload'
        with self.assertRaises(OSError):
            self.invoke()
        for state in ('STOPPED_UNKNOWN', 'CANCELLED_BEFORE_DEVICE_WRITE', 'SD_STAGE_INTENT',
                      'RAM_MAY_BE_ACTIVE', 'FLASH_MAY_HAVE_STARTED'):
            with self.assertRaises(JournalError):
                self.journal.advance(state)

    def test_other_global_unknown_blocks_before_io(self):
        blocker = InstallJournal.create(self.root / 'global-sessions', 'unknown',
                    plan_sha256='c'*64, body_sha256='d'*64, model='synthetic')
        blocker.advance('STOPPED_UNKNOWN')
        with self.assertRaises(JournalError):
            self.invoke()
        self.assertEqual(self.channel.calls, [])

    def test_read_and_lifecycle_faults_never_retry(self):
        # Each case owns an isolated fresh journal, lease and nonce namespace.
        for fault in ('loader', 'slot', 'job', 'read', 'exec', 'early', 'ready', 'result', 'START', 'timeout'):
            with self.subTest(fault=fault):
                case = CaptureTests('test_simulated_success_is_only_observation')
                case.setUp()
                try:
                    case.channel.fault = fault
                    with self.assertRaises((ValueError, OSError, TimeoutError)):
                        case.invoke()
                    self.assertEqual(case.journal.state, ro.UNKNOWN)
                    self.assertLessEqual(case.channel.calls.count('upload'), 1)
                    self.assertLessEqual(case.channel.calls.count('START'), 1)
                    if fault == 'read':
                        self.assertEqual(case.channel.calls.count('exec_failure'), 1)
                finally:
                    case.doCleanups()

    def test_preflight_rejects_unreviewed_freeze(self):
        (self.kit / 'freeze.json').write_text('{}')
        # Access the real implementation behind the explicit transport fixture.
        real_preflight = self.real_preflight
        with self.assertRaises(ValueError):
            real_preflight(self.assets)

    real_preflight = staticmethod(ro.preflight_assets)


class ProtocolTests(unittest.TestCase):
    def channel(self, responses):
        from collections import deque
        class Device:
            driver = object()
        device = Device()
        calls = []
        replies = deque(responses)
        def send(device, function, data, sink):
            calls.append(data)
            reply = replies.popleft()
            if isinstance(reply, Exception):
                raise reply
            sink.write(reply)
            return 0, None
        channel = ro.IdentityChannel(device, bytes.fromhex(ro.NONCE))
        channel.send_packet = send
        channel.context_guard = lambda: None
        return channel, calls

    def test_exact_ro_start_and_no_second_attempt(self):
        channel, calls = self.channel([bytes(4), bytes(4)])
        with tempfile.TemporaryDirectory() as folder:
            channel.start_once(Path(folder).resolve())
            with self.assertRaises(ValueError):
                channel.start_once(Path(folder).resolve())
        self.assertEqual(calls[1], ro.struct.pack('<HH', 0x1001, 16) +
                         b'\0\xff\0ROSTART1' + bytes.fromhex(ro.NONCE) + ro.struct.pack('<Q', 1))
        self.assertEqual(len(calls), 2)

    def test_per_packet_guard_stops_between_select_and_read(self):
        channel, calls = self.channel([bytes(4), bytes(4)])
        checks = []
        def guard():
            checks.append(1)
            if len(checks) > 1:
                raise ValueError('lease changed')
        channel.context_guard = guard
        with self.assertRaises(ValueError):
            channel.read('ready')
        self.assertEqual(len(calls), 1)

    def test_unknown_read_is_sticky_without_resend(self):
        channel, calls = self.channel([bytes(4), OSError('unknown')])
        with self.assertRaises(OSError):
            channel.read('result')
        with self.assertRaises(RuntimeError):
            channel.read('result')
        self.assertEqual(len(calls), 2)

    def test_transport_caps_result_and_ready(self):
        for name, length in (('ready', 128), ('result', 200000)):
            channel, calls = self.channel([bytes(4), bytes(4) + b'X' * (length + 1)])
            with self.assertRaises(ValueError):
                channel.read(name)
            self.assertFalse(channel.healthy)
            self.assertEqual(len(calls), 2)

    def test_no_general_control_or_arbitrary_paths(self):
        channel, calls = self.channel([])
        for action in (lambda: channel.read('../../dev/mem'),
                       lambda: channel.write_control('ack', b''),
                       lambda: channel.write_control('start', b'')):
            with self.assertRaises(ValueError):
                action()
        self.assertEqual(calls, [])

    def test_known_absent_job_only(self):
        channel, calls = self.channel([bytes(4), ro.struct.pack('<I', 0x10000006)])
        channel.assert_job_absent()
        self.assertEqual(len(calls), 2)
        channel, calls = self.channel([bytes(4), bytes(4)])
        with self.assertRaises(ValueError):
            channel.assert_job_absent()


if __name__ == '__main__':
    unittest.main()
