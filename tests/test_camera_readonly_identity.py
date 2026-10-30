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

FREEZE = b'{\n  "schema": "readonly-runtime-identity-freeze/1",\n  "canonical_run": "canonical",\n  "files": {\n    "README.md": {\n      "bytes": 5363,\n      "sha256": "0b346cf3cfbf4a95348e82e4459e7fc2b3c7442ad6b25bd2bf74303e1bf40d6a"\n    },\n    "approval-template.json": {\n      "bytes": 388,\n      "sha256": "0036319950813c167bf272e60fb2fcbff612df7cd1b02ad6783943b1993fc0be"\n    },\n    "bootstrap_model.py": {\n      "bytes": 10347,\n      "sha256": "f04a8e0621ca70285677f35f536e471d0c81e296848cea2926f833a0a1e03846"\n    },\n    "build-invocation.json": {\n      "bytes": 3271,\n      "sha256": "3012332b011986df854526511ee5c9d89e10edbb5a5bd9270d38653f9e0ecb34"\n    },\n    "build.py": {\n      "bytes": 3519,\n      "sha256": "5735977515074ffff5f0e21bffd734ed22f06761b54047b915c69e0b08bd1967"\n    },\n    "canonical/bootstrap-model-report.json": {\n      "bytes": 7897,\n      "sha256": "9f3364d77b0f6af8b54bf9e7e40f4b38688c664f85911e5b13de795a7af849b9"\n    },\n    "canonical/bootstrap.compile.log": {\n      "bytes": 0,\n      "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"\n    },\n    "canonical/bootstrap.json": {\n      "bytes": 172,\n      "sha256": "7eb51bcda333c0664e45d70eaf8709cd11aef3bd03a3ba0990c8eea9144dad25"\n    },\n    "canonical/compile.log": {\n      "bytes": 0,\n      "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"\n    },\n    "canonical/job.h": {\n      "bytes": 168,\n      "sha256": "d4ca03496c38177122e4f5b3bf95d93d614414734de3243709f86093b127ca82"\n    },\n    "canonical/libJit.so": {\n      "bytes": 7416,\n      "sha256": "e2971269981e5d69a8dd754f0c52cb16eb19f23b457fae625498836fcb7afc2a"\n    },\n    "canonical/manifest.json": {\n      "bytes": 3271,\n      "sha256": "3012332b011986df854526511ee5c9d89e10edbb5a5bd9270d38653f9e0ecb34"\n    },\n    "canonical/model-report.json": {\n      "bytes": 106415,\n      "sha256": "e4b67f9c9bdb3909687a65f8f55de11c28a9283dfe6b00786e2e203c5e01a79b"\n    },\n    "canonical/synthetic-decoded.json": {\n      "bytes": 1967,\n      "sha256": "3a414730bb4e2f34e3704c2145ce08ef153ac11c4a3336916b27c10c1fa6ccd7"\n    },\n    "canonical/synthetic-result.bin": {\n      "bytes": 459,\n      "sha256": "2a3e259fc042a8a0da3248afe55ca7b14d1875b303af8db0eb9deb4ea55be07b"\n    },\n    "canonical/worker.elf": {\n      "bytes": 3544,\n      "sha256": "847bf052ef5c4916d71ea9e78f3e61818d2d11725321ecf249882b1baa6a33a7"\n    },\n    "canonical/worker_blob.h": {\n      "bytes": 10591,\n      "sha256": "936bdc6bff6a16e46f49fd8873499efbf188dc683044bee9e71a1304bc6cfec1"\n    },\n    "contract.py": {\n      "bytes": 2063,\n      "sha256": "2fdcb6bd741970d5c86f6c93867393b085cc14b10f50c8dd4fb8ee286ee12c7e"\n    },\n    "launch-plan.json": {\n      "bytes": 2534,\n      "sha256": "d7625f4c1b793c14cfffcb1f9dec86955b63f650b69502d228a34bfccef3678e"\n    },\n    "model.py": {\n      "bytes": 7728,\n      "sha256": "5762b970aa54bf6705c62134b762f8c69f3c9a002e108d2b43b2ed297133c442"\n    },\n    "rebuild/bootstrap.compile.log": {\n      "bytes": 0,\n      "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"\n    },\n    "rebuild/compile.log": {\n      "bytes": 0,\n      "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"\n    },\n    "rebuild/job.h": {\n      "bytes": 168,\n      "sha256": "d4ca03496c38177122e4f5b3bf95d93d614414734de3243709f86093b127ca82"\n    },\n    "rebuild/libJit.so": {\n      "bytes": 7416,\n      "sha256": "e2971269981e5d69a8dd754f0c52cb16eb19f23b457fae625498836fcb7afc2a"\n    },\n    "rebuild/manifest.json": {\n      "bytes": 3263,\n      "sha256": "4d16d3485230bebddb86742f053e6b47c66473c72a30f9c1ac8f6c5064dd9f73"\n    },\n    "rebuild/worker.elf": {\n      "bytes": 3544,\n      "sha256": "847bf052ef5c4916d71ea9e78f3e61818d2d11725321ecf249882b1baa6a33a7"\n    },\n    "rebuild/worker_blob.h": {\n      "bytes": 10591,\n      "sha256": "936bdc6bff6a16e46f49fd8873499efbf188dc683044bee9e71a1304bc6cfec1"\n    },\n    "rebuild-report.json": {\n      "bytes": 112,\n      "sha256": "de19bbdd38d33e59548d2ec4d5d2aed8721a245b39e7e73cf84ce067ab42cbfe"\n    },\n    "reviewed-inputs.json": {\n      "bytes": 805,\n      "sha256": "6cc93a16cf366e328854d066e4050a6ff57a0563d60d01b2a106c24a131f6aad"\n    },\n    "worker.c": {\n      "bytes": 2981,\n      "sha256": "22c93723630cfdf8ed7bcb2fc460e45dfd814d5d21b9c72694d1b21fb041f2f2"\n    }\n  },\n  "hardware_operations": 0,\n  "physical_origin_proven": false\n}\n'
MANIFEST = b'{\n  "schema": "readonly-runtime-identity-offline/1",\n  "scope": "RO_METADATA",\n  "nonce": "957ba14fe2d99b34871ae4f436d92d96",\n  "job_dir": "/tmp_wbshd/roid_957ba14fe2d99b34871ae4f436d92d96",\n  "compile_command": [\n    "/workspace/a7iv-lab/local/zig-aarch64-macos-0.15.2/zig",\n    "cc",\n    "-target",\n    "aarch64-linux-gnu",\n    "-mcpu=generic",\n    "-Os",\n    "-ffreestanding",\n    "-fno-builtin",\n    "-fno-stack-protector",\n    "-fno-unwind-tables",\n    "-fno-asynchronous-unwind-tables",\n    "-nostdlib",\n    "-static",\n    "-fno-pic",\n    "-Wl,-e,_start",\n    "-Wl,--no-undefined",\n    "-Wl,--build-id=none",\n    "-Wl,-z,noexecstack",\n    "-Wl,-z,max-page-size=4096",\n    "-I",\n    "/workspace/a7iv-lab/output/readonly-runtime-identity-20261031/canonical",\n    "-I",\n    "/workspace/a7iv-lab/ref/sony-a7m4-custom-firmware/no-fastboot-install/software/app/native",\n    "/workspace/a7iv-lab/output/readonly-runtime-identity-20261031/worker.c",\n    "-o",\n    "/workspace/a7iv-lab/output/readonly-runtime-identity-20261031/canonical/worker.elf"\n  ],\n  "pins": {\n    "local/zig-aarch64-macos-0.15.2/zig": "c65cd34917923f575448cc0603dd7c2326da0af0e5c323043d090662dcdf351c",\n    "ref/sony-a7m4-custom-firmware/no-fastboot-install/software/app/native/linux_a64.h": "827bfa50c9d5e2a1ee8eacc032303844cd3c0a8a9b4f5ea1bfa640a987eedd88",\n    "ref/sony-a7m4-custom-firmware/no-fastboot-install/software/app/native/bootstrap.c": "4e4dcb37eceab654a25b4a7f0d16626d1764f2a9708a48b3275da10c173b19a1"\n  },\n  "sources": {\n    "worker.c": "22c93723630cfdf8ed7bcb2fc460e45dfd814d5d21b9c72694d1b21fb041f2f2",\n    "contract.py": "2fdcb6bd741970d5c86f6c93867393b085cc14b10f50c8dd4fb8ee286ee12c7e",\n    "build.py": "5735977515074ffff5f0e21bffd734ed22f06761b54047b915c69e0b08bd1967",\n    "model.py": "5762b970aa54bf6705c62134b762f8c69f3c9a002e108d2b43b2ed297133c442"\n  },\n  "worker_sha256": "847bf052ef5c4916d71ea9e78f3e61818d2d11725321ecf249882b1baa6a33a7",\n  "hardware_operations": 0,\n  "physical_origin_proven": false,\n  "full_image_admission": false,\n  "bootstrap_compiled": true,\n  "bootstrap_compile_command": [\n    "/workspace/a7iv-lab/local/zig-aarch64-macos-0.15.2/zig",\n    "cc",\n    "-target",\n    "aarch64-linux-gnu",\n    "-Os",\n    "-ffreestanding",\n    "-fno-builtin",\n    "-fno-stack-protector",\n    "-nostdlib",\n    "-shared",\n    "-fPIC",\n    "-Wl,-Bsymbolic",\n    "-Wl,--no-undefined",\n    "-Wl,--build-id=none",\n    "-Wl,-z,noexecstack",\n    "-Wl,-z,max-page-size=4096",\n    "-I",\n    "/workspace/a7iv-lab/output/readonly-runtime-identity-20261031/canonical",\n    "-I",\n    "/workspace/a7iv-lab/ref/sony-a7m4-custom-firmware/no-fastboot-install/software/app/native",\n    "/workspace/a7iv-lab/ref/sony-a7m4-custom-firmware/no-fastboot-install/software/app/native/bootstrap.c",\n    "-o",\n    "/workspace/a7iv-lab/output/readonly-runtime-identity-20261031/canonical/libJit.so"\n  ],\n  "bootstrap_sha256": "e2971269981e5d69a8dd754f0c52cb16eb19f23b457fae625498836fcb7afc2a",\n  "fixed_upload_cleanup": "/tmp/jiritsu/libJit.so",\n  "fixed_upload_cleanup_requires": "exclusive host/device lease and verified current upload ownership; otherwise reject"\n}\n'

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


class LateModelChannel(SimulatedChannel):
    def read(self, name, missing=False):
        if name == 'result':
            self.calls.append(name)
            if self.fault == 'missing':
                return None
            if self.fault == 'result':
                return self.result[:-1]
            if self.fault == 'read':
                raise OSError('unknown late read')
            return self.result
        return super().read(name, missing)

    def upload_once(self, *args):
        raise AssertionError('Late observer must never upload')

    def start_once(self, *args):
        raise AssertionError('Late observer must never START')


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
        (self.kit / 'freeze.json').write_bytes(FREEZE)
        (self.kit / 'canonical').mkdir()
        (self.kit / 'canonical/manifest.json').write_bytes(MANIFEST)
        self.assertEqual(ro.sha(CONTRACT), '2fdcb6bd741970d5c86f6c93867393b085cc14b10f50c8dd4fb8ee286ee12c7e')
        self.assets = ro.Assets(self.kit, self.root)
        reference = dict(scope=ro.SCOPE, nonce=ro.NONCE, job_dir='/tmp_wbshd/roid_' + ro.NONCE,
                         kit_dir=str(self.kit), source_root=str(self.root), freeze_sha256=ro.FREEZE_SHA256,
                         manifest_sha256=ro.sha(MANIFEST),
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

    def test_sealed_decoder_survives_live_kit_change(self):
        self.invoke()
        (self.kit / 'contract.py').write_bytes(b'changed')
        self.assertEqual(InstallJournal.open(self.journal.session_dir).state, ro.OBSERVED)

    def drift(self):
        from contextlib import ExitStack
        stack = ExitStack()
        self.addCleanup(stack.close)
        for name, value in (('NONCE', 'a' * 32), ('FREEZE_SHA256', '1' * 64),
                            ('WORKER_SHA256', '2' * 64), ('MODULE_SHA256', '3' * 64),
                            ('EXPECTED_WRITES', ('future-profile-write-declarations',))):
            stack.enter_context(patch.object(ro, name, value))
        stack.enter_context(patch.object(ro, 'host_source_bindings', return_value={'new-source.py': '4' * 64}))
        return stack

    def test_known_terminal_replays_after_new_profile_and_source_version(self):
        self.invoke()
        self.drift()
        self.assertEqual(InstallJournal.open(self.journal.session_dir).state, ro.OBSERVED)
        assert_operation_allowed(sessions_root=self.root / 'sessions')
        fresh = InstallJournal.create(self.root / 'sessions', 'fresh-profile',
                    plan_sha256='c' * 64, body_sha256='d' * 64, model='synthetic-new-profile')
        self.assertEqual(fresh.state, 'PLANNED')

    def test_frozen_approval_replay_survives_current_write_policy_drift(self):
        self.invoke()
        with patch.object(ro, 'EXPECTED_WRITES', ('new current profile write policy',)):
            self.assertEqual(InstallJournal.open(self.journal.session_dir).state, ro.OBSERVED)
            assert_operation_allowed(sessions_root=self.root / 'sessions')
        changed = json.loads(json.dumps(self.approval))
        changed['binding']['expected_writes'] = ['new current profile write policy']
        with patch.object(ro, 'EXPECTED_WRITES', tuple(changed['binding']['expected_writes'])):
            with self.assertRaisesRegex(ValueError, 'Historical v1 approval'):
                ro.validate_historical_approval_v1(changed, self.prepared.reference,
                                                  self.reservation['record']['context'])

    def test_unknown_still_blocks_after_profile_and_source_drift(self):
        self.channel.fault = 'upload'
        with self.assertRaises(OSError):
            self.invoke()
        self.drift()
        self.assertEqual(InstallJournal.open(self.journal.session_dir).state, ro.UNKNOWN)
        with self.assertRaises(JournalError):
            assert_operation_allowed(sessions_root=self.root / 'sessions')
        for state in ('STOPPED_UNKNOWN', 'CANCELLED_BEFORE_DEVICE_WRITE',
                      'MANUALLY_RECONCILED_SAFE', 'FLASH_MAY_HAVE_STARTED'):
            with self.assertRaises(JournalError):
                self.journal.advance(state)

    def test_historical_source_tampering_blocks_replay(self):
        self.invoke()
        item = self.reservation['record']['historical_snapshot']
        path = Path(item['path'])
        snapshot = json.loads(path.read_bytes())
        snapshot['blobs']['host/camera_stream_channel.py'] = b'changed'.hex()
        path.chmod(0o600)
        path.write_text(json.dumps(snapshot))
        with self.assertRaises(ValueError):
            InstallJournal.open(self.journal.session_dir)

    def test_self_consistent_decoder_hash_cannot_authorize_code_execution(self):
        self.reserve()
        item = dict(self.reservation['record']['historical_snapshot'])
        path = Path(item['path'])
        snapshot = json.loads(path.read_bytes())
        reference = dict(self.prepared.reference)
        malicious = b"raise AssertionError('UNREVIEWED DECODER EXECUTED')"
        reference['contract_sha256'] = ro.sha(malicious)
        snapshot['asset_reference'] = reference
        snapshot['blobs']['contract'] = malicious.hex()
        path.chmod(0o600)
        path.write_text(json.dumps(snapshot))
        item['sha256'] = ro.sha(path.read_bytes())
        with patch('builtins.exec', side_effect=AssertionError('decoder execution forbidden')) as execute:
            with self.assertRaisesRegex(ValueError, 'Unsupported historical decoder'):
                ro.validate_history(item, reference)
            with self.assertRaisesRegex(ValueError, 'Known reviewed decoder'):
                ro.decode_result(b'', reference, historical_contract=malicious)
            execute.assert_not_called()

    def test_unknown_historical_abi_fails_closed(self):
        self.reserve()
        item = dict(self.reservation['record']['historical_snapshot'])
        path = Path(item['path'])
        snapshot = json.loads(path.read_bytes())
        snapshot['decoder'] = 'unknown-new-ABI'
        path.chmod(0o600)
        path.write_text(json.dumps(snapshot))
        item['sha256'] = ro.sha(path.read_bytes())
        with self.assertRaisesRegex(ValueError, 'Unsupported historical decoder'):
            ro.validate_history(item, self.prepared.reference)

    def test_actual_physical_channel_cannot_be_simulated(self):
        channel = ro.IdentityChannel(self.device, bytes.fromhex(ro.NONCE))
        calls = []
        channel.send_packet = lambda *args: calls.append(args)
        with self.assertRaisesRegex(ValueError, 'Physical transport'):
            self.invoke(channel=channel)
        self.assertEqual(calls, [])
        self.assertEqual(self.journal.state, 'PLANNED')

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

    def late_setup(self, replace_lease=True):
        self.channel.fault = 'upload'
        with self.assertRaises(OSError):
            self.invoke()
        self.old_lease_instance = self.lease.metadata['instance']
        if replace_lease:
            self.lease.__exit__(None, None, None)
            self.lease.__enter__()
        self.late_folder = self.root / 'late-evidence'
        self.late_folder.mkdir()
        self.late_nonce = 'f' * 32
        self.late_channel = LateModelChannel(self.device, self.result)
        self.late_approval = dict(operator='SIMULATED LATE OBSERVER', explicit_approval=True,
                binding=ro.terminal_observation_payload(self.journal, self.context, self.late_folder, self.late_nonce))

    def invoke_late(self, **changes):
        args = dict(lease=self.lease, journal=self.journal, context=self.context,
                    approval=self.late_approval, observation_nonce=self.late_nonce, channel=self.late_channel)
        args.update(changes)
        return ro.observe_existing_terminal_authenticated(self.device, self.late_folder, **args)

    def test_late_success_only_reads_original_job_under_new_lease(self):
        self.late_setup()
        receipt = self.invoke_late()
        self.assertEqual(self.journal.state, ro.OBSERVED)
        self.assertEqual(self.late_channel.calls, ['launch', 'ready', 'result', ro.SLOT])
        observed = receipt['terminal_observation']['context']['lease_identity']['instance']
        self.assertNotEqual(observed, self.old_lease_instance)
        self.assertEqual(InstallJournal.open(self.journal.session_dir).state, ro.OBSERVED)
        assert_operation_allowed(sessions_root=self.root / 'sessions')
        before = list(self.late_channel.calls)
        with self.assertRaises(ValueError):
            self.invoke_late()
        self.assertEqual(before, self.late_channel.calls)

    def test_late_observer_accepts_same_still_held_lease(self):
        self.late_setup(replace_lease=False)
        receipt = self.invoke_late()
        self.assertEqual(receipt['terminal_observation']['context']['lease_identity']['instance'],
                         self.old_lease_instance)
        self.assertEqual(self.journal.state, ro.OBSERVED)

    def test_late_observer_rejects_released_lease_before_io(self):
        self.late_setup()
        self.lease.__exit__(None, None, None)
        with self.assertRaises(ValueError):
            self.invoke_late()
        self.assertEqual(self.late_channel.calls, [])
        self.assertEqual(self.journal.state, ro.UNKNOWN)

    def test_late_observer_uses_original_nonce_after_current_profile_changes(self):
        self.late_setup()
        with patch.object(ro, 'NONCE', 'a' * 32), patch.object(ro, 'FREEZE_SHA256', '1' * 64):
            receipt = self.invoke_late()
        self.assertEqual(receipt['decoded']['nonce'], self.prepared.reference['nonce'])
        self.assertEqual(self.journal.state, ro.OBSERVED)

    def test_late_missing_result_consumes_attempt_without_clearing_unknown(self):
        self.late_setup()
        self.late_channel.fault = 'missing'
        with self.assertRaises(ValueError):
            self.invoke_late()
        self.assertEqual(self.journal.state, ro.UNKNOWN)
        before = list(self.late_channel.calls)
        self.late_channel = LateModelChannel(self.device, self.result)
        # A fresh evidence path/approval cannot replay the same attempt nonce.
        self.late_folder = self.root / 'another-evidence'
        self.late_folder.mkdir()
        self.late_approval['binding'] = ro.terminal_observation_payload(
                self.journal, self.context, self.late_folder, self.late_nonce)
        with self.assertRaises(FileExistsError):
            self.invoke_late()
        self.assertEqual(self.late_channel.calls, [])
        with self.assertRaises(JournalError):
            assert_operation_allowed(sessions_root=self.root / 'sessions')

    def test_late_malformed_result_is_saved_and_stays_unknown(self):
        self.late_setup()
        self.late_channel.fault = 'result'
        with self.assertRaises(ValueError):
            self.invoke_late()
        self.assertTrue((self.late_folder / 'result-raw.json').is_file())
        self.assertEqual(self.journal.state, ro.UNKNOWN)

    def test_late_unknown_read_never_retries(self):
        self.late_setup()
        self.late_channel.fault = 'read'
        with self.assertRaises(OSError):
            self.invoke_late()
        self.assertEqual(self.late_channel.calls, ['launch'])
        self.assertEqual(self.journal.state, ro.UNKNOWN)

    def test_late_wrong_target_source_or_old_approval_does_no_io(self):
        self.late_setup()
        for changes in (dict(context=ro.CaptureContext('another-target')),
                        dict(context=ro.CaptureContext('synthetic-camera', 'HARDWARE', lambda *_: True)),
                        dict(approval=self.approval)):
            with self.assertRaises(ValueError):
                self.invoke_late(**changes)
        self.assertEqual(self.late_channel.calls, [])
        self.assertEqual(self.journal.state, ro.UNKNOWN)

    def test_late_physical_transport_cannot_use_simulated_context(self):
        self.late_setup()
        channel = ro.TerminalObservationChannel(self.device, bytes.fromhex(ro.NONCE))
        calls = []
        channel.send_packet = lambda *args: calls.append(args)
        with self.assertRaisesRegex(ValueError, 'Physical transport'):
            self.invoke_late(channel=channel)
        self.assertEqual(calls, [])
        self.assertEqual(self.journal.state, ro.UNKNOWN)

    def test_late_occupied_slot_stays_unknown(self):
        self.late_setup()
        self.late_channel.fault = 'slot'
        with self.assertRaises(ValueError):
            self.invoke_late()
        self.assertTrue((self.late_folder / 'slot-observation.json').is_file())
        self.assertEqual(self.journal.state, ro.UNKNOWN)

    def test_late_persistence_failure_cannot_close_unknown(self):
        self.late_setup()
        original = ro.durable_new
        def fail(path, value):
            if str(path).endswith('result-raw.json'):
                raise OSError('persistence unknown')
            return original(path, value)
        with patch.object(ro, 'durable_new', side_effect=fail):
            with self.assertRaises(OSError):
                self.invoke_late()
        self.assertEqual(self.journal.state, ro.UNKNOWN)

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

    def test_terminal_transport_has_no_upload_start_or_other_file_api(self):
        channel = ro.TerminalObservationChannel(object(), bytes.fromhex(ro.NONCE))
        calls = []
        channel.send_packet = lambda *args: calls.append(args)
        channel.context_guard = lambda: None
        for action in (lambda: channel.upload_once(b'', '', ''),
                       lambda: channel.start_once(''),
                       lambda: channel.write_control('start', b''),
                       lambda: channel.assert_job_absent(),
                       lambda: channel.read('exec_failure'),
                       lambda: channel.read_loader('/lib/ld-2.25.so')):
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
