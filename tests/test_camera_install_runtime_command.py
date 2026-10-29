import unittest
from unittest.mock import patch, MagicMock
from pathlib import Path
import json
import hashlib
import tempfile
from contextlib import ExitStack
import camera_install_runtime_command as command


class RuntimeCommandTests(unittest.TestCase):
    def test_missing_consent_or_camera_readiness_stops_before_local_or_device_work(self):
        with patch.object(command,'_source_only_runtime') as startup,patch.object(command,'_base_plan') as plan,patch.object(command,'CameraDeviceLease') as lease:
            for read,ready in ((False,True),(True,False),(1,True),(True,1)):
                with self.subTest(read=read,ready=ready),self.assertRaises(ValueError):
                    command.run_read(original_plan=Path('/unused'),original_plan_sha256='a'*64,
                        review_path=Path('/unused'),review_sha256='b'*64,evidence=Path('/unused'),
                        read_authorized=read,camera_ready=ready)
            startup.assert_not_called();plan.assert_not_called();lease.assert_not_called()

    def test_source_only_startup_failure_prevents_plan_or_ownership(self):
        with patch.object(command,'_source_only_runtime',side_effect=ValueError('startup')),patch.object(command,'_base_plan') as plan,patch.object(command,'CameraDeviceLease') as lease:
            with self.assertRaisesRegex(ValueError,'startup'):
                command.run_read(original_plan=Path('/unused'),original_plan_sha256='a'*64,
                    review_path=Path('/unused'),review_sha256='b'*64,evidence=Path('/unused'),
                    read_authorized=True,camera_ready=True)
            plan.assert_not_called();lease.assert_not_called()

    def test_missing_macos_usb_privilege_stops_before_plan_or_journal(self):
        with patch.object(command,'_source_only_runtime'),patch.object(command.sys,'platform','darwin'),patch.object(command.os,'geteuid',return_value=501),patch.object(command,'_base_plan') as plan,patch.object(command,'CameraDeviceLease') as lease:
            with self.assertRaisesRegex(ValueError,'sudo'):
                command.run_read(original_plan=Path('/unused'),original_plan_sha256='a'*64,
                    review_path=Path('/unused'),review_sha256='b'*64,evidence=Path('/unused'),
                    read_authorized=True,camera_ready=True)
            plan.assert_not_called();lease.assert_not_called()

    def test_reference_reconstruction_keeps_exact_native_asset_hashes(self):
        reference={'p1':{'directory':'/MODEL/p1','manifest_sha256':'a'*64},'metadata':{'job_dir':'/MODEL/meta',
            'manifest_sha256':'b'*64,'module_sha256':'c'*64,'native_model_sha256':'d'*64,'bootstrap_model_sha256':'e'*64}}
        result=command.assets_from_reference(reference)
        self.assertEqual(result.p1_directory,Path('/MODEL/p1'))
        self.assertEqual(result.metadata_assets.module_sha256,'c'*64)
        self.assertEqual(result.metadata_assets.bootstrap_model_sha256,'e'*64)

    def test_authorized_command_passes_exact_scope_after_two_preflights(self):
        with tempfile.TemporaryDirectory(dir=command.PLAIN.parents[1]) as temporary,ExitStack() as stack:
            root=Path(temporary).resolve();base=root/'plan.json';review=root/'review.json'
            body='b'*64
            base.write_text(json.dumps(dict(schema='camera-offline-toolchain-plan/1',local_checks_passed=True,
                prepared_offline_only=True,execution_approval_received=False,model='ILCE-7M4',
                package_sha256=command.PACKAGE_SHA,plaintext_sha256=command.PLAIN_SHA,reference_body_sha256=body)))
            reference={'p1':{'directory':str(root/'p1'),'manifest_sha256':'a'*64},'metadata':{'job_dir':str(root/'meta'),
                'manifest_sha256':'b'*64,'module_sha256':'c'*64,'native_model_sha256':'d'*64,'bootstrap_model_sha256':'e'*64}}
            review.write_text(json.dumps(dict(schema=command.REVIEW_SCHEMA,asset_reference=reference)))
            stack.enter_context(patch.object(command,'_source_only_runtime'))
            stack.enter_context(patch.object(command,'_host_access'))
            preflight=stack.enter_context(patch.object(command,'preflight_assets',return_value=object()))
            validation=stack.enter_context(patch.object(command,'validate_review'))
            stack.enter_context(patch.object(command,'read_requirements',return_value={'required_partition_sizes':{'nflasha1':1}}))
            lease=MagicMock();stack.enter_context(patch.object(command,'CameraDeviceLease',return_value=lease))
            journal=MagicMock();create=stack.enter_context(patch.object(command.InstallJournal,'create',return_value=journal))
            execute=stack.enter_context(patch.object(command,'run_runtime_session',return_value={'state':'MODEL_ONLY'}))
            digest=hashlib.sha256(base.read_bytes()).hexdigest()
            result=command.run_read(original_plan=base,original_plan_sha256=digest,review_path=review,
                review_sha256='c'*64,evidence=root/'evidence',read_authorized=True,camera_ready=True)
            self.assertEqual(result,{'state':'MODEL_ONLY'})
            self.assertEqual(preflight.call_count,2);self.assertEqual(validation.call_count,2)
            self.assertEqual(create.call_args.kwargs['body_sha256'],body)
            self.assertEqual(execute.call_args.args[0],body)
            self.assertIs(execute.call_args.kwargs['runtime_read_authorized'],True)
            self.assertEqual(execute.call_args.kwargs['plan_sha256'],digest)


if __name__=='__main__':unittest.main()
