import copy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

import camera_install_epoch_session as session
import camera_install_epoch_plan as plan
import camera_install_runtime_metadata as meta
import test_camera_install_runtime_metadata as fixtures


class EpochSessionTests(unittest.TestCase):
    def setUp(self):
        self.f=fixtures.PendingEpochMetadataTests();self.f.setUp();self.addCleanup(self.f.doCleanups)
        f=self.f;self.base=f.base;self.prior=f.prior
        self.root=self.base.root
        self.source=self.root/'source';self.source.mkdir()
        required=('fixture.py','Sony-PMCA-RE/pmca/__init__.py','camera_install_epoch_session.py',
            'camera_install_epoch_plan.py','camera_install_card_withdraw.py','camera_install_io.py','camera_install_runtime_metadata.py')
        for name in required:
            path=self.source/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text('# offline source fixture\n')
        self.enterContext(patch.object(session,'ROOT',self.source));self.enterContext(patch.object(plan,'ROOT',self.source))
        self.enterContext(patch.object(session,'preparation_sources',return_value=('fixture.py','Sony-PMCA-RE/pmca/__init__.py')))
        self.prepared=meta.preflight_assets(self.base.assets)
        self.preflight=Mock(return_value=self.prepared)
        self.review=plan.seal(self.root/'review',assets=self.base.assets,body_sha256=self.prior.body,
            plan_sha256=self.prior.session.plan,pending_reference=self.prior.pending_reference,
            initial_runtime_reference=f.initial_ref,withdrawal_reference=f.withdrawal_ref,
            journal=self.prior.session.journal,preflight_fn=self.preflight)
        self.folder=self.root/'epoch';self.folder.mkdir();self.calls=[];self.device=SimpleNamespace(driver=SimpleNamespace(write=lambda *_:None))
        self.original_driver=self.device.driver
        self.run=Mock(side_effect=self.normal_session)
        self.capture=Mock(side_effect=self.capture_metadata)
        self.history=self.prior.session.journal.events

    def normal_session(self,body,work,**options):
        self.calls.append('auth');options['record_event'](dict(model='ILCE-7M4',body_matched=True))
        value=work(self.device)
        self.assertTrue((self.folder/'pending-epoch-terminal.json').is_file())
        self.assertIsNot(self.device.driver,self.original_driver)
        self.calls.append('STOP');self.device.driver.write(b'fake STOP')
        options['record_event'](dict(event='STOP_RESPONSE',mode='service',success=True))
        return value

    def capture_metadata(self,device,folder,**options):
        self.calls.append('metadata')
        return meta.capture_pending_epoch_authenticated(device,folder,channel_factory=self.base.factory,**options)

    def invoke(self,**changes):
        f=self.f
        options=dict(plan_sha256=self.prior.session.plan,pending_reference=self.prior.pending_reference,
            initial_runtime_reference=f.initial_ref,withdrawal_reference=f.withdrawal_ref,
            review_path=self.review['review_path'],review_sha256=self.review['review_sha256'],assets=self.base.assets,
            journal=self.prior.session.journal,lease=self.prior.session.lease,epoch_read_authorized=True,
            operator_never_started_confirmed=True,manual_AP_reboot_confirmed=True,
            withdrawal_preceded_manual_AP_reboot_confirmed=True,run_session=self.run,
            capture_fn=self.capture,preflight_fn=self.preflight,clock=lambda:self.base.time,sleep=self.base.sleep)
        options.update(changes)
        return session.run_pending_epoch_session(self.prior.body,self.folder,**options)

    def test_changed_boot_uuid_is_observation_only_with_durable_terminal_before_STOP(self):
        value=self.invoke()
        self.assertEqual(self.calls,['auth','metadata','STOP'])
        self.assertTrue(value['boot_id_differs']);self.assertFalse(value['source_is_hardware'])
        self.assertFalse(value['metadata_receipt']['source_is_hardware'])
        self.assertEqual(value['current_boot_id'],self.base.channel.boot_id)
        self.assertEqual(value['state'],'PENDING_EPOCH_KNOWN_SERVICE_EXIT')
        self.assertEqual(self.prior.session.journal.events,self.history)
        self.assertIs(self.device.driver,self.original_driver)
        for name in session.FALSE_CLAIMS:self.assertIs(value[name],False)

    def test_unchanged_boot_id_never_means_reboot_or_cleanup(self):
        self.f.summary['initial_boot_id']=self.base.channel.boot_id
        review=json.loads(Path(self.review['review_path']).read_text());review['source_summary']=copy.deepcopy(self.f.summary)
        Path(self.review['review_path']).write_text(json.dumps(review));self.review['review_sha256']=hashlib.sha256(Path(self.review['review_path']).read_bytes()).hexdigest()
        result=self.invoke();self.assertFalse(result['boot_id_differs']);self.assertFalse(result['cancellation_recorded'])

    def test_consent_and_mixed_injection_reject_before_auth(self):
        for options in (dict(epoch_read_authorized=False),dict(manual_AP_reboot_confirmed=False),
            dict(operator_never_started_confirmed=False),dict(withdrawal_preceded_manual_AP_reboot_confirmed=False),dict(run_session=None),dict(capture_fn=None)):
            with self.subTest(options=options),self.assertRaises(ValueError):self.invoke(**options)
        self.run.assert_not_called();self.capture.assert_not_called()

    def test_source_or_review_mutation_reject_before_auth_and_reservation(self):
        (self.source/'camera_install_epoch_session.py').write_text('changed')
        with self.assertRaises(ValueError):self.invoke()
        self.run.assert_not_called();self.assertFalse((self.base.job/'physical-attempt.json').exists())

    def test_unknown_STOP_keeps_native_terminal_and_pending(self):
        def unknown(body,work,**options):
            options['record_event'](dict(model='ILCE-7M4',body_matched=True));work(self.device)
            raise OSError('unknown STOP')
        self.run.side_effect=unknown
        with self.assertRaises(OSError):self.invoke()
        self.assertTrue((self.folder/'pending-epoch-terminal.json').is_file())
        self.assertFalse((self.folder/'pending-epoch-session-exit.json').exists())
        self.assertEqual(self.prior.session.journal.events,self.history)
        self.assertIs(self.device.driver,self.original_driver)

    def test_lease_replaced_after_callback_prevents_STOP(self):
        def swapped(body,work,**options):
            options['record_event'](dict(model='ILCE-7M4',body_matched=True));value=work(self.device)
            self.prior.session.lease.__exit__(None,None,None);self.prior.session.lease.__enter__()
            self.device.driver.write(b'fake STOP')
            return value
        self.run.side_effect=swapped
        with self.assertRaises(ValueError):self.invoke()
        self.assertFalse((self.folder/'pending-epoch-session-exit.json').exists())

    def test_terminal_fsync_failure_prevents_STOP(self):
        actual=session.durable_new
        def fail(path,value):
            if Path(path).name=='pending-epoch-terminal.json':raise OSError('terminal fsync unknown')
            return actual(path,value)
        with patch.object(session,'durable_new',side_effect=fail),self.assertRaises(OSError):self.invoke()
        self.assertNotIn('STOP',self.calls)

    def test_saved_native_receipt_mutation_prevents_completed_exit(self):
        def mutate(body,work,**options):
            options['record_event'](dict(model='ILCE-7M4',body_matched=True));value=work(self.device)
            (self.folder/'metadata-receipt.json').write_text('{}')
            options['record_event'](dict(event='STOP_RESPONSE',mode='service',success=True));return value
        self.run.side_effect=mutate
        with self.assertRaises(ValueError):self.invoke()
        self.assertFalse((self.folder/'pending-epoch-session-exit.json').exists())

    def test_old_initial_runtime_context_change_is_detected_before_upload(self):
        self.f.initial.write_text('{"changed":true}')
        with self.assertRaises(ValueError):self.invoke()
        self.run.assert_not_called()

    def test_default_custom_context_cannot_promote_injected_assets(self):
        with self.assertRaises(ValueError):self.invoke(run_session=None,capture_fn=None,preflight_fn=None)
        self.run.assert_not_called()

    def test_wrong_model_event_cannot_enter_metadata(self):
        def wrong(body,work,**options):
            options['record_event'](dict(model='ILCE-7RM5',body_matched=True))
            return work(self.device)
        self.run.side_effect=wrong
        with self.assertRaises(ValueError):self.invoke()
        self.capture.assert_not_called()

    def test_reused_review_output_never_overwrites(self):
        before=Path(self.review['review_path']).read_bytes()
        with self.assertRaises(ValueError):plan.seal(Path(self.review['review_path']).parent,assets=self.base.assets,
            body_sha256=self.prior.body,plan_sha256=self.prior.session.plan,pending_reference=self.prior.pending_reference,
            initial_runtime_reference=self.f.initial_ref,withdrawal_reference=self.f.withdrawal_ref,
            journal=self.prior.session.journal,preflight_fn=self.preflight)
        self.assertEqual(Path(self.review['review_path']).read_bytes(),before)

    def test_completed_job_and_session_cannot_be_replayed(self):
        self.invoke()
        with self.assertRaises(ValueError):self.invoke()
        self.assertEqual(self.run.call_count,1)

    def test_failed_reservation_marks_possible_claims_but_never_authenticates(self):
        reserve=Mock(side_effect=OSError('claim fsync failed'))
        with self.assertRaises(OSError):self.invoke(reserve_fn=reserve)
        self.run.assert_not_called();self.capture.assert_not_called()
        failure=json.loads((self.folder/'pending-epoch-unknown.json').read_text())
        self.assertTrue(failure['claims_may_be_reserved'])
        self.assertFalse(failure['authentication_may_have_started'])
