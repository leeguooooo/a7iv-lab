from copy import deepcopy
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import Mock,patch

import camera_install_cancel_session as cancel
import camera_install_epoch_session as epoch
from camera_install_journal import InstallJournal,JournalError
import test_camera_install_epoch_session as fixtures


class EpochCancellationTests(unittest.TestCase):
    def setUp(self):
        self.ef=fixtures.EpochSessionTests();self.ef.setUp();self.addCleanup(self.ef.doCleanups)
        self.f=self.ef.f;self.prior=self.ef.prior
        self.folder=self.ef.root/'cancel';self.folder.mkdir()
        self.runner=Mock(side_effect=self.read_epoch)
        self.enterContext(patch('camera_install_receipts.historical_native',return_value={'sources':{},'schema':'camera-install-runtime-metadata-offline/2','profile':'fixed_partition_alias_metadata_v2_boot_epoch'}))
        self.enterContext(patch.object(cancel,'DEFAULT_SESSIONS',self.ef.root/'absent-global'))
        self.history=self.prior.session.journal.events

    def read_epoch(self,body,folder,**options):
        self.ef.folder=Path(folder)
        return self.ef.invoke()

    def invoke(self,**changes):
        p=self.prior;f=self.f
        options=dict(plan_sha256=p.session.plan,pending_reference=p.pending_reference,stage_reference=p.reference,
            initial_runtime_reference=f.initial_ref,withdrawal_reference=f.withdrawal_ref,
            epoch_assets=self.ef.base.assets,epoch_review_path=self.ef.review['review_path'],
            epoch_review_sha256=self.ef.review['review_sha256'],journal=p.session.journal,lease=p.session.lease,
            cancellation_authorized=True,card_read_authorized=True,operator_health_confirmed=True,
            operator_never_started_confirmed=True,manual_AP_reboot_confirmed=True,
            withdrawal_preceded_manual_AP_reboot_confirmed=True,
            epoch_session=self.runner,discover=p.discover,clock=lambda:self.ef.base.time,sleep=self.ef.base.sleep)
        options.update(changes)
        return cancel.run_epoch_cancellation_session(p.body,self.folder,**options)

    def test_real_v2_epoch_receipt_difference_and_inactive_card_still_DI_assessment_only(self):
        result=self.invoke()
        self.assertEqual(result['state'],'CANCELLATION_ASSESSED_ONLY')
        self.assertTrue(result['AP_boot_epoch_change_observed'])
        self.assertFalse(result['previous_AP_process_contexts_ended'])
        self.assertFalse(result['source_is_hardware']);self.assertFalse(result['cancellation_recorded'])
        self.assertEqual(self.prior.session.journal.events,self.history)
        for key in ('RAM_restoration_proven','original_mm_continuity_proven','CP_coldboot_proven','NOR_state_proven','full_camera_coldboot_proven'):
            self.assertIs(result[key],False)
        path=self.folder/'cancellation-assessment.json'
        with self.assertRaises(ValueError):cancel.validate_cancellation_receipt(cancel._reference(path),
            self.prior.session.journal.binding,self.history,self.prior.session.journal.session_dir)

    def test_same_boot_uuid_blocks_without_card_or_journal_transition(self):
        self.f.summary['initial_boot_id']=self.ef.base.channel.boot_id
        path=Path(self.ef.review['review_path']);review=json.loads(path.read_text());review['source_summary']=deepcopy(self.f.summary)
        path.write_text(json.dumps(review));self.ef.review['review_sha256']=hashlib.sha256(path.read_bytes()).hexdigest()
        result=self.invoke()
        self.assertEqual(result['state'],'CANCELLATION_BLOCKED_SAME_AP_BOOT_EPOCH')
        self.assertFalse(result['AP_boot_epoch_change_observed']);self.prior.discover.assert_not_called()
        self.assertEqual(self.prior.session.journal.events,self.history)

    def test_missing_manual_or_other_consent_rejects_before_epoch(self):
        for change in (dict(manual_AP_reboot_confirmed=False),dict(operator_never_started_confirmed=False),
            dict(operator_health_confirmed=False),dict(withdrawal_preceded_manual_AP_reboot_confirmed=False),dict(cancellation_authorized=False),dict(card_read_authorized=False),
            dict(epoch_session=None),dict(discover=None)):
            with self.subTest(change=change),self.assertRaises(ValueError):self.invoke(**change)
        self.runner.assert_not_called()

    def test_unknown_epoch_STOP_never_reads_card_or_records_cancel(self):
        self.runner.side_effect=OSError('unknown epoch STOP')
        with self.assertRaises(OSError):self.invoke()
        self.prior.discover.assert_not_called();self.assertEqual(self.prior.session.journal.events,self.history)

    def test_active_candidate_after_reboot_is_not_removed_or_accepted(self):
        self.prior.root_update.write_bytes(self.prior.payload)
        with self.assertRaises(ValueError):self.invoke()
        self.assertEqual(self.prior.root_update.read_bytes(),self.prior.payload)
        self.assertEqual(self.prior.session.journal.events,self.history)

    def test_replaced_lease_after_epoch_prevents_card(self):
        def replace(*args,**kwargs):
            value=self.read_epoch(*args,**kwargs)
            self.prior.session.lease.__exit__(None,None,None);self.prior.session.lease.__enter__()
            return value
        self.runner.side_effect=replace
        with self.assertRaises(ValueError):self.invoke()
        self.prior.discover.assert_not_called()

    def test_complete_epoch_file_tampering_rejects_before_card(self):
        def changed(*args,**kwargs):
            value=self.read_epoch(*args,**kwargs)
            (Path(args[1])/'pending-epoch-session-exit.json').write_text('{}')
            return value
        self.runner.side_effect=changed
        with self.assertRaises(ValueError):self.invoke()
        self.prior.discover.assert_not_called()

    def test_ap_scope_terminal_replays_without_claiming_mm_or_CP_and_is_tamper_evident(self):
        report=self.invoke()
        reference=report['completed_epoch_reference']
        receipt=json.loads(Path(reference['path']).read_text())
        proof=dict(receipt=receipt,initial_boot_id=report['initial_boot_id'],current_boot_id=report['current_boot_id'],
            boot_id_differs=True,source_is_hardware=True)
        report.update(state=cancel.TERMINAL,producer_kind='DEFAULT_OWNED_PENDING_EPOCH_AND_INACTIVE_CARD',
            source_is_hardware=True,injected_execution=False,previous_AP_process_contexts_ended=True,
            card_collector_kind='DEFAULT_FILESYSTEM_DISCOVERY')
        path=self.folder/'terminal-boundary-fixture.json';path.write_text(json.dumps(report))
        journal=self.prior.session.journal
        with patch.object(epoch,'validate_completed_pending_epoch',return_value=proof):
            event=journal.record_install_preparation_cancelled(path,explicit_user_approval=True)
            self.assertEqual(event['state'],cancel.TERMINAL)
            self.assertEqual(InstallJournal.open(journal.session_dir).state,cancel.TERMINAL)
            for field in ('RAM_restoration_proven','original_mm_continuity_proven','CP_coldboot_proven','NOR_state_proven'):
                changed=dict(report,**{field:True});path.write_text(json.dumps(changed))
                with self.subTest(field=field),self.assertRaises((ValueError,JournalError)):InstallJournal.open(journal.session_dir)
                path.write_text(json.dumps(report))
