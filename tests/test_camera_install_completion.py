import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import camera_install_completion as completion
from camera_install_journal import InstallJournal, JournalError
from camera_install_receipts import load_reference
from install_model_fixture import formal_flash


class CompletionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.binding = dict(body_sha256='b'*64, plan_sha256='a'*64, model='ILCE-7M4')
        self.journal = InstallJournal.create(self.root/'journals','case',**self.binding)
        formal_flash(self,self.journal)
        self.path = self.root/'completed.json'
        self.observations = dict(reported_complete=True,updater_stopped_confirmed=True,
            normal_service_reentry_authorized=True,completed_after_camera_requested_steps=True,
            statement='Operator explicitly reports update completion and permits normal-service re-entry.',
            evidence_references=[])

    def seal(self, **changes):
        return completion.seal_completion(self.path,binding=self.binding,history=self.journal.events,
            session_dir=self.journal.session_dir,observations=self.observations|changes)

    def test_operator_completion_records_reentry_but_not_installation_acceptance(self):
        ref=self.seal();_,report=load_reference(ref)
        self.assertFalse(report['source_is_hardware'])
        for name in completion.FALSE_CLAIMS:self.assertFalse(report[name])
        self.journal.record_device_completion(self.path)
        self.assertEqual(InstallJournal.open(self.journal.session_dir).state,'DEVICE_COMPLETION_REPORTED')
        with self.assertRaises(JournalError):self.journal.advance('DEVICE_COMPLETION_REPORTED')

    def test_all_confirmations_are_required_without_publishing_invalid_report(self):
        for name in ('reported_complete','updater_stopped_confirmed','normal_service_reentry_authorized',
                     'completed_after_camera_requested_steps'):
            with self.subTest(field=name),self.assertRaises(ValueError):self.seal(**{name:False})
            self.assertFalse(self.path.exists())

    def test_model_or_hardware_claims_never_authorize_reentry(self):
        for extra in ({'model_fixture_only':True},{'nested':{'injected':True}}, {'source_is_hardware':True}):
            with self.subTest(extra=extra),self.assertRaises(ValueError):self.seal(**extra)
            self.assertFalse(self.path.exists())

    def test_missing_statement_or_evidence_rejected(self):
        for extra in ({'statement':' '},{'statement':'x'*8193},{'evidence_references':[{'path':'/missing','sha256':'a'*64}]}):
            with self.subTest(extra=extra),self.assertRaises((ValueError,OSError)):self.seal(**extra)
            self.assertFalse(self.path.exists())

    def test_rewrapped_candidate_runtime_body_and_flash_mutations_rejected(self):
        ref=self.seal();_,original=load_reference(ref)
        for key,value in [('candidate_sha256','c'*64),('body_sha256','c'*64),
                          ('flash_event_sha256','c'*64),('runtime_reference',{'path':'/missing','sha256':'c'*64}),
                          ('source_is_hardware',True),('photo_verified',True)]:
            report=copy.deepcopy(original);report[key]=value;self.path.write_text(json.dumps(report))
            current=dict(path=str(self.path),sha256=hashlib.sha256(self.path.read_bytes()).hexdigest())
            with self.subTest(field=key),self.assertRaises(ValueError):
                completion.validate_completion_receipt(current,self.binding,self.journal.events,self.journal.session_dir)

    def test_unknown_update_history_stays_blocked(self):
        self.journal.advance('STOPPED_UNKNOWN')
        with self.assertRaises(ValueError):self.seal()
        self.assertFalse(self.path.exists())

    def test_existing_completion_never_overwritten(self):
        self.path.write_bytes(b'preserve')
        with self.assertRaises(ValueError):self.seal()
        self.assertEqual(self.path.read_bytes(),b'preserve')


if __name__=='__main__':unittest.main()
