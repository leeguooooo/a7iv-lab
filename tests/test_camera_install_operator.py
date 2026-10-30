import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import camera_install_operator as operator
from camera_install_receipts import load_reference


class OperatorTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve()
        self.binding=dict(body_sha256='b'*64,plan_sha256='a'*64,model='ILCE-7M4')
        data=self.root/'evidence.json';data.write_text(json.dumps(dict(kind='local unit-test evidence')))
        ref=dict(path=str(data),sha256=hashlib.sha256(data.read_bytes()).hexdigest())
        self.references={k:ref for k in operator.admission.REF_KEYS-{'approval'}}
        self.observed=dict(model='ILCE-7M4',target_version='6.02',**dict.fromkeys(operator.admission.OBSERVED,True))

    def test_offline_template_contains_no_observed_or_approved_value(self):
        ref=operator.write_operator_template(self.root/'template.json',binding=self.binding)
        _,report=load_reference(ref)
        self.assertFalse(report['approved']);self.assertFalse(report['installation_authorized'])
        self.assertTrue(all(v is None for v in report['observed'].values()))

    def test_full_approval_requires_explicit_boolean_and_statement(self):
        for approved in (False,None,1):
            path=self.root/'not-approved.json'
            with self.subTest(approved=approved),self.assertRaises(ValueError):
                operator.record_full_approval(path,binding=self.binding,references=self.references,
                    statement='operator approval',explicit_user_approval=approved)
            self.assertFalse(path.exists())
        with self.assertRaises(ValueError):
            operator.record_full_approval(self.root/'empty.json',binding=self.binding,references=self.references,
                statement='',explicit_user_approval=True)
        self.assertFalse((self.root/'empty.json').exists())

    def test_approval_binds_exact_evidence_but_does_not_run_admission_or_device(self):
        ref=operator.record_full_approval(self.root/'approval.json',binding=self.binding,
            references=self.references,statement='Explicit operator approval for this evidence set.',explicit_user_approval=True)
        _,report=load_reference(ref)
        self.assertEqual(report['evidence_references'],self.references)
        self.assertEqual(report['scope'],'FULL_INSTALL')
        self.assertEqual(report['candidate_sha256'],operator.PACKAGE_SHA)

    def test_missing_or_nonboolean_current_observation_never_publishes(self):
        for observed in (self.observed|{'slot1':None},self.observed|{'power_suitable':1},
                         self.observed|{'model_fixture_only':True},self.observed|{'target_version':'0.02'}):
            path=self.root/'bad-observation.json'
            with self.subTest(observed=observed),self.assertRaises(ValueError):
                operator.record_observation(path,binding=self.binding,references=self.references,observed=observed,
                    statement='operator observation',evidence_references=[self.references['runtime']])
            self.assertFalse(path.exists())

    def test_observation_keeps_the_explicit_statement_and_fixed_reference_set(self):
        statement='Operator explicitly confirms current screen and power conditions.'
        ref=operator.record_observation(self.root/'observation.json',binding=self.binding,references=self.references,
            observed=self.observed,statement=statement,evidence_references=[self.references['runtime']])
        _,report=load_reference(ref)
        self.assertEqual(report['statement'],statement)
        self.assertEqual(report['current_read_reference'],self.references['current_read'])
        self.assertEqual(report['observation_kind'],'EXPLICIT_OPERATOR_OBSERVATION')

    def test_risk_exception_is_not_inferred_from_prepare_request(self):
        assessment=dict(known_gaps=['independent_medium_missing:cnflasha1','physical_NOR_backup_missing'])
        with patch.object(operator.admission,'assess_recovery',return_value=({},assessment)) as assess:
            with self.assertRaises(ValueError):
                operator.record_recovery_exception(self.root/'no-risk.json',binding=self.binding,
                    recovery_reference=self.references['recovery'],statement='continue preparing')
            assess.assert_not_called()
            ref=operator.record_recovery_exception(self.root/'risk.json',binding=self.binding,
                recovery_reference=self.references['recovery'],statement='Explicitly accept the listed recovery risks.',
                explicit_user_approval=True)
        _,report=load_reference(ref)
        self.assertEqual(report['accepted_gaps'],assessment['known_gaps'])
        self.assertEqual(report['approval_kind'],'EXPLICIT_USER_INFORMED_RECOVERY_EXCEPTION')


if __name__=='__main__':unittest.main()
