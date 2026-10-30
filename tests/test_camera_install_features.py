"""Local operator reports with an explicitly mocked trusted content validator."""
import copy
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

import camera_install_features as features
from camera_install_journal import InstallJournal


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


class FunctionalReportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.binding = dict(body_sha256='b' * 64, plan_sha256='a' * 64, model='ILCE-7M4')
        self.content = dict(path=str(self.root / 'verification.json'), sha256='c' * 64)
        self.completion = dict(path=str(self.root / 'completion.json'), sha256='d' * 64)
        self.context = dict(**self.binding, session_id='fixture', candidate_sha256=features.PACKAGE_SHA,
            content_reference=self.content, completion_reference=self.completion,
            content_event_sha256='e' * 64, history_sha256='f' * 64, capture_run_sha256='1' * 64, post_exit_sha256='2' * 64)
        self.trusted_fixture_validator = self.enterContext(patch.object(features, 'validate_content_evidence', return_value=self.context))
        self.media = {}
        for index, key in enumerate(features.MEDIA_KEYS):
            photo = key.endswith('_photo')
            path = self.root / (key + ('.JPG' if photo else '.MP4'))
            raw = (b'\xff\xd8\xff\xe0JPEG-fixture' if photo else struct.pack('>I', 24) + b'ftypisomvideo-fixture') + bytes([index])
            path.write_bytes(raw)
            self.media[key] = dict(path=str(path), bytes=len(raw), sha256=digest(raw))
        self.report = dict(explicit_operator_confirmation=True, statement='I checked these four separate tests.',
            reported_at_utc='2026-10-30T01:00:00Z', looks={})
        for look in features.LOOKS:
            self.report['looks'][look] = {kind: dict(media_key=look + '_' + kind,
                **dict.fromkeys(features.ASSERTIONS, True)) for kind in features.KINDS}
        self.report['restart'] = dict(kind='OPERATOR_REPORTED_UNPOWERED_CYCLE', statement='I followed the approved completion steps and checked retention.',
            performed=True, completed=True, camera_requested_steps_followed=True, menu_usable_after=True,
            FL2_retained_after=True, FL3_retained_after=True, parameters_retained_after=True,
            power_removed_confirmed=True, power_restored_confirmed=True)
        self.options = dict(journal=object(), content_reference=self.content, completion_reference=self.completion,
            candidate_sha256=features.PACKAGE_SHA, operator_report=self.report, media_references=self.media)

    def assess(self, **changes):
        return features.assess_functional_acceptance(**(self.options | changes))

    def test_all_four_tests_are_operator_only_and_preserve_machine_unknowns(self):
        result = self.assess()
        self.assertTrue(result['ALL_ACCEPTED'])
        self.assertEqual(result['state'], 'OPERATOR_REPORTED_FUNCTIONAL_ACCEPTANCE')
        self.assertEqual(result['source_kind'], 'EXPLICIT_OPERATOR_FUNCTIONAL_REPORT')
        self.assertFalse(result['source_is_hardware'])
        for name in features.FALSE_CLAIMS:
            self.assertIs(result[name], False)
        self.assertTrue(result['cold_cycle_not_verified'])
        self.assertEqual(self.trusted_fixture_validator.call_count, 2)
        for look in features.LOOKS:
            self.assertEqual(set(result['looks'][look]), {'photo', 'video'})

    def test_photos_alone_and_missing_look_or_video_never_pass(self):
        for key in features.MEDIA_KEYS:
            with self.subTest(missing=key):
                media = dict(self.media);media.pop(key)
                with self.assertRaises(ValueError):self.assess(media_references=media)
        report = copy.deepcopy(self.report)
        del report['looks']['FL3']['video']
        with self.assertRaises(ValueError):self.assess(operator_report=report)

    def test_each_operator_assertion_is_required_and_strict(self):
        for field in features.ASSERTIONS:
            for value in (False, 1, 'yes'):
                with self.subTest(field=field, value=value):
                    report = copy.deepcopy(self.report);report['looks']['FL2']['video'][field] = value
                    with self.assertRaises(ValueError):self.assess(operator_report=report)
        report = copy.deepcopy(self.report);report['explicit_operator_confirmation'] = False
        with self.assertRaises(ValueError):self.assess(operator_report=report)

    def test_ordinary_off_on_retains_media_tests_but_not_all_accepted(self):
        report = copy.deepcopy(self.report);report['restart']['kind'] = 'ORDINARY_OFF_ON'
        result = self.assess(operator_report=report)
        self.assertFalse(result['ALL_ACCEPTED'])
        self.assertEqual(result['state'], 'PARTIAL_OPERATOR_ACCEPTANCE')
        self.assertTrue(result['photo_and_video_reported_complete'])
        self.assertTrue(result['operator_reported_retention_complete'])
        self.assertFalse(result['unpowered_cycle_reported'])
        self.assertTrue(result['cold_cycle_not_verified'])
        self.assertFalse(result['linux_epoch_change_proven'])

    def test_partial_restart_never_passes_all_accepted(self):
        for field in ('performed', 'completed', 'FL3_retained_after', 'power_removed_confirmed', 'power_restored_confirmed'):
            with self.subTest(field=field):
                report = copy.deepcopy(self.report);report['restart'][field] = False
                result = self.assess(operator_report=report)
                self.assertFalse(result['ALL_ACCEPTED'])
                self.assertTrue(result['photo_and_video_reported_complete'])
        report = copy.deepcopy(self.report);report.pop('restart')
        with self.assertRaises(ValueError):self.assess(operator_report=report)

    def test_hash_size_missing_symlink_and_wrong_media_kind_are_refused(self):
        for field, value in (('sha256', '0' * 64), ('bytes', 1), ('path', str(self.root / 'missing.JPG'))):
            with self.subTest(field=field):
                media = copy.deepcopy(self.media);media['FL2_photo'][field] = value
                with self.assertRaises((ValueError, OSError)):self.assess(media_references=media)
        link = self.root / 'linked.JPG';link.symlink_to(self.media['FL2_photo']['path'])
        media = copy.deepcopy(self.media);media['FL2_photo']['path'] = str(link)
        with self.assertRaises(ValueError):self.assess(media_references=media)
        photo = Path(self.media['FL2_photo']['path']).read_bytes()
        wrong = self.root / 'photo-named-video.MP4';wrong.write_bytes(photo)
        media = copy.deepcopy(self.media);media['FL2_video'] = dict(path=str(wrong), bytes=len(photo), sha256=digest(photo))
        with self.assertRaises(ValueError):self.assess(media_references=media)

    def test_inode_and_identical_content_reuse_are_refused(self):
        media = copy.deepcopy(self.media);media['FL3_photo'] = media['FL2_photo'].copy()
        with self.assertRaisesRegex(ValueError, 'cannot be reused'):self.assess(media_references=media)
        path = self.root / 'copy.JPG';raw = Path(self.media['FL2_photo']['path']).read_bytes();path.write_bytes(raw)
        media['FL3_photo'] = dict(path=str(path), bytes=len(raw), sha256=digest(raw))
        with self.assertRaisesRegex(ValueError, 'cannot be reused'):self.assess(media_references=media)

    def test_changed_content_context_and_media_after_read_are_refused(self):
        self.trusted_fixture_validator.side_effect = [self.context, self.context | dict(history_sha256='0' * 64)]
        with self.assertRaisesRegex(ValueError, 'context changed'):self.assess()
        self.trusted_fixture_validator.side_effect = None
        original = features._media
        def changed(reference, kind):
            result = original(reference, kind)
            if reference == self.media['FL3_video']:
                Path(self.media['FL2_photo']['path']).write_bytes(b'changed')
            return result
        with patch.object(features, '_media', side_effect=changed), self.assertRaisesRegex(ValueError, 'changed after'):
            self.assess()

    def test_local_record_is_exclusive_and_never_changes_a_journal(self):
        path = self.root / 'operator-report.json'
        saved = features.record_functional_acceptance(path, **self.options)
        self.assertEqual(saved['sha256'], digest(path.read_bytes()))
        self.assertFalse(saved['journal_changed'])
        self.assertTrue(json.loads(path.read_text())['ALL_ACCEPTED'])
        with self.assertRaises(ValueError):features.record_functional_acceptance(path, **self.options)


class ContentBoundaryTests(unittest.TestCase):
    def test_noncontent_and_cancelled_ledgers_are_rejected_before_reading_artifacts(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            binding = dict(body_sha256='b' * 64, plan_sha256='a' * 64, model='ILCE-7M4')
            for state in ('PLANNED', 'CANCELLED_BEFORE_DEVICE_WRITE', 'DEVICE_COMPLETION_REPORTED'):
                journal = InstallJournal(path, [dict(state=state, binding=binding, details={}, event_sha256='1' * 64)])
                with patch.object(features.InstallJournal, 'open', return_value=journal), self.assertRaises(ValueError):
                    features.validate_content_evidence(journal, {}, {}, features.PACKAGE_SHA)

    def test_unreferenced_all_passed_dictionary_cannot_replace_content_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            binding = dict(body_sha256='b' * 64, plan_sha256='a' * 64, model='ILCE-7M4')
            original = dict(path=str(path / 'actual.json'), sha256='a' * 64)
            journal = InstallJournal(path, [dict(state='CONTENT_VERIFIED', binding=binding,
                details=dict(verification_artifact=original), event_sha256='1' * 64)])
            with patch.object(features.InstallJournal, 'open', return_value=journal), self.assertRaisesRegex(ValueError, 'not the journal'):
                features.validate_content_evidence(journal, dict(all_passed=True, source_is_hardware=True), {}, features.PACKAGE_SHA)


if __name__ == '__main__':unittest.main()
