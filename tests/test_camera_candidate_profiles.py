import unittest

from camera_candidate_profiles import (LEGACY, OBSERVER, profile_for_binding,
    profile_for_digest, require_matching_candidate, report_binding_fields)


class CandidateProfileTests(unittest.TestCase):
    def setUp(self):
        self.old = dict(body_sha256='b'*64, plan_sha256='a'*64, model='ILCE-7M4')
        self.new = dict(self.old, candidate_sha256=OBSERVER.package_sha256)

    def test_legacy_binding_never_implicitly_selects_new_candidate(self):
        self.assertIs(profile_for_binding(self.old), LEGACY)
        with self.assertRaises(ValueError):
            require_matching_candidate(self.old, OBSERVER.package_sha256)
        self.assertEqual(set(self.old), {'body_sha256', 'plan_sha256', 'model'})

    def test_explicit_candidate_cannot_mix_with_legacy_evidence(self):
        self.assertIs(profile_for_binding(self.new), OBSERVER)
        with self.assertRaises(ValueError):
            require_matching_candidate(self.new, LEGACY.package_sha256)
        fields = report_binding_fields(self.new)
        self.assertEqual(fields, self.new)
        self.assertEqual(report_binding_fields(self.old)['candidate_sha256'], LEGACY.package_sha256)

    def test_unsigned_plaintext_and_unknown_digests_are_not_candidates(self):
        for digest in ('998950da9c73cbb29786acfbd9be416ff5e776227dcf2d3b4cb87bf7ec981199',
                       OBSERVER.plaintext_sha256, '0'*64, None):
            with self.subTest(digest=digest), self.assertRaises(ValueError):
                profile_for_digest(digest)

    def test_binding_shape_and_model_are_exact(self):
        for changed in (dict(self.new, extra=True), dict(self.new, model='another'),
                        dict(self.new, body_sha256='wrong'), dict(self.new, candidate_sha256='0'*64)):
            with self.assertRaises(ValueError): profile_for_binding(changed)


if __name__ == '__main__': unittest.main()
