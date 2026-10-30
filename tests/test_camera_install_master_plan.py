import unittest
from camera_toolchain import original_plan_body, PACKAGE_SHA, PLAIN_SHA


class MasterPlanTests(unittest.TestCase):
    def common(self):
        return dict(local_checks_passed=True,prepared_offline_only=True,execution_approval_received=False,
                    model='ILCE-7M4',package_sha256=PACKAGE_SHA,plaintext_sha256=PLAIN_SHA)

    def preparation(self):
        return self.common()|dict(schema='camera-install-patch-session-plan/1',
            scope='INSTALL_PREPARATION_VOLATILE_PATCH_ONLY',body_sha256='b'*64,
            installation_authorized=False,hardware_admission_proven=False,flash_authorized=False)

    def test_preparation_master_binds_the_same_plan_without_full_install_authority(self):
        self.assertEqual(original_plan_body(self.preparation(),require_preparation=True),'b'*64)

    def test_legacy_read_plan_is_not_a_formal_installation_master(self):
        legacy=self.common()|dict(schema='camera-offline-toolchain-plan/1',reference_body_sha256='b'*64)
        self.assertEqual(original_plan_body(legacy),'b'*64)
        with self.assertRaises(ValueError):original_plan_body(legacy,require_preparation=True)

    def test_bad_source_scope_candidate_or_authority_is_rejected(self):
        for field,value in [('scope','FULL_INSTALL'),('flash_authorized',True),('installation_authorized',True),
                            ('execution_approval_received',True),('body_sha256','x'*64),
                            ('package_sha256','c'*64),('model','other'),('local_checks_passed',1)]:
            with self.subTest(field=field),self.assertRaises(ValueError):
                original_plan_body(self.preparation()|{field:value},require_preparation=True)


if __name__=='__main__':unittest.main()
