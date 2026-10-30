"""Host-only plan publication with synthetic assets and source files."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import camera_install_patch_plan as plan


class PlanTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        (self.root / 'output').mkdir()
        self.source = self.root / 'host.py'
        self.source.write_bytes(b'host-only synthetic source\n')
        self.body = self.root / 'output/body.json'
        self.body.write_text(json.dumps(dict(body=dict(model='ILCE-7M4', usb_serial_sha256='a' * 64))))
        self.output = self.root / 'output/sealed'
        self.reference = dict(schema='synthetic-assets', nonce='b' * 32)
        self.prepared = SimpleNamespace(reference=self.reference,
            manifest=dict(sources={'host.py': hashlib.sha256(self.source.read_bytes()).hexdigest()}))
        self.patches = [patch.object(plan, 'ROOT', self.root),
            patch.object(plan, 'review_source_paths', return_value=('host.py',)),
            patch.object(plan, 'preflight_assets', return_value=self.prepared),
            patch.object(plan, '_candidate_package_check', return_value=dict(local_checks_passed=True,
                package_sha256='c'*64, plaintext_sha256='d'*64)),
            patch.object(plan, 'validate_review', side_effect=self.validate)]
        for value in self.patches:
            value.start()
            self.addCleanup(value.stop)

    def validate(self, path, digest, body, prepared):
        raw = Path(path).read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), digest)
        payload = json.loads(raw)
        self.assertEqual(payload['body_sha256'], body)
        self.assertEqual(payload['asset_reference'], prepared.reference)
        for name, expected in payload['sources'].items():
            if hashlib.sha256((self.root / name).read_bytes()).hexdigest() != expected:
                raise ValueError('Source changed before publication')
        return dict(path=str(path), sha256=digest)

    def seal(self, **overrides):
        options = dict(assets=object(), capture_assets=object(), body_reference=self.body)
        options.update(overrides)
        return plan.seal(self.output, **options)

    def test_plan_and_exact_source_snapshot_without_any_approval(self):
        value = self.seal()
        raw = (self.output / 'plan.json').read_bytes()
        payload = json.loads(raw)
        self.assertEqual(value['plan_sha256'], hashlib.sha256(raw).hexdigest())
        self.assertEqual(payload['scope'], 'INSTALL_PREPARATION_VOLATILE_PATCH_ONLY')
        self.assertEqual(payload['source_only_runtime'], plan.SOURCE_ONLY_RUNTIME)
        for field in ('installation_authorized', 'flash_authorized', 'hardware_admission_proven',
                      'execution_approval_received'):
            self.assertIs(payload[field], False)
        self.assertEqual(payload['hardware_operations'], 0)
        self.assertTrue(payload['body_reference']['historical_only'])
        self.assertEqual((self.output / 'sources/host.py').read_bytes(), self.source.read_bytes())
        self.assertFalse((self.output / 'plan.pending.json').exists())
        self.assertEqual(plan.preflight_assets.call_count, 2)
        self.assertEqual((self.output / 'plan.json').stat().st_mode & 0o777, 0o600)

    def test_existing_plan_is_never_overwritten(self):
        self.seal()
        before = (self.output / 'plan.json').read_bytes()
        plan.preflight_assets.reset_mock()
        with self.assertRaisesRegex(ValueError, 'fresh plan directory'):
            self.seal()
        plan.preflight_assets.assert_not_called()
        self.assertEqual((self.output / 'plan.json').read_bytes(), before)

    def test_missing_or_wrong_body_binding_refuses_before_assets(self):
        for body in ({}, dict(model='different', usb_serial_sha256='a' * 64),
                     dict(model='ILCE-7M4', usb_serial_sha256='bad')):
            with self.subTest(body=body):
                self.body.write_text(json.dumps(dict(body=body)))
                with self.assertRaisesRegex(ValueError, 'historical body reference'):
                    self.seal()
                self.assertFalse(self.output.exists())
        plan.preflight_assets.assert_not_called()

    def test_source_change_keeps_plan_unpublished(self):
        original = plan._write
        def changed(path, raw):
            original(path, raw)
            if path.name == 'plan.pending.json':
                self.source.write_bytes(b'changed source\n')
        with patch.object(plan, '_write', side_effect=changed):
            with self.assertRaisesRegex(ValueError, 'Source changed'):
                self.seal()
        self.assertFalse((self.output / 'plan.json').exists())
        self.assertTrue((self.output / 'plan.pending.json').exists())

    def test_used_or_changed_assets_at_second_check_keep_plan_unpublished(self):
        changed = deepcopy(self.prepared)
        changed.reference = dict(schema='other')
        plan.preflight_assets.side_effect = [self.prepared, changed]
        with self.assertRaisesRegex(ValueError, 'asset binding changed'):
            self.seal()
        self.assertFalse((self.output / 'plan.json').exists())

    def test_symlink_body_or_output_parent_refuses_before_assets(self):
        alias = self.root / 'output/body-alias.json'
        alias.symlink_to(self.body)
        with self.assertRaisesRegex(ValueError, 'Nonsymlink'):
            self.seal(body_reference=alias)
        parent = self.root / 'output/parent-alias'
        parent.symlink_to(self.root / 'output', target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'Nonsymlink'):
            plan.seal(parent / 'new', assets=object(), capture_assets=object(), body_reference=self.body)
        plan.preflight_assets.assert_not_called()

    def test_duplicate_body_keys_are_rejected(self):
        self.body.write_text('{"body":{},"body":{"model":"ILCE-7M4","usb_serial_sha256":"' + 'a' * 64 + '"}}')
        with self.assertRaisesRegex(ValueError, 'Duplicate'):
            self.seal()
        plan.preflight_assets.assert_not_called()

    def test_fsync_failure_does_not_publish_plan(self):
        with patch.object(plan, '_sync', side_effect=OSError('fsync failed')):
            with self.assertRaisesRegex(OSError, 'fsync failed'):
                self.seal()
        self.assertFalse((self.output / 'plan.json').exists())

    def test_existing_destination_race_is_not_overwritten(self):
        link = plan.os.link
        def raced(source, target):
            target.write_bytes(b'independent racing plan')
            link(source, target)
        with patch.object(plan.os, 'link', side_effect=raced):
            with self.assertRaises(FileExistsError):
                self.seal()
        self.assertEqual((self.output / 'plan.json').read_bytes(), b'independent racing plan')
        self.assertTrue((self.output / 'plan.pending.json').exists())

    def test_snapshot_corruption_before_publication_is_refused(self):
        def corrupted(*args):
            value = self.validate(*args)
            (self.output / 'sources/host.py').write_bytes(b'corrupted snapshot')
            return value
        plan.validate_review.side_effect = corrupted
        with self.assertRaisesRegex(ValueError, 'snapshot changed'):
            self.seal()
        self.assertFalse((self.output / 'plan.json').exists())

    def test_body_reference_change_keeps_plan_unpublished(self):
        write = plan._write
        def changed(path, raw):
            write(path, raw)
            if path.name == 'plan.pending.json':
                self.body.write_text('{}')
        with patch.object(plan, '_write', side_effect=changed):
            with self.assertRaisesRegex(ValueError, 'body reference changed'):
                self.seal()
        self.assertFalse((self.output / 'plan.json').exists())


if __name__ == '__main__':
    unittest.main()
