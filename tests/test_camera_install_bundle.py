from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

import camera_install_bundle as bundle


class BundleTests(unittest.TestCase):
    def test_only_fixed_offline_tools_are_executable(self):
        with patch.object(bundle.subprocess,'run') as run:
            with self.assertRaises(ValueError):bundle._tool('arbitrary.py',(),Path('/unused'))
            run.assert_not_called()

    def test_arguments_are_passed_without_shell_interpretation(self):
        with tempfile.TemporaryDirectory() as temporary:
            log=Path(temporary)/'log'
            with patch.object(bundle.subprocess,'run',return_value=SimpleNamespace(returncode=0)) as run:
                bundle._tool('build_install_runtime_metadata_offline.py',('--output','literal $(no-shell)'),log)
            self.assertEqual(run.call_args.args[0][-1],'literal $(no-shell)')
            self.assertNotIn('shell',run.call_args.kwargs)
            self.assertFalse(log.stat().st_size)

    def test_failed_build_is_reported_without_automatically_reexecuting(self):
        with tempfile.TemporaryDirectory() as temporary:
            log=Path(temporary)/'log'
            with patch.object(bundle.subprocess,'run',return_value=SimpleNamespace(returncode=1)) as run:
                with self.assertRaisesRegex(ValueError,'preparation failed'):
                    bundle._tool('build_install_runtime_metadata_offline.py',('--output','/MODEL'),log)
                self.assertEqual(run.call_count,1)

    def test_existing_bundle_directory_is_preserved_before_any_build(self):
        with tempfile.TemporaryDirectory(dir=bundle.ROOT/'output') as temporary:
            folder=Path(temporary).resolve();(folder/'keep').write_bytes(b'keep')
            with patch.object(bundle,'_tool') as run:
                with self.assertRaises(ValueError):bundle.build_assets(folder)
                run.assert_not_called()
            self.assertEqual((folder/'keep').read_bytes(),b'keep')


if __name__=='__main__':unittest.main()
