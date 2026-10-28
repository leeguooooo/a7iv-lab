"""Exercise the real Darwin no-replace primitive on host TEMP files only."""
from pathlib import Path
import sys
import tempfile
import unittest

from camera_sd_stage import rename_exclusive


@unittest.skipUnless(sys.platform=='darwin','Darwin filesystem API')
class ExclusiveRenameTests(unittest.TestCase):
    def test_collision_preserves_both_files_and_success_moves_exact_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();source=root/'source';target=root/'target'
            source.write_bytes(b'candidate');target.write_bytes(b'old package')
            with self.assertRaises(FileExistsError):rename_exclusive(source,target)
            self.assertEqual(source.read_bytes(),b'candidate')
            self.assertEqual(target.read_bytes(),b'old package')
            new=root/'new-name';rename_exclusive(source,new)
            self.assertFalse(source.exists());self.assertEqual(new.read_bytes(),b'candidate')
            self.assertEqual(target.read_bytes(),b'old package')


if __name__=='__main__':unittest.main()
