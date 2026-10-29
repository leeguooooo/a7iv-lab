import unittest
import camera_install_requirements as requirements


class RequirementsTests(unittest.TestCase):
    def raw(self):
        return ''.join(f'/dev/nflasha{n} none raw {1000+n} 0\n' for n in requirements.TARGETS).encode()

    def test_capacities_are_from_bytes_and_target_set_is_exact(self):
        raw=b'# mount.conf\r\n'+self.raw()+b'/dev/nflasha2 /setting vfat 2500 512\r\n'
        self.assertEqual(requirements.parse_mount_requirements(raw),
            {'nflasha'+str(n):1000+n for n in requirements.TARGETS})

    def test_missing_duplicate_zero_and_bad_rows_rejected(self):
        raw=self.raw()
        for bad in (raw.split(b'\n',1)[1],raw+raw.split(b'\n',1)[0]+b'\n',
                    raw.replace(b'1001',b'0'),raw.replace(b'1001',b'-1'),
                    raw.replace(b'1001',b'9223372036854775808'),raw.replace(b'raw 1001',b'raw nope'),
                    raw.replace(b'/dev/nflasha1 ',b'/dev/../nflasha1 '),raw+b'bad\n'):
            with self.subTest(raw=bad),self.assertRaises(ValueError):requirements.parse_mount_requirements(bad)

    def test_non_ascii_unbounded_and_empty_inputs_rejected(self):
        for raw in (b'',b'x'*65537,'text',b'\xff'+self.raw()):
            with self.subTest(kind=type(raw)),self.assertRaises((ValueError,UnicodeError)):
                requirements.parse_mount_requirements(raw)


if __name__ == '__main__':unittest.main()
