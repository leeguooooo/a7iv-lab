"""Exercise the real portable C parser on host, never camera/USB APIs."""
import ctypes as C
import hashlib
import math
import random
import struct
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

class Info(C.Structure):
    _fields_ = [('size', C.c_uint32), ('rows', C.c_uint32),
                ('domain_min', C.c_double*3), ('domain_max', C.c_double*3),
                ('output_min', C.c_double*3), ('output_max', C.c_double*3),
                ('explicit_domain', C.c_uint32)]

class Error(C.Structure):
    _fields_ = [('code', C.c_uint32), ('line', C.c_uint32)]

def cube(size=2, header='', first=None, row_delta=0, newline='\n'):
    rows = [f'{r/(size-1):.9g} {g/(size-1):.9g} {b/(size-1):.9g}'
            for b in range(size) for g in range(size) for r in range(size)]
    if first is not None:
        rows[0] = first
    if row_delta < 0:
        rows = rows[:row_delta]
    if row_delta > 0:
        rows += ['0 0 0']*row_delta
    return (f'TITLE "Temporary # identity"\nLUT_3D_SIZE {size}\n'+header+
            '\n'.join(rows)+'\n').replace('\n', newline).encode()

class CubeInputTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='camera-cube-host-')
        library = Path(cls.temp.name)/'parser.so'
        flag = '-dynamiclib' if sys.platform == 'darwin' else '-shared'
        subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-O2',
                        '-fPIC', flag, str(ROOT/'native/cube_input.c'), '-o', str(library)],
                       check=True, capture_output=True, text=True)
        cls.lib = C.CDLL(str(library))
        cls.lib.camera_cube_parse.argtypes = [C.c_char_p, C.c_size_t, C.POINTER(C.c_float),
                                             C.c_size_t, C.POINTER(Info), C.POINTER(Error)]
        cls.lib.camera_cube_parse.restype = C.c_int
        cls.lib.camera_cube_sample.argtypes = [C.POINTER(Info), C.POINTER(C.c_float), C.c_size_t,
                                               C.POINTER(C.c_double), C.c_int, C.POINTER(C.c_double)]
        cls.lib.camera_cube_sample.restype = C.c_int
        cls.lib.camera_cube_resample.argtypes = [C.POINTER(Info), C.POINTER(C.c_float), C.c_size_t,
                                                 C.c_uint32, C.c_int, C.POINTER(C.c_float), C.c_size_t,
                                                 C.POINTER(Info), C.POINTER(C.c_uint32)]
        cls.lib.camera_cube_resample.restype = C.c_int
        cls.lib.camera_cube_pack_ap_integer.argtypes = [C.POINTER(Info), C.POINTER(C.c_float),
                C.c_size_t, C.c_int, C.POINTER(C.c_ubyte), C.c_size_t, C.POINTER(C.c_uint32)]
        cls.lib.camera_cube_pack_ap_integer.restype = C.c_int

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def parse(self, text, capacity=None, byte_count=None):
        capacity = capacity if capacity is not None else 33**3*3
        temporary = (C.c_float*capacity)()
        info = Info()
        C.memset(C.byref(info), 0x5A, C.sizeof(info))
        before = bytes(info)
        error = Error()
        status = self.lib.camera_cube_parse(text, len(text) if byte_count is None else byte_count,
                                            temporary, capacity, C.byref(info), C.byref(error))
        self.assertEqual(status, error.code)
        if status:
            self.assertEqual(bytes(info), before, 'failure must not publish candidate metadata')
        return status, info, temporary, error

    def test_identity_axes_red_varies_fastest(self):
        status, info, values, _ = self.parse(cube())
        self.assertEqual(status, 0)
        self.assertEqual((info.size, info.rows), (2, 8))
        self.assertEqual(list(values[:12]), [0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0])
        self.assertEqual(list(info.domain_max), [1, 1, 1])

    def test_native_sized_cubes(self):
        for size in (17, 33):
            with self.subTest(size=size):
                status, info, values, _ = self.parse(cube(size))
                self.assertEqual(status, 0)
                self.assertEqual(info.rows, size**3)
                self.assertEqual(list(values[(info.rows-1)*3:info.rows*3]), [1, 1, 1])

    def test_standard_domain_is_preserved_not_ignored(self):
        status, info, _, _ = self.parse(cube(header='DOMAIN_MIN -1 -2 -3\nDOMAIN_MAX 2 3 4\n'))
        self.assertEqual(status, 0)
        self.assertEqual(list(info.domain_min), [-1, -2, -3])
        self.assertEqual(list(info.domain_max), [2, 3, 4])
        self.assertEqual(info.explicit_domain, 1)

    def test_native_range_and_duplicate_domain(self):
        self.assertEqual(self.parse(cube(header='LUT_3D_INPUT_RANGE 0 2\n'))[0], 0)
        self.assertNotEqual(self.parse(cube(header='LUT_3D_INPUT_RANGE 0 1\nDOMAIN_MIN 0 0 0\n'))[0], 0)

    def test_invalid_domain_order(self):
        for h in ['DOMAIN_MIN 1 0 0\n', 'DOMAIN_MIN 2 0 0\nDOMAIN_MAX 1 1 1\n',
                  'DOMAIN_MAX nan 1 1\n', 'DOMAIN_MIN 0 0 0\nDOMAIN_MIN 0 0 0\n']:
            with self.subTest(header=h):
                self.assertNotEqual(self.parse(cube(header=h))[0], 0)

    def test_short_and_extra_rows_both_rejected(self):
        for delta in (-1, 1):
            with self.subTest(delta=delta):
                self.assertNotEqual(self.parse(cube(row_delta=delta))[0], 0)

    def test_nonfinite_numeric_tokens_and_overflow(self):
        for token in ['nan', 'NaN', 'inf', '-inf', '1e309', '1e39', '0x1p0', '1e-1000', '1e-320', '1e-100']:
            with self.subTest(token=token):
                self.assertNotEqual(self.parse(cube(first=f'0 {token} 0'))[0], 0)

    def test_decimal_grammar_leading_zeroes_and_small_values(self):
        for token, expected in [('0000000000000000000000001', 1), ('.000000000000000000001', 1e-21),
                                ('1e-20', 1e-20), ('+1.', 1), ('-0.25', -.25)]:
            with self.subTest(token=token):
                status, _, values, _ = self.parse(cube(first=f'{token} 0 0'))
                self.assertEqual(status, 0)
                self.assertTrue(math.isclose(values[0], expected, rel_tol=1e-6, abs_tol=1e-30))
        for token in ['.', '+', '1e', '1e+', '1.2suffix']:
            self.assertNotEqual(self.parse(cube(first=f'{token} 0 0'))[0], 0)

    def test_unsupported_or_duplicate_directives(self):
        for h in ['LUT_1D_SIZE 4\n', 'UNKNOWN 1\n', 'LUT_3D_SIZE 2\n', 'TITLE "again"\n']:
            with self.subTest(header=h):
                self.assertNotEqual(self.parse(cube(header=h))[0], 0)

    def test_bad_row_shape(self):
        for row in ['0 0', '0 0 0 0', 'broken', '']:
            with self.subTest(row=row):
                self.assertNotEqual(self.parse(cube(first=row))[0], 0)

    def test_bom_comments_crlf_and_last_line_without_newline(self):
        text=b'\xef\xbb\xbf# comment\r\n'+cube(newline='\r\n').rstrip(b'\r\n')
        self.assertEqual(self.parse(text)[0], 0)
        self.assertEqual(self.parse(cube(first='0 0 0 # safe comment'))[0], 0)

    def test_limits_and_capacity_before_publication(self):
        self.assertNotEqual(self.parse(cube(), capacity=23)[0], 0)
        self.assertNotEqual(self.parse(cube().replace(b'SIZE 2', b'SIZE 66'))[0], 0)
        self.assertNotEqual(self.parse(b'x', byte_count=32*1024*1024+1)[0], 0)
        self.assertNotEqual(self.parse(cube()+b'\x00')[0], 0)
        self.assertNotEqual(self.parse(b'#'+b'x'*4097+b'\n'+cube())[0], 0)

    def test_late_header_after_data_rejected(self):
        self.assertNotEqual(self.parse(cube()+b'DOMAIN_MAX 1 1 1\n')[0], 0)

    def test_decimal_values_match_float32_reference(self):
        rng = random.Random(7184)
        tokens = [f'{rng.uniform(-2, 7):.12g}' for _ in range(17**3*3)]
        text = ('LUT_3D_SIZE 17\n'+'\n'.join(' '.join(tokens[n:n+3])
                for n in range(0, len(tokens), 3))).encode()
        status, _, values, _ = self.parse(text)
        self.assertEqual(status, 0)
        expected = [struct.unpack('<f', struct.pack('<f', float(t)))[0] for t in tokens]
        self.assertEqual(list(values[:len(tokens)]), expected)

    def test_maximum_ingestion_grid_is_not_a_native_support_claim(self):
        status, info, _, _ = self.parse(cube(65), capacity=65**3*3)
        self.assertEqual(status, 0)
        self.assertEqual(info.rows, 65**3)

    def sample(self, info, values, rgb, bounds=0, count=None):
        result = (C.c_double*3)(91, 92, 93)
        status = self.lib.camera_cube_sample(C.byref(info), values,
                    len(values) if count is None else count, (C.c_double*3)(*rgb), bounds, result)
        if status:
            self.assertEqual(list(result), [91, 92, 93])
        return status, list(result)

    def resample(self, info, values, target=17, bounds=0, capacity=None):
        capacity = target**3*3 if capacity is None else capacity
        temporary = (C.c_float*capacity)()
        result = Info()
        C.memset(C.byref(result), 0x5A, C.sizeof(result))
        before = bytes(result)
        clamped = C.c_uint32(0x1234)
        status = self.lib.camera_cube_resample(C.byref(info), values, len(values), target,
                    bounds, temporary, capacity, C.byref(result), C.byref(clamped))
        if status:
            self.assertEqual(bytes(result), before)
            self.assertEqual(clamped.value, 0x1234)
        return status, result, temporary, clamped.value

    def test_trilinear_mixed_axes_against_analytic_polynomial(self):
        _, info, values, _ = self.parse(cube())
        def transform(r, g, b):
            return [r+2*g-3*b, r*g+b, 2*r*g*b]
        for b in range(2):
            for g in range(2):
                for r in range(2):
                    index=((b*2+g)*2+r)*3
                    values[index:index+3] = transform(r, g, b)
        rng = random.Random(1927)
        for _ in range(500):
            rgb=[rng.random() for _ in range(3)]
            status, actual = self.sample(info, values, rgb)
            self.assertEqual(status, 0)
            for a, expected in zip(actual, transform(*rgb)):
                self.assertAlmostEqual(a, expected, places=12)

    def test_sampling_domain_mapping_and_endpoint(self):
        _, info, values, _ = self.parse(cube(header='DOMAIN_MIN -1 -2 -3\nDOMAIN_MAX 1 2 3\n'))
        self.assertEqual(self.sample(info, values, [0, 0, 0]), (0, [.5, .5, .5]))
        self.assertEqual(self.sample(info, values, [1, 2, 3]), (0, [1, 1, 1]))

    def test_outside_domain_requires_explicit_clamp(self):
        _, info, values, _ = self.parse(cube())
        self.assertNotEqual(self.sample(info, values, [-.1, .5, 2])[0], 0)
        self.assertEqual(self.sample(info, values, [-.1, .5, 2], 1), (0, [0, .5, 1]))
        self.assertNotEqual(self.sample(info, values, [0, 0, 0], 2)[0], 0)

    def test_sampling_rejects_inconsistent_metadata_and_nonfinite_values(self):
        _, info, values, _ = self.parse(cube())
        self.assertNotEqual(self.sample(info, values, [math.nan, 0, 0])[0], 0)
        self.assertNotEqual(self.sample(info, values, [0, 0, 0], count=23)[0], 0)
        info.rows = 7
        self.assertNotEqual(self.sample(info, values, [0, 0, 0])[0], 0)
        info.rows = 8
        info.domain_max[0] = math.inf
        self.assertNotEqual(self.sample(info, values, [0, 0, 0])[0], 0)
        info.domain_max[0] = 1
        values[23] = math.nan
        self.assertNotEqual(self.sample(info, values, [0, 0, 0])[0], 0)

    def test_resampling_identity_to_17_and_33(self):
        _, info, values, _ = self.parse(cube())
        for n in (17, 33):
            status, result, output, clamped = self.resample(info, values, n)
            self.assertEqual(status, 0)
            self.assertEqual((result.size, result.rows, clamped), (n, n**3, 0))
            for b in range(n):
                for g in range(n):
                    for r in range(n):
                        index=((b*n+g)*n+r)*3
                        self.assertEqual(list(output[index:index+3]), [r/(n-1), g/(n-1), b/(n-1)])

    def test_resampling_65_grid_preserves_selected_non_linear_nodes(self):
        _, info, values, _ = self.parse(cube(65), capacity=65**3*3)
        for b in range(65):
            for g in range(65):
                for r in range(65):
                    index=((b*65+g)*65+r)*3
                    values[index:index+3] = [(r/64)**2, (g/64)**2, (b/64)**2]
        status, _, output, clamped = self.resample(info, values)
        self.assertEqual((status, clamped), (0, 0))
        for b in range(17):
            for g in range(17):
                for r in range(17):
                    index=((b*17+g)*17+r)*3
                    self.assertEqual(list(output[index:index+3]), [(r/16)**2, (g/16)**2, (b/16)**2])

    def test_resampling_explicit_domain_and_clamp_accounting(self):
        _, info, values, _ = self.parse(cube(header='DOMAIN_MIN -1 -1 -1\nDOMAIN_MAX 1 1 1\n'))
        status, result, output, clamped = self.resample(info, values)
        self.assertEqual((status, clamped), (0, 0))
        self.assertEqual(list(output[:3]), [.5, .5, .5])
        self.assertEqual(list(result.domain_min), [0, 0, 0])
        self.assertEqual(list(result.domain_max), [1, 1, 1])
        _, info, values, _ = self.parse(cube(header='DOMAIN_MAX .5 .5 .5\n'))
        self.assertNotEqual(self.resample(info, values)[0], 0)
        status, _, _, clamped = self.resample(info, values, bounds=1)
        self.assertEqual((status, clamped), (0, 17**3-9**3))

    def test_resampling_rejects_overlap_bad_capacity_and_dirty_source(self):
        _, info, values, _ = self.parse(cube())
        self.assertNotEqual(self.resample(info, values, capacity=10)[0], 0)
        self.assertNotEqual(self.resample(info, values, target=65)[0], 0)
        # Use a large source buffer so the public capacity argument is valid;
        # rejection here must be due to overlap, before any writes.
        result = Info()
        before = bytes(values)
        status = self.lib.camera_cube_resample(C.byref(info), values, len(values), 17,
                    0, values, len(values), C.byref(result), None)
        self.assertEqual(status, 1)
        self.assertEqual(bytes(values), before)
        values[0] = math.inf
        self.assertNotEqual(self.resample(info, values)[0], 0)

    def pack(self, info, values, policy=0, capacity=48000):
        output=(C.c_ubyte*capacity)(*([0x5A]*capacity))
        saturated=C.c_uint32(0x1234)
        status=self.lib.camera_cube_pack_ap_integer(C.byref(info), values, len(values),
                    policy, output, capacity, C.byref(saturated))
        if status:
            self.assertEqual(saturated.value, 0x1234)
            self.assertEqual(bytes(output), bytes([0x5A])*capacity)
        return status, bytes(output), saturated.value

    def test_parser_resample_and_pack_match_original_ap_identity(self):
        # Goldens are from original A7M4 helper replay, bound in
        # output/a7m4-cube-integer-packing-review.json, not this implementation.
        golden='c14036d10d22481f4e73a0853b64014c42e141807c0e2f777489820300ffb247'
        for n in (17, 33):
            _, info, values, _ = self.parse(cube())
            status, normalized, sampled, _ = self.resample(info, values, n)
            self.assertEqual(status, 0)
            status, payload, saturated = self.pack(normalized, sampled)
            self.assertEqual((status, saturated), (0, 0))
            self.assertEqual(hashlib.sha256(payload).hexdigest(), golden)

    def test_asymmetric_packing_matches_original_ap_replay_goldens(self):
        goldens={17:'68f034d9794fd4da8630e67d9c04540a0735a755bc36579df6cfcdae05f608fd',
                 33:'0ac8a35aaa40abb64a9b8b921cbe367f22d38327d3f61bd21d2b033523e77ce6'}
        for n, expected in goldens.items():
            _, info, values, _ = self.parse(cube(n))
            for b in range(n):
                for g in range(n):
                    for r in range(n):
                        index=((b*n+g)*n+r)*3
                        values[index:index+3] = [((r*409+g*73+b*11)%65536)/8192,
                            ((r*37+g*811+b*13)%65536)/8192, ((r*19+g*31+b*199)%65536)/8192]
            status, payload, saturated = self.pack(info, values)
            self.assertEqual((status, saturated), (0, 0))
            self.assertEqual(hashlib.sha256(payload).hexdigest(), expected)

    def test_pack_saturation_is_explicit_and_counted(self):
        _, info, values, _ = self.parse(cube(17))
        values[0]=-1
        values[1]=9
        self.assertNotEqual(self.pack(info, values)[0], 0)
        status, payload, saturated = self.pack(info, values, policy=1)
        self.assertEqual((status, saturated), (0, 2))
        self.assertEqual(struct.unpack_from('<H', payload, 0)[0], 0)
        self.assertEqual(struct.unpack_from('<H', payload, 16000)[0], 65535)

    def test_packing_rejects_unconverted_domain_and_small_buffer(self):
        _, info, values, _ = self.parse(cube(17, header='DOMAIN_MAX 2 2 2\n'))
        self.assertNotEqual(self.pack(info, values)[0], 0)
        info.domain_max[0]=info.domain_max[1]=info.domain_max[2]=1
        self.assertNotEqual(self.pack(info, values, capacity=47999)[0], 0)
        self.assertNotEqual(self.pack(info, values, policy=2)[0], 0)
        values[0]=math.nan
        self.assertNotEqual(self.pack(info, values)[0], 0)

if __name__ == '__main__':
    unittest.main()
