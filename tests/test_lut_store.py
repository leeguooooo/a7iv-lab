"""Real host POSIX persistence tests. Every filesystem path is a temporary directory."""
import ctypes as C
import fcntl
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
import zlib

ROOT=Path(__file__).resolve().parents[1]
RECORD_BYTES=48256

class Meta(C.Structure):
    _fields_=[('slot',C.c_uint32),('source_grid',C.c_uint32),('compiled_grid',C.c_uint32),
              ('bounds_policy',C.c_uint32),('quantization_policy',C.c_uint32),
              ('clamped_nodes',C.c_uint32),('saturated_components',C.c_uint32),
              ('generation',C.c_uint64),('filename',C.c_char_p),
              ('input_space',C.c_char_p),('output_space',C.c_char_p)]

class Result(C.Structure):
    _fields_=[('generation',C.c_uint64),('from_backup',C.c_uint32),
              ('renamed_primary',C.c_uint32),('directory_synced',C.c_uint32)]

class LutStoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build=tempfile.TemporaryDirectory(prefix='camera-lut-store-host-')
        library=Path(cls.build.name)/'store.so'
        subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror','-O2','-fPIC',
                        '-dynamiclib' if sys.platform=='darwin' else '-shared',
                        '-DCAMERA_LUT_STORE_TESTING',str(ROOT/'native/lut_store.c'),
                        '-o',str(library)],check=True,capture_output=True,text=True)
        cls.lib=C.CDLL(str(library))
        cls.lib.camera_lut_record_build.argtypes=[C.POINTER(Meta),C.c_void_p,C.c_size_t,
                C.c_void_p,C.c_size_t,C.c_void_p,C.c_size_t]
        cls.lib.camera_lut_record_build.restype=C.c_int
        cls.lib.camera_lut_record_validate.argtypes=[C.c_void_p,C.c_size_t]
        cls.lib.camera_lut_record_validate.restype=C.c_int
        cls.lib.camera_lut_store_save.argtypes=[C.c_char_p,C.c_void_p,C.c_size_t,
                                              C.c_uint64,C.POINTER(Result)]
        cls.lib.camera_lut_store_save.restype=C.c_int
        cls.lib.camera_lut_store_load.argtypes=[C.c_char_p,C.c_uint32,C.c_void_p,
                                              C.c_size_t,C.POINTER(Result)]
        cls.lib.camera_lut_store_load.restype=C.c_int
        cls.lib.camera_lut_store_test_fault.argtypes=[C.c_int]
        cls.lib.camera_lut_store_test_short_writes.argtypes=[C.c_int]

    @classmethod
    def tearDownClass(cls):
        cls.build.cleanup()

    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='camera-lut-store-data-')
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.lib.camera_lut_store_test_fault(0)
        self.lib.camera_lut_store_test_short_writes(0)

    def record(self,gen=1,slot=0,value=1,filename=b'test.cube'):
        meta=Meta(slot=slot,source_grid=33,compiled_grid=17,generation=gen,
                  filename=filename,input_space=b'Sony ST / sRGB',output_space=b'sRGB')
        payload=bytes([value])*48000;source=b'LUT_3D_SIZE 33\n'
        out=C.create_string_buffer(RECORD_BYTES)
        status=self.lib.camera_lut_record_build(C.byref(meta),source,len(source),
                                                payload,len(payload),out,len(out))
        self.assertEqual(status,0)
        return out.raw

    def save(self,record,expected=0):
        result=Result()
        status=self.lib.camera_lut_store_save(str(self.root).encode(),record,len(record),
                                             expected,C.byref(result))
        return status,result

    def load(self,slot=0):
        out=C.create_string_buffer(b'X'*RECORD_BYTES,RECORD_BYTES)
        result=Result();C.memset(C.byref(result),0x5a,C.sizeof(result));before=bytes(result)
        status=self.lib.camera_lut_store_load(str(self.root).encode(),slot,out,len(out),C.byref(result))
        if status:
            self.assertEqual(out.raw,b'X'*RECORD_BYTES)
            self.assertEqual(bytes(result),before)
        return status,out.raw,result

    def test_record_header_crc_and_payload_roundtrip(self):
        record=self.record()
        self.assertEqual(self.lib.camera_lut_record_validate(record,len(record)),0)
        self.assertEqual(record[:8],b'A7LUT01\x00')
        self.assertEqual(struct.unpack_from('<Q',record,24)[0],1)
        self.assertEqual(struct.unpack_from('<I',record,32)[0],zlib.crc32(b'LUT_3D_SIZE 33\n'))
        checked=bytearray(record);stored=struct.unpack_from('<I',checked,252)[0];checked[252:256]=bytes(4)
        self.assertEqual(stored,zlib.crc32(checked))
        self.assertEqual(record[256:],bytes([1])*48000)

    def test_primary_save_and_exact_load(self):
        record=self.record();status,result=self.save(record)
        self.assertEqual(status,0)
        self.assertEqual((result.generation,result.renamed_primary,result.directory_synced),(1,1,1))
        status,actual,result=self.load()
        self.assertEqual(status,0);self.assertEqual(actual,record)
        self.assertEqual((result.generation,result.from_backup),(1,0))
        self.assertFalse(list(self.root.glob('.slot*')))

    def test_second_generation_keeps_previous_verified_backup(self):
        first=self.record();second=self.record(2,value=2)
        self.assertEqual(self.save(first)[0],0);self.assertEqual(self.save(second,1)[0],0)
        self.assertEqual((self.root/'slot00.bak').read_bytes(),first)
        self.assertEqual(self.load()[1],second)

    def test_generation_conflict_does_not_replace_current(self):
        self.assertEqual(self.save(self.record())[0],0)
        second=self.record(2,value=2);self.assertEqual(self.save(second,1)[0],0)
        self.assertEqual(self.save(self.record(2,value=3),1)[0],7)
        self.assertEqual(self.load()[1],second)
        self.assertEqual(self.save(self.record(4),2)[0],7)

    def test_prepublication_faults_preserve_primary_and_clean_owned_stage(self):
        first=self.record();self.assertEqual(self.save(first)[0],0)
        for checkpoint in (1,2,3):
            with self.subTest(checkpoint=checkpoint):
                self.lib.camera_lut_store_test_fault(checkpoint)
                status,result=self.save(self.record(2,value=2),1)
                self.assertEqual(status,2)
                self.assertEqual(result.renamed_primary,0)
                self.assertEqual(self.load()[1],first)
                self.assertFalse(list(self.root.glob('.slot*')))
        self.lib.camera_lut_store_test_fault(0)

    def test_postrename_sync_failure_is_uncertain_and_reconcilable(self):
        self.assertEqual(self.save(self.record())[0],0)
        second=self.record(2,value=2);self.lib.camera_lut_store_test_fault(4)
        status,result=self.save(second,1)
        self.assertEqual(status,4)
        self.assertEqual((result.generation,result.renamed_primary,result.directory_synced),(2,1,0))
        self.lib.camera_lut_store_test_fault(0)
        self.assertEqual(self.load()[1],second)
        self.assertEqual(self.save(second,1)[0],7)

    def test_corrupt_primary_recovers_backup_without_overwriting_it(self):
        first=self.record();self.save(first);self.save(self.record(2,value=2),1)
        (self.root/'slot00.lut').write_bytes(b'corrupt')
        status,actual,result=self.load()
        self.assertEqual(status,0);self.assertEqual(actual,first);self.assertEqual(result.from_backup,1)
        recovered=self.record(2,value=7);self.assertEqual(self.save(recovered,1)[0],0)
        self.assertEqual((self.root/'slot00.bak').read_bytes(),first)
        self.assertEqual(self.load()[1],recovered)

    def test_all_invalid_records_fail_without_publishing(self):
        record=bytearray(self.record());record[-1]^=1
        self.assertEqual(self.save(bytes(record))[0],1)
        self.assertEqual(self.load()[0],6)
        (self.root/'slot00.lut').write_bytes(record)
        self.assertNotEqual(self.load()[0],0)
        self.assertNotEqual(self.save(self.record())[0],0)
        self.assertFalse((self.root/'slot00.bak').exists())

    def test_lock_contention_returns_busy(self):
        with (self.root/'slot00.lock').open('w') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            self.assertEqual(self.save(self.record())[0],3)
            self.assertEqual(self.load()[0],3)

    def test_short_write_loop_and_interrupted_retry(self):
        self.lib.camera_lut_store_test_short_writes(1)
        record=self.record();self.assertEqual(self.save(record)[0],0)
        self.assertEqual(self.load()[1],record)

    def test_unicode_metadata_and_invalid_name_rejection(self):
        self.assertEqual(self.save(self.record(filename='夜景.cube'.encode()))[0],0)
        for name in [b'../bad.cube',b'bad\\file.cube',b'a'*64,b'bad\n.cube',b'\xc0\xaf.cube']:
            meta=Meta(slot=1,source_grid=33,compiled_grid=17,generation=1,
                      filename=name,input_space=b'sRGB',output_space=b'sRGB')
            out=C.create_string_buffer(b'X'*RECORD_BYTES,RECORD_BYTES)
            status=self.lib.camera_lut_record_build(C.byref(meta),b'a',1,
                        bytes(48000),48000,out,len(out))
            self.assertEqual(status,1);self.assertEqual(out.raw,b'X'*RECORD_BYTES)

    def test_slots_are_independent_and_wrong_slot_backup_rejected(self):
        first=self.record();other=self.record(slot=1,value=8)
        self.assertEqual(self.save(first)[0],0);self.assertEqual(self.save(other)[0],0)
        self.assertEqual(self.load(0)[1],first);self.assertEqual(self.load(1)[1],other)
        (self.root/'slot02.bak').write_bytes(first)
        self.assertNotEqual(self.load(2)[0],0)

    def test_symlink_does_not_read_or_overwrite_external_file(self):
        external=self.root/'unrelated';external.write_bytes(b'unrelated')
        (self.root/'slot00.lut').symlink_to(external)
        self.assertNotEqual(self.load()[0],0);self.assertNotEqual(self.save(self.record())[0],0)
        self.assertEqual(external.read_bytes(),b'unrelated')

    def test_exhausted_temporary_names_do_not_delete_existing_files(self):
        for attempt in range(64):
            (self.root/f'.slot00.new.1.{attempt}').write_bytes(b'existing-stage')
        self.assertEqual(self.save(self.record())[0],2)
        for attempt in range(64):
            self.assertEqual((self.root/f'.slot00.new.1.{attempt}').read_bytes(),b'existing-stage')
        self.assertFalse((self.root/'slot00.lut').exists())

if __name__=='__main__':
    unittest.main()
