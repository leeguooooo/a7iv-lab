"""Original-layout capture owns a value snapshot, not a borrowed AP pointer."""
import ctypes as C
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from test_lut_media import Snapshot

ROOT=Path(__file__).resolve().parents[1]
VTABLE=0x59c56a8
class Request(C.Structure):
    _fields_=[('request_id',C.c_uint64),('snapshot',Snapshot),('card',C.c_uint32),
              ('slot',C.c_uint32),('filename_bytes',C.c_uint32),('reserved',C.c_uint32),
              ('filename',C.c_char*64)]
class LutApRequestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix='camera-lut-ap-capture-');path=Path(cls.temp.name)/'request.so'
        subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror','-O2','-fPIC',
            '-dynamiclib' if sys.platform=='darwin' else '-shared',str(ROOT/'native/lut_ap_request.c'),
            str(ROOT/'native/lut_media.c'),'-o',str(path)],check=True,capture_output=True,text=True)
        cls.lib=C.CDLL(str(path));cls.lib.camera_lut_ap_capture_local_copy.argtypes=[C.c_void_p,C.c_size_t,C.c_size_t,C.c_uint64,C.c_uint64,C.c_uint64,C.POINTER(Request)];cls.lib.camera_lut_ap_capture_local_copy.restype=C.c_int
    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()
    def object(self,slot=3,card=0,name=b'look.cube',vtable=VTABLE,kind=3):
        raw=bytearray(704);struct.pack_into('<Q',raw,0,vtable);struct.pack_into('<I',raw,0x18,card)
        for n in (0,1):raw[0x1c+n*0x70+0x19]=ord('A')+n;struct.pack_into('<I',raw,0x1c+n*0x70+0x1c,kind)
        raw[0x16c:0x16c+len(name)]=name;struct.pack_into('<I',raw,0x1ac,slot&0xffffffff)
        return C.create_string_buffer(bytes(raw),len(raw))
    def capture(self,obj,selected=7,current=7,request_id=123,bytes_=704,vtable=VTABLE):
        out=Request();C.memset(C.byref(out),0x5a,C.sizeof(out));before=bytes(out)
        status=self.lib.camera_lut_ap_capture_local_copy(obj,bytes_,vtable,selected,current,request_id,C.byref(out))
        if status:self.assertEqual(bytes(out),before)
        return status,out
    def test_user_slots_and_owned_snapshot(self):
        for selected in (3,18):
            obj=self.object(slot=selected,card=1,name='夜景.CUBE'.encode(),kind=9)
            C.memmove(C.addressof(obj)+0x1c,struct.pack('<Q',C.addressof(obj)+0x200),8)
            status,out=self.capture(obj);self.assertEqual(status,0)
            self.assertEqual((out.request_id,out.card,out.slot,out.snapshot.generation),(123,1,selected-3,7))
            C.memset(obj,0xcc,704)
            self.assertEqual(out.filename,'夜景.CUBE'.encode())
            self.assertEqual(out.snapshot.media[0x70+0x19],ord('B'))
            allowed={0x19,0x70+0x19,*range(0x1c,0x20),*range(0x70+0x1c,0x70+0x20)}
            self.assertTrue(all(value==0 for index,value in enumerate(out.snapshot.media) if index not in allowed))
    def test_builtin_and_out_of_range_slots_rejected(self):
        for slot in (0,1,2,19,-1):self.assertNotEqual(self.capture(self.object(slot=slot))[0],0)
    def test_stale_or_unbound_generation_is_not_captured(self):
        self.assertEqual(self.capture(self.object(),selected=7,current=8)[0],6)
        self.assertEqual(self.capture(self.object(),selected=0)[0],2)
        self.assertEqual(self.capture(self.object(),current=0)[0],2)
    def test_wrong_object_type_or_truncated_view_rejected(self):
        self.assertEqual(self.capture(self.object(vtable=VTABLE+80))[0],5)
        self.assertNotEqual(self.capture(self.object(),bytes_=703)[0],0)
        self.assertNotEqual(self.capture(self.object(),vtable=0)[0],0)
    def test_filename_shape_and_traversal_rejected(self):
        for name in (b'',b'bad.txt',b'../bad.cube',b'A:bad.cube',b'x'*59+b'.cube'):
            self.assertNotEqual(self.capture(self.object(name=name))[0],0)
    def test_media_not_ready_and_invalid_card_rejected(self):
        self.assertEqual(self.capture(self.object(kind=0))[0],2)
        self.assertNotEqual(self.capture(self.object(card=2))[0],0)
    def test_request_token_and_overlapping_output_rejected(self):
        self.assertNotEqual(self.capture(self.object(),request_id=0)[0],0)
        obj=self.object();before=obj.raw
        out=C.cast(obj,C.POINTER(Request))
        status=self.lib.camera_lut_ap_capture_local_copy(obj,704,VTABLE,7,7,1,out)
        self.assertEqual(status,1);self.assertEqual(obj.raw,before)

if __name__=='__main__':unittest.main()
