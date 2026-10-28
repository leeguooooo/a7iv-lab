"""Checked native sequence adapter stops config after failed/empty transfer."""
import ctypes as C
from pathlib import Path
import struct,subprocess,sys,tempfile,unittest
ROOT=Path(__file__).resolve().parents[1]
VTABLE=0x59d0a80
SEND=C.CFUNCTYPE(C.c_int,C.c_uint32,C.c_uint32,C.POINTER(C.c_uint32),C.POINTER(C.c_uint32))
CONFIG=C.CFUNCTYPE(C.c_int,C.c_uint32,C.c_uint32,C.c_uint32,C.c_uint32,C.c_void_p)
class Functions(C.Structure):_fields_=[('send',SEND),('config',CONFIG)]
class Result(C.Structure):_fields_=[('selected',C.c_uint32),('handle',C.c_uint32),('bytes',C.c_uint32),('config_called',C.c_uint32),('send_return',C.c_int32),('config_return',C.c_int32)]
class SelectGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix='camera-lut-select-guard-');p=Path(cls.temp.name)/'guard.so'
        subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror','-O2','-fPIC','-dynamiclib' if sys.platform=='darwin' else '-shared',str(ROOT/'native/lut_select_guard.c'),'-o',str(p)],check=True,capture_output=True,text=True)
        cls.lib=C.CDLL(str(p));cls.call=cls.lib.camera_lut_ap_select_checked
        cls.call.argtypes=[C.c_void_p,C.c_size_t,C.c_size_t,C.POINTER(Functions),C.POINTER(Result)];cls.call.restype=C.c_int
    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()
    def object(self,selected=3,exists=1,vtable=VTABLE):
        b=bytearray(112);struct.pack_into('<Q',b,0,vtable);struct.pack_into('<II',b,0x14,0x55,selected&0xffffffff);struct.pack_into('<I',b,0x6c,exists)
        b[0x2c:0x6c]=bytes(range(64));return C.create_string_buffer(bytes(b),112)
    def run_call(self,obj,send_ret=1,handle=0x1234,bytes_=48000,config_ret=1,mutate=False,capacity=112,vtable=VTABLE):
        events=[]
        @SEND
        def send(selected,exists,h,n):
            events.append(('send',selected,exists));h[0]=handle;n[0]=bytes_
            if mutate:C.memset(obj,0xcc,112)
            return send_ret
        @CONFIG
        def config(first,selected,h,n,metadata):
            events.append(('config',first,selected,h,n,C.string_at(metadata,64)));return config_ret
        functions=Functions(send,config);out=Result();C.memset(C.byref(out),0x5a,C.sizeof(out));before=bytes(out)
        status=self.call(obj,capacity,vtable,C.byref(functions),C.byref(out))
        if not events:self.assertEqual(bytes(out),before)
        return status,out,events
    def test_failed_send_never_requests_config_even_with_nonzero_outputs(self):
        for ret in (0,-1,2):
            status,out,events=self.run_call(self.object(),send_ret=ret)
            self.assertEqual(status,4);self.assertEqual(out.config_called,0);self.assertEqual(len(events),1)
    def test_success_without_user_handle_or_length_stops(self):
        for handle,n in [(0,48000),(4,0),(0,0)]:
            status,out,events=self.run_call(self.object(),handle=handle,bytes_=n)
            self.assertEqual(status,5);self.assertEqual(out.config_called,0);self.assertEqual(len(events),1)
    def test_valid_user_value_and_metadata_are_owned_through_callback(self):
        for selected in (3,18):
            status,out,events=self.run_call(self.object(selected),mutate=True)
            self.assertEqual(status,0);self.assertEqual(out.config_called,1)
            self.assertEqual(events[-1],('config',0x55,selected,0x1234,48000,bytes(range(64))))
    def test_builtin_zero_handle_config_preserved(self):
        for selected in (0,1,2):
            status,out,events=self.run_call(self.object(selected,0),handle=0,bytes_=0)
            self.assertEqual(status,0);self.assertEqual(len(events),2)
            self.assertEqual((out.handle,out.bytes,out.config_called),(0,0,1))
    def test_unavailable_and_invalid_selection_have_no_effect(self):
        for obj,status in [(self.object(3,0),3),(self.object(19),1),(self.object(-1),1),(self.object(3,2),1)]:
            got,_,events=self.run_call(obj);self.assertEqual(got,status);self.assertEqual(events,[])
    def test_bad_type_size_or_binding_have_no_effect(self):
        for obj,n,vt,status in [(self.object(vtable=4),112,VTABLE,2),(self.object(),111,VTABLE,1),(self.object(),112,0,1)]:
            got,_,events=self.run_call(obj,capacity=n,vtable=vt);self.assertEqual(got,status);self.assertEqual(events,[])
    def test_config_status_is_not_promoted_to_ack(self):
        for ret in (0,-1,2):
            status,out,events=self.run_call(self.object(),config_ret=ret)
            self.assertEqual(status,6);self.assertEqual(out.config_called,1);self.assertEqual(out.config_return,ret)
    def test_output_overlap_and_missing_callbacks_rejected(self):
        obj=self.object();before=obj.raw;out=C.cast(obj,C.POINTER(Result));functions=Functions()
        self.assertEqual(self.call(obj,112,VTABLE,C.byref(functions),out),1);self.assertEqual(obj.raw,before)
        result=Result();C.memset(C.byref(result),0x5a,C.sizeof(result));before=bytes(result)
        self.assertEqual(self.call(obj,112,VTABLE,C.byref(functions),C.byref(result)),1);self.assertEqual(bytes(result),before)
if __name__=='__main__':unittest.main()
