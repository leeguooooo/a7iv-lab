"""Real C media logic with explicit Fsys callback fixtures; no camera IO."""
import ctypes as C
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
class Snapshot(C.Structure):
    _fields_=[('media',C.c_ubyte*224),('generation',C.c_uint64)]
class Entry(C.Structure):
    _fields_=[('name_bytes',C.c_uint32),('status',C.c_uint32),('file_bytes',C.c_uint64),('name',C.c_char*256)]
class List(C.Structure):
    _fields_=[('media_generation',C.c_uint64),('card',C.c_uint32),('count',C.c_uint32),('status',C.c_uint32),('reserved',C.c_uint32),('entries',Entry*64)]
FIRST=C.CFUNCTYPE(C.c_int,C.c_void_p,C.c_char_p,C.c_void_p)
NEXT=C.CFUNCTYPE(C.c_int,C.c_void_p,C.c_void_p)
OPEN=C.CFUNCTYPE(C.c_int,C.c_void_p,C.c_char_p,C.POINTER(C.c_uint64))
READ=C.CFUNCTYPE(C.c_int,C.c_void_p,C.c_uint64,C.c_void_p,C.c_size_t,C.POINTER(C.c_size_t))
CLOSE=C.CFUNCTYPE(C.c_int,C.c_void_p,C.c_uint64)
class IO(C.Structure):
    _fields_=[('context',C.c_void_p),('find_first',FIRST),('find_next',NEXT),('open_read',OPEN),('read',READ),('close',CLOSE)]
APFIRST=C.CFUNCTYPE(C.c_int,C.c_char_p,C.c_void_p)
APNEXT=C.CFUNCTYPE(C.c_int,C.c_void_p)
APOPEN=C.CFUNCTYPE(C.c_int,C.c_char_p,C.c_uint32,C.POINTER(C.c_uint64))
APREAD=C.CFUNCTYPE(C.c_int,C.c_uint64,C.c_void_p,C.c_size_t,C.POINTER(C.c_size_t))
APCLOSE=C.CFUNCTYPE(C.c_int,C.c_uint64)
class Functions(C.Structure):
    _fields_=[('find_first',APFIRST),('find_next',APNEXT),('open',APOPEN),('read',APREAD),('close',APCLOSE)]

class Driver:
    def __init__(self,files=None,data=b'abc',chunk=None,bad_pointer=False,no_nul=False,
                 next_error=False,open_error=False,read_error=False,close_error=False,oversized_count=False):
        self.files=files or [];self.data=data;self.chunk=chunk;self.calls=[];self.paths=[]
        self.index=0;self.at=0
        def item(arena):
            if self.index==len(self.files):return 4
            name,size,flags=self.files[self.index];self.index+=1
            C.memset(arena,0,4096)
            ptr=arena+256 if not bad_pointer else arena+4096
            C.memmove(arena,struct.pack('<QQ',ptr,size),16)
            C.memmove(arena+0x26,bytes([flags]),1)
            if not bad_pointer:
                encoded=name.encode();C.memmove(arena+256,encoded,len(encoded))
                if no_nul:C.memset(arena+256,ord('x'),4096-256)
            return 0
        def first(ctx,path,arena):self.calls.append('first');self.paths.append(path);self.index=0;return item(arena)
        def nxt(ctx,arena):self.calls.append('next');return 3 if next_error else item(arena)
        def opn(ctx,path,handle):
            self.calls.append('open');self.paths.append(path);self.at=0;handle[0]=0
            return 3 if open_error else 0
        def read(ctx,handle,buffer,amount,count):
            self.calls.append('read')
            if read_error:return 3
            n=min(amount,len(self.data)-self.at)
            if self.chunk is not None:n=min(n,self.chunk)
            if n:C.memmove(buffer,self.data[self.at:self.at+n],n)
            self.at+=n;count[0]=amount+1 if oversized_count else n;return 0
        def close(ctx,handle):self.calls.append('close');return 3 if close_error else 0
        self.callbacks=[FIRST(first),NEXT(nxt),OPEN(opn),READ(read),CLOSE(close)]
        self.io=IO(None,*self.callbacks)

class LutMediaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix='camera-lut-media-host-');path=Path(cls.temp.name)/'media.so'
        subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror','-O2','-fPIC',
                        '-dynamiclib' if sys.platform=='darwin' else '-shared',str(ROOT/'native/lut_media.c'),'-o',str(path)],check=True,capture_output=True,text=True)
        cls.lib=C.CDLL(str(path));cls.lib.camera_lut_media_path.argtypes=[C.POINTER(Snapshot),C.c_uint32,C.c_char_p,C.c_size_t,C.c_void_p,C.c_size_t]
        cls.lib.camera_lut_media_scan.argtypes=[C.POINTER(IO),C.POINTER(Snapshot),C.c_uint32,C.c_void_p,C.c_size_t,C.POINTER(List)]
        cls.lib.camera_lut_media_read.argtypes=[C.POINTER(IO),C.POINTER(Snapshot),C.c_uint32,C.POINTER(Entry),C.c_uint64,C.c_void_p,C.c_size_t,C.POINTER(C.c_size_t)]
        cls.lib.camera_lut_media_bind_wrappers.argtypes=[C.POINTER(IO),C.POINTER(Functions)]
        cls.lib.camera_lut_media_bind_wrappers.restype=C.c_int
        for name in ['camera_lut_media_path','camera_lut_media_scan','camera_lut_media_read']:getattr(cls.lib,name).restype=C.c_int
    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()
    def snapshot(self,kind=3,generation=7):
        value=Snapshot();value.generation=generation
        for card,letter in [(0,b'A'),(1,b'B')]:
            C.memmove(C.addressof(value)+card*0x70+0x19,letter,1)
            C.memmove(C.addressof(value)+card*0x70+0x1c,struct.pack('<I',kind),4)
        return value
    def path(self,snapshot,name=b'look.cube',card=0,capacity=512):
        out=C.create_string_buffer(b'X'*capacity,capacity);before=out.raw
        status=self.lib.camera_lut_media_path(C.byref(snapshot),card,name,len(name),out,capacity)
        if status:self.assertEqual(out.raw,before)
        return status,out.value
    def scan(self,driver,snapshot=None,card=0,arena_size=4096):
        snapshot=snapshot or self.snapshot();arena=C.create_string_buffer(arena_size);out=List()
        status=self.lib.camera_lut_media_scan(C.byref(driver.io),C.byref(snapshot),card,arena,arena_size,C.byref(out))
        if status:self.assertEqual((out.count,out.status),(0,status))
        return status,out
    def read(self,driver,snapshot=None,size=3,name=b'look.cube',selected_generation=7,capacity=None):
        snapshot=snapshot or self.snapshot();entry=Entry(len(name),0,size,name);capacity=capacity if capacity is not None else size+1
        data=C.create_string_buffer(capacity);count=C.c_size_t(0x1234)
        status=self.lib.camera_lut_media_read(C.byref(driver.io),C.byref(snapshot),0,C.byref(entry),selected_generation,data,capacity,C.byref(count))
        if status:self.assertEqual(count.value,0x1234)
        return status,data.raw[:count.value] if not status else b''
    def test_native_directory_routes_and_cards(self):
        self.assertEqual(self.path(self.snapshot()),(0,b'A:/Private/Sony/PRO/LUT/look.cube'))
        self.assertEqual(self.path(self.snapshot(9),card=1),(0,b'B:/Sony/PRO/LUT/look.cube'))
    def test_unbound_or_unknown_media_and_path_components(self):
        for snap in [self.snapshot(0),self.snapshot(1),self.snapshot(generation=0)]:self.assertNotEqual(self.path(snap)[0],0)
        for name in [b'../look.cube',b'A:look.cube',b'x\\look.cube',b'bad\n.cube',b'']:
            self.assertNotEqual(self.path(self.snapshot(),name)[0],0)
        self.assertNotEqual(self.path(self.snapshot(),card=2)[0],0)
        self.assertNotEqual(self.path(self.snapshot(),capacity=5)[0],0)
    def test_scan_filters_directories_and_preserves_names(self):
        driver=Driver([('.',0,16),('..',0,16),('folder.cube',4,16),('notes.txt',9,0),('夜景.CuBe',42,0)])
        status,out=self.scan(driver);self.assertEqual(status,0);self.assertEqual((out.count,out.media_generation),(1,7))
        self.assertEqual(out.entries[0].name,'夜景.CuBe'.encode());self.assertEqual(out.entries[0].file_bytes,42)
        self.assertEqual(driver.paths,[b'A:/Private/Sony/PRO/LUT/*.*'])
    def test_scan_shows_ineligible_files_with_status(self):
        status,out=self.scan(Driver([('empty.cube',0,0),('huge.cube',32*1024*1024+1,0)]))
        self.assertEqual((status,out.count),(0,2));self.assertEqual([out.entries[n].status for n in range(2)],[4,4])
    def test_empty_scan_and_capacity_limit(self):
        self.assertEqual(self.scan(Driver())[0],0)
        self.assertEqual(self.scan(Driver([(f'{n}.cube',3,0) for n in range(65)]))[0],4)
    def test_scan_corruption_and_partial_errors_clear_count(self):
        for driver in [Driver([('a.cube',3,0)],bad_pointer=True),Driver([('a.cube',3,0)],no_nul=True),Driver([('bad/entry.cube',3,0)]),Driver([('a.cube',3,0)],next_error=True)]:
            self.assertNotEqual(self.scan(driver)[0],0)
        self.assertNotEqual(self.scan(Driver(),arena_size=3112)[0],0)
    def test_file_read_handles_short_reads_and_zero_opaque_handle(self):
        driver=Driver(data=b'abcdefgh',chunk=2);self.assertEqual(self.read(driver,size=8),(0,b'abcdefgh'))
        self.assertEqual(driver.calls.count('close'),1);self.assertEqual(driver.paths,[b'A:/Private/Sony/PRO/LUT/look.cube'])
    def test_card_generation_change_rejects_before_io(self):
        driver=Driver();self.assertEqual(self.read(driver,snapshot=self.snapshot(generation=8))[0],6);self.assertFalse(driver.calls)
    def test_file_growth_and_truncation_are_stale(self):
        for data in [b'ab',b'abcd']:
            driver=Driver(data=data);self.assertEqual(self.read(driver)[0],6);self.assertEqual(driver.calls.count('close'),1)
    def test_read_errors_and_close_failure_do_not_commit_count(self):
        for options in [dict(read_error=True),dict(close_error=True),dict(oversized_count=True)]:
            driver=Driver(**options);self.assertEqual(self.read(driver)[0],3);self.assertEqual(driver.calls.count('close'),1)
        driver=Driver(open_error=True);self.assertEqual(self.read(driver)[0],3);self.assertNotIn('close',driver.calls)
    def test_invalid_selection_and_small_capacity_do_not_open(self):
        for options in [dict(name=b'x.txt'),dict(name=b'../x.cube'),dict(capacity=3),dict(size=0)]:
            driver=Driver();self.assertNotEqual(self.read(driver,**options)[0],0);self.assertFalse(driver.calls)

    def test_ap_wrapper_glue_forces_read_mode_and_preserves_opaque_handle(self):
        calls=[]
        def opn(path,mode,handle):calls.append(('open',path,mode));handle[0]=0x123456789abcdef0;return 0
        def read(handle,buffer,amount,count):calls.append(('read',handle,amount));count[0]=0;return 0
        callbacks=[APFIRST(lambda p,i:4),APNEXT(lambda i:4),APOPEN(opn),APREAD(read),APCLOSE(lambda h:calls.append(('close',h)) or 0)]
        table=Functions(*callbacks);io=IO()
        self.assertEqual(self.lib.camera_lut_media_bind_wrappers(C.byref(io),C.byref(table)),0)
        handle=C.c_uint64();self.assertEqual(io.open_read(io.context,b'A:/x.cube',C.byref(handle)),0)
        count=C.c_size_t();buffer=C.create_string_buffer(8)
        io.read(io.context,handle.value,buffer,8,C.byref(count));io.close(io.context,handle.value)
        self.assertEqual(calls,[('open',b'A:/x.cube',0),('read',0x123456789abcdef0,8),('close',0x123456789abcdef0)])

    def test_binding_rejects_missing_functions_without_replacing_io(self):
        io=Driver().io;before=bytes(io);bad=Functions()
        self.assertEqual(self.lib.camera_lut_media_bind_wrappers(C.byref(io),C.byref(bad)),1)
        self.assertEqual(bytes(io),before)

if __name__=='__main__':unittest.main()
