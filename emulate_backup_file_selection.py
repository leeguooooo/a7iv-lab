"""Offline replay of M4 backup-file selection/save control flow.

Executes analysis-linked original AArch64 selectors, Data_check, and save_file.
Models VFS reads/writes, checksum calculation, mutexes and body reload/validation.
Never opens a camera or writes a backup image. Reports omit personal contents.
"""
import hashlib
import json
import struct
from pathlib import Path
from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3, UC_ARM64_REG_LR, UC_ARM64_REG_PC, UC_ARM64_REG_SP
from a7m4.fat import Fat

ROOT = Path(__file__).resolve().parent
ELF = ROOT/'local/analysis/m4-persistence/linked/backup.analysis.elf'
EXPECTED = 'f0e083703a6ff669574dfad39ef4b0495e20a87b93f202d420bdc931ce3b5c3a'
STATE = 0x112d70


class Replay:
    def __init__(self, selected=0, fail=None):
        assert hashlib.sha256(ELF.read_bytes()).hexdigest() == EXPECTED
        self.u = u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        u.mem_map(0x100000, 0x500000)
        with ELF.open('rb') as f:
            e = ELFFile(f)
            self.sy = {s.name:s['st_value'] for s in e.get_section_by_name('.symtab').iter_symbols() if s.name}
            for seg in e.iter_segments():
                if seg['p_type']=='PT_LOAD' and seg['p_filesz']:
                    u.mem_write(seg['p_vaddr'], seg.data())
        u.mem_map(0x20000000, 0x4000000)
        self.live, self.work, self.heap = 0x20000000, 0x20800000, 0x21000000
        self.stack, self.stop = 0x23e00000, 0x23f00000
        self.fail = fail
        self.events = []
        self.writes = 0
        self.returned = False
        self.files = {}
        src = Fat((ROOT/'output/backup-01/execution/cnflasha2.bin').read_bytes()).read('BACKUP.BIN')
        self.original_sha = hashlib.sha256(src).hexdigest()
        self.size = len(src)
        self.initial_count = 50
        for i,name in enumerate(['/setting/Backup.bin','/setting/Backup.bak']):
            data = bytearray(src)
            struct.pack_into('<I', data, 0x2c, 50 if i==selected else 49)
            # Header-only Data_check selects on cookie, state and count; VFS
            # reload validation is modeled separately, not claimed as tested.
            self.files[name] = bytes(data)
        u.mem_write(self.live, self.files[['/setting/Backup.bin','/setting/Backup.bak'][selected]])
        u.mem_write(self.work, src)
        u.mem_write(self.sy['Backup_bin_start'], struct.pack('<Q',self.live))
        u.mem_write(self.sy['Backup_bin_size'], struct.pack('<Q',self.size))
        header_global=struct.unpack('<Q',bytes(u.mem_read(0x1057e8,8)))[0]
        u.mem_write(header_global,struct.pack('<Q',self.live))
        self.primary = 0x23d00000
        u.mem_write(self.primary, b'/setting/Backup.bin\0')
        u.mem_write(STATE+0x90,b'/setting/Backup.bak\0')
        u.mem_write(STATE+0xd0,struct.pack('<Q',self.primary))
        u.mem_write(STATE+0xd8,struct.pack('<II',selected,50))
        self.imports={v:k for k,v in self.sy.items() if k in ['mutex_lock','mutex_unlock','vfree','strlen','strncpy']}
        self.hooks={self.sy[k]:k for k in ['backup_logrec','backupfile_load_file','Data_CalChecksum']}
        self.hooks.update({0x105d40:'write_file',0x106618:'reload_body',0x105fb0:'file_exists'})
        u.hook_add(UC_HOOK_CODE,self.hook)

    def string(self,a):
        return bytes(self.u.mem_read(a,256)).split(b'\0',1)[0].decode()

    def ret(self,value=0):
        self.u.reg_write(UC_ARM64_REG_X0,value&((1<<64)-1))
        self.u.reg_write(UC_ARM64_REG_PC,self.u.reg_read(UC_ARM64_REG_LR))

    def hook(self,u,addr,size,ctx):
        if addr==self.stop:
            self.returned=True;u.emu_stop();return
        name=self.hooks.get(addr,self.imports.get(addr))
        if not name:return
        a,b,c,d=[u.reg_read(r) for r in [UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3]]
        if name in ['mutex_lock','mutex_unlock','vfree','backup_logrec']:
            self.ret();return
        if name=='strlen':self.ret(len(self.string(a)));return
        if name=='strncpy':
            s=self.string(b).encode()[:c];u.mem_write(a,s+bytes(c-len(s)));self.ret(a);return
        if name=='file_exists':self.ret(0 if self.string(a) in self.files else -1);return
        if name=='Data_CalChecksum':
            # The selection/save control flow is tested, not Sony checksum code.
            self.ret(0);return
        if name=='backupfile_load_file':
            path=self.string(a);raw=self.files.get(path)
            if raw is None:self.ret(0);return
            n=struct.unpack('<Q',bytes(u.mem_read(b,8)))[0]
            n=min(n,len(raw));p=self.heap;self.heap+=(n+4095)&~4095
            u.mem_write(p,raw[:n]);self.ret(p);return
        if name=='reload_body':
            path=self.string(a);self.events.append({'kind':'reload_body','path':path})
            if self.fail=='reload':self.ret(-5);return
            u.mem_write(self.live,self.files[path]);self.ret(0);return
        if name=='write_file':
            path=self.string(a);self.writes+=1;raw=bytes(u.mem_read(c,d))
            failure=(self.fail=='body' and self.writes==1) or (self.fail=='header' and self.writes==2)
            written=d//2 if failure else d
            old=self.files.get(path,b'');self.files[path]=raw[:written]+old[written:]
            self.events.append({'kind':'write','path':path,'flags':hex(b),'requested':d,'written':written,'return':-5 if failure else 0})
            self.ret(-5 if failure else 0);return
        raise RuntimeError(name)

    def call(self,entry,*args):
        self.returned=False
        self.u.reg_write(UC_ARM64_REG_SP,self.stack)
        self.u.reg_write(UC_ARM64_REG_LR,self.stop)
        for r,v in zip([UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3],args):self.u.reg_write(r,v)
        self.u.emu_start(entry,0,count=2000000)
        assert self.returned,'Instruction bound'
        return self.u.reg_read(UC_ARM64_REG_X0)&0xffffffff

    def current(self):
        self.call(self.sy['backupfile_get_filename'],0)
        return self.string(self.u.reg_read(UC_ARM64_REG_X0))

    def save(self):
        return self.call(self.sy['backupfile_save_file'],0,self.work,self.size)


def main():
    results=[]
    for selected in [0,1]:
        r=Replay(selected)
        before=r.current();s1=r.save();mid=r.current();s2=r.save();after=r.current()
        paths=[x['path'] for x in r.events if x['kind']=='write']
        assert s1==s2==0 and before!=mid and before==after
        assert paths==[mid,mid,before,before]
        assert struct.unpack_from('<I',r.files[mid],0x2c)[0]==51
        assert struct.unpack_from('<I',r.files[before],0x2c)[0]==52
        results.append({'case':'double_save','initial_selected':before,'after_first':mid,'after_second':after,'returns':[s1,s2],'events':r.events,'passed':True})
    for failure in ['body','header','reload']:
        r=Replay(0,failure);before=r.current();code=r.save();after=r.current()
        assert code==(0 if failure=='reload' else 0xfffffffb)
        assert before==after
        results.append({'case':'failure_'+failure,'return_u32':hex(code),'selection_unchanged':True,'events':r.events,'passed':True})
    r=Replay();arg=0x23d01000;r.u.mem_write(arg,b'/setting/Backup.bin\0')
    assert r.call(0x106030,arg)==0
    assert r.string(STATE+0x90)=='/setting/Backup.bak'
    results.append({'case':'derive_backup_path','input':'/setting/Backup.bin','derived':'/setting/Backup.bak','passed':True})
    out=ROOT/'output/rea-study/m4-persistence-followup-01';out.mkdir(mode=0o700,exist_ok=True)
    report={'hardware_io':False,'analysis_elf_sha256':EXPECTED,'source_backup_sha256':r.original_sha,'executed_real_functions':['backupfile_get_filename','backupfile_save_file','backupfile_load','Data_check','Data_GetCount','Data_SetCount','path-selection helper0x6030'],'modeled_functions':['VFS load/write (including partial writes)','body reload/validation','Data_CalChecksum','mutexes','logging','strlen/strncpy'],'does_not_validate':['physical filesystem/power failure','actual checksum algorithm','CP synchronization helpers','full senser_cmd_save entry and both group merge passes'],'tests':results,'all_passed':True}
    (out/'file-selection-emulation.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'all_passed':True,'tests':len(results),'results':[{'case':x['case'],'passed':x['passed']} for x in results]}))


if __name__=='__main__':main()
