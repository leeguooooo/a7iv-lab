"""Cooperative host ownership. A lock file or PID alone never proves liveness.

This locks participating tools only, not the camera or other independent apps.
An on-camera operation can outlive the host lock; unresolved transaction evidence
must therefore be handled separately before any later device operation.
"""
import datetime
import errno
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import uuid

DEFAULT_LOCK = Path(__file__).resolve().parent / 'output/camera-device-owner.lock'


class DeviceBusy(RuntimeError):
    pass


class CameraDeviceLease:
    def __init__(self, action, *, owner=None, lock_path=None):
        self.path = Path(lock_path) if lock_path is not None else DEFAULT_LOCK
        self.owner = owner or os.environ.get('CODEX_THREAD_ID') or f'pid:{os.getpid()}'
        if not all(isinstance(v,str) and re.fullmatch(r'[A-Za-z0-9/_:.\-]{1,120}',v)
                   for v in (action,self.owner)):
            raise ValueError('Bounded host action/owner labels required')
        self.action,self.fd,self.metadata = action,None,None

    def _record(self, state):
        self.metadata['state'] = state
        self.metadata['recorded_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        raw = (json.dumps(self.metadata,sort_keys=True)+'\n').encode()
        os.lseek(self.fd,0,os.SEEK_SET)
        done=0
        while done<len(raw):
            count=os.write(self.fd,raw[done:])
            if count<=0:raise OSError('Short host lease record')
            done+=count
        os.ftruncate(self.fd,len(raw));os.fsync(self.fd)

    def __enter__(self):
        if self.fd is not None:raise RuntimeError('Lease instance already entered')
        self.path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        self.fd=os.open(self.path,os.O_RDWR|os.O_CREAT|getattr(os,'O_NOFOLLOW',0),0o600)
        try:
            if not stat.S_ISREG(os.fstat(self.fd).st_mode):raise ValueError('Regular host lock required')
            try:fcntl.flock(self.fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except OSError as error:
                if error.errno in (errno.EAGAIN,errno.EWOULDBLOCK):
                    raise DeviceBusy('Another participating camera tool holds the live host lease') from error
                raise
            self.metadata={'schema':'camera-host-owner/1','owner':self.owner,'action':self.action,
                           'pid':os.getpid(),'instance':uuid.uuid4().hex,
                           'not_a_device_completion_receipt':True}
            self._record('HELD')
            return self
        except BaseException:
            os.close(self.fd);self.fd=None
            raise

    def __exit__(self,kind,error,traceback):
        try:
            try:self._record('RELEASED')
            except BaseException:
                if kind is None:raise
        finally:
            try:fcntl.flock(self.fd,fcntl.LOCK_UN)
            finally:os.close(self.fd);self.fd=None


def inspect_lease(lock_path=None):
    path=Path(lock_path) if lock_path is not None else DEFAULT_LOCK
    if not path.exists():return {'live_host_lock':False,'owner_metadata':None,'device_completion_proven':False}
    fd=os.open(path,os.O_RDWR|getattr(os,'O_NOFOLLOW',0))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):raise ValueError('Regular host lock required')
        try:metadata=json.loads(os.read(fd,4096))
        except (ValueError,UnicodeError):metadata=None
        try:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);busy=False
            fcntl.flock(fd,fcntl.LOCK_UN)
        except OSError as error:
            if error.errno not in (errno.EAGAIN,errno.EWOULDBLOCK):raise
            busy=True
        return {'live_host_lock':busy,'owner_metadata':metadata,'device_completion_proven':False}
    finally:os.close(fd)
