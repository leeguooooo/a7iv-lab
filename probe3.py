"""Third read-only probe: pull the A7M4 program files and system info through Jiritsu reads.

The A7C II tool reads /usr/lib/appFw.so and /cp/cpapp-b.bin as /tmp/jiritsu/../..<path>
(Jiritsu cmd 15 select + cmd 17 read). Only those two commands are sent; nothing is written.

Run: sudo DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib Sony-PMCA-RE/.venv/bin/python probe3.py
"""
import hashlib
import os
import struct
import sys
import time
import traceback

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'Sony-PMCA-RE'))

from pmca.commands.usb import senserShellCommand
from pmca.platform.backend.senser import SenserPlatformBackend

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'dumps', time.strftime('%Y%m%d-%H%M%S') + '-probe3')

FILES = [
 '/proc/version',
 '/proc/cmdline',
 '/proc/mounts',
 '/proc/partitions',
 '/proc/cpuinfo',
 '/etc/version',
 '/cp/cpapp-b.bin',
 '/usr/lib/appFw.so',
]
JIRITSU_MISSING = 0x10000006


def probe(camera):
 os.makedirs(OUT, exist_ok=True)
 SenserPlatformBackend(camera).start()

 def jiritsu(cmd, data):
  res, out = camera.dev.sendSenserPacket(0x40, struct.pack('<HH', 0x1001, cmd) + data)
  out = bytes(out or b'')
  if res or len(out) < 4:
   raise RuntimeError('jiritsu cmd %d: response %r, %d bytes' % (cmd, res, len(out)))
  return struct.unpack_from('<I', out)[0], out[4:]

 for path in FILES:
  print('\n== %s ==' % path)
  try:
   status, _ = jiritsu(15, b'\0' + ('/tmp/jiritsu/../..' + path).encode('ascii') + b'\0')
   if status:
    print('select status %#x' % status)
    continue
   t = time.time()
   status, data = jiritsu(17, b'\0\xff\0')
   if status == JIRITSU_MISSING:
    print('missing')
    continue
   if status:
    print('read status %#x' % status)
    continue
   name = path.strip('/').replace('/', '_')
   with open(os.path.join(OUT, name), 'wb') as f:
    f.write(data)
   print('%d bytes in %.1fs, sha256 %s' % (len(data), time.time() - t, hashlib.sha256(data).hexdigest()))
   if path.startswith('/proc') or path.startswith('/etc'):
    sys.stdout.write(data[:1500].decode('latin1', 'replace'))
  except Exception:
   traceback.print_exc(file=sys.stdout)


if __name__ == '__main__':
 senserShellCommand(complete=probe)
