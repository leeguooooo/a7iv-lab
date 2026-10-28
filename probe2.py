"""Second read-only probe: check whether the channels the A7C II tool relies on exist on the A7M4.

- Jiritsu select/read (0x1001 cmd 15/17) of a file that does not exist
- CP unit reads (AdjustControl 0x603/0x40) for the A7C II keys
- service terminal again, with a traceback to see which call fails
Nothing is written to the camera (Jiritsu 16/18 and CP 0x41 are never sent).

Run: sudo DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib Sony-PMCA-RE/.venv/bin/python probe2.py
"""
import os
import struct
import sys
import time
import traceback

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'Sony-PMCA-RE'))

from pmca.commands.usb import senserShellCommand
from pmca.platform.backend.senser import SenserPlatformBackend

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'dumps', time.strftime('%Y%m%d-%H%M%S') + '-probe2')

# Keys used on the A7C II 2.01 (appFw.so / cpapp-b.bin); the A7M4 may use others.
CP_KEYS = [0x02a40001, 0x02a4000d]
JIRITSU_MISSING = 0x10000006


def save(name, data):
 path = os.path.join(OUT, name)
 with open(path, 'wb') as f:
  f.write(data)
 print('saved %s (%d bytes)' % (path, len(data)))


def step(name, fn):
 print('\n== %s ==' % name)
 try:
  fn()
 except Exception:
  traceback.print_exc(file=sys.stdout)


def probe(camera):
 os.makedirs(OUT, exist_ok=True)
 backend = SenserPlatformBackend(camera)
 backend.start()

 def jiritsu(cmd, data):
  res, out = camera.dev.sendSenserPacket(0x40, struct.pack('<HH', 0x1001, cmd) + data)
  out = bytes(out or b'')
  status = struct.unpack_from('<I', out)[0] if len(out) >= 4 else None
  print('jiritsu cmd %d -> response %r, status %s, %d bytes' % (cmd, res, '%#x' % status if status is not None else None, len(out)))
  return status, out

 def jiritsu_probe():
  path = b'/tmp/jiritsu/camera-use-probe-missing'
  status, _ = jiritsu(15, b'\0' + path + b'\0')
  if status == 0:
   status, _ = jiritsu(17, b'\0\xff\0')
   if status == JIRITSU_MISSING:
    print('jiritsu channel works (file reported missing, as expected)')

 def cp_probe():
  for key in CP_KEYS:
   try:
    data = bytes(camera._sendAdjustControlPacket(0x603, 0x40, struct.pack('<II', key, 1)))
    print('cp %#010x -> %d bytes' % (key, len(data)))
    save('cp_%08x.bin' % key, data)
   except Exception as e:
    print('cp %#010x failed: %r' % (key, e))

 def terminal_probe():
  print('setTerminalEnable(False)')
  camera.setTerminalEnable(False)
  print('setTerminalEnable(True)')
  camera.setTerminalEnable(True)
  print('readTerminal')
  print(repr(bytes(camera.dev.readTerminal())))
  camera.setTerminalEnable(False)

 step('jiritsu (select + read, missing file)', jiritsu_probe)
 step('cp units (read only)', cp_probe)
 step('service terminal (debug)', terminal_probe)


if __name__ == '__main__':
 senserShellCommand(complete=probe)
