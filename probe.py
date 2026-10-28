"""One-shot read-only service mode probe for the A7M4.

Exiting service mode leaves the camera stuck as 054C:096F until it is power-cycled,
so everything is done inside a single session: device info, backup preset dump,
boot rom dump, and a batch of read-only commands on the service terminal.
Nothing is written to the camera.

Run: sudo DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib Sony-PMCA-RE/.venv/bin/python probe.py
"""
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'Sony-PMCA-RE'))

from pmca.commands.usb import senserShellCommand
from pmca.platform import PropertyInterface
from pmca.platform.backend.senser import SenserPlatformBackend

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'dumps', time.strftime('%Y%m%d-%H%M%S'))

TERMINAL_COMMANDS = [
 'id',
 'uname -a',
 'cat /proc/version',
 'cat /proc/cpuinfo',
 'cat /proc/meminfo | head -5',
 'cat /proc/partitions',
 'cat /proc/mtd',
 'cat /proc/cmdline',
 'mount',
 'df',
 'ls -la /',
 'ls -la /dev/block /dev/mmcblk* 2>/dev/null | head -60',
 'ls -la /setting /android /opt 2>/dev/null',
 'ps',
]


def save(name, data):
 path = os.path.join(OUT, name)
 with open(path, 'wb') as f:
  f.write(data)
 print('saved %s (%d bytes)' % (path, len(data)))


def step(name, fn):
 print('\n== %s ==' % name)
 try:
  fn()
 except Exception as e:
  print('failed: %r' % e)


def read_terminal(dev, seconds):
 buf = b''
 end = time.time() + seconds
 while time.time() < end:
  d = dev.dev.readTerminal()
  if d:
   buf += bytes(d)
   end = max(end, time.time() + 1)
 return buf


def probe(camera):
 os.makedirs(OUT, exist_ok=True)
 backend = SenserPlatformBackend(camera)
 backend.start()
 log = []

 def info():
  for id, desc, value in PropertyInterface(backend).getProps():
   line = '%-20s%s' % (desc + ': ', value)
   print(line)
   log.append(line)
  save('info.txt', '\n'.join(log).encode())

 def backup():
  save('backup_status.bin', bytes(backend.getBackupStatus()))
  save('backup_preset.bin', bytes(backend.getBackupData()))

 def bootrom():
  with open(os.path.join(OUT, 'bootrom.bin'), 'wb') as f:
   backend.readMemory(0xffff0000, 0x6000, f)
  print('saved bootrom.bin')

 def terminal():
  camera.setTerminalEnable(False)
  camera.setTerminalEnable(True)
  out = read_terminal(camera, 3)
  for cmd in TERMINAL_COMMANDS:
   camera.dev.writeTerminal(('%s\n' % cmd).encode())
   out += read_terminal(camera, 2)
  camera.setTerminalEnable(False)
  save('terminal.txt', out)
  sys.stdout.write(out.decode('latin1', 'replace'))

 step('info', info)
 step('backup preset (read)', backup)
 step('boot rom (read)', bootrom)
 step('service terminal (read-only commands)', terminal)


if __name__ == '__main__':
 senserShellCommand(complete=probe)
