"""Offline: look for each A7C II patch window's original bytes in the A7M4 programs."""
import json, sys
patches = json.load(open('ref/a7c2-fl23-research/src/camera_runtime/assets/patches.json'))
d = sys.argv[1]
progs = [open(d + '/usr_lib_appFw.so', 'rb').read(), open(d + '/cp_cpapp-b.bin', 'rb').read()]
names = ['appFw.so', 'cpapp-b.bin']
for chip, p in enumerate(patches):
    data = progs[chip]
    print('\n### %s (A7C II source %s..., A7M4 size %d)' % (names[chip], p['source_sha256'][:12], len(data)))
    for w in p['writes']:
        before = bytes.fromhex(w['before_hex'])
        hits, i = [], data.find(before)
        while i >= 0 and len(hits) < 6:
            hits.append(i); i = data.find(before, i + 1)
        n = data.count(before) if len(before) >= 4 else len(hits)
        print('  %-10s %5dB %-55s hits=%s%s' % (w['file_offset'], len(before), w['purpose'][:55],
              n, (' at ' + ','.join(hex(h) for h in hits[:4])) if hits and n <= 4 else ''))
