"""Offline: map the A7M4 CP colour units onto the A7C II layout (core.merge_colors)."""
import struct, sys
d = sys.argv[1]
u1 = open(d + '/cp_02a40001.bin', 'rb').read()
ud = open(d + '/cp_02a4000d.bin', 'rb').read()

def row_sums(b):
    a, b_, c, d_, e, f = struct.unpack('<6h', b)
    return (a + b_ + 1024 - a - b_, d_ + 1024 - d_, 1024)

print('param -> slot (unit01 @0x1200 / unit0d @0x196)')
for p in range(80):
    s1, s2 = u1[0x1200 + p], ud[0x196 + p]
    if s1 or s2:
        print('  param %2d: unit01 slot %3d  unit0d slot %3d%s' % (p, s1, s2, '' if s1 == s2 else '  <-- differ'))
print('unit01 0x1200..0x1250 nonzero count:', sum(1 for b in u1[0x1200:0x1250] if b))
print('unit0d 0x196..0x1e0 nonzero count:', sum(1 for b in ud[0x196:0x1e0] if b))

print('\nchroma records (unit01 @0x1250 + slot*64), matrix records (unit0d @0x1e0 + slot*768)')
for slot in range(32):
    c = u1[0x1250 + slot * 64: 0x1250 + slot * 64 + 64]
    m = ud[0x1e0 + slot * 768: 0x1e0 + slot * 768 + 576]
    if 0x1250 + slot * 64 + 64 > len(u1): break
    used = any(c) or any(m)
    tail = any(c[48:])
    mats = [struct.unpack('<6h', m[i:i + 12]) for i in range(0, 576, 12)] if any(m) else []
    print('  slot %2d: chroma %s%s matrix %s' % (slot, 'set ' if any(c) else 'empty', ' (tail nonzero!)' if tail else '',
          ('set, first coeffs %s' % (mats[0],)) if mats else 'empty'))
for p, s in [(55, 23), (56, 25)]:
    print('\nA7C II target param %d slot %d: param free=%s, slot referenced=%s, slot data empty=%s' % (
        p, s, not (u1[0x1200 + p] or ud[0x196 + p]),
        s in u1[0x1200:0x1250] or s in ud[0x196:0x196 + 74],
        not (any(u1[0x1250 + s * 64:0x1250 + s * 64 + 64]) or any(ud[0x1e0 + s * 768:0x1e0 + s * 768 + 576]))))
