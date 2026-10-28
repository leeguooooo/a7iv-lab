"""Freeze separate fixed-P1 tools from the sealed reader build/model sources.

Only target admission, schema, and self-provenance names change. Native stream
logic and synthetic syscalls remain unchanged. Existing batch sources stay intact.
"""
import hashlib
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def change(text, old, new):
    if text.count(old) != 1:
        raise ValueError('Donor structure changed')
    return text.replace(old, new)


def main():
    donors = [
        ('build_remaining_backup_worker.py', 'fc326f129f0abb0c3a114912ad92f0d25d7b457b151eed7464fdafe662fbc812',
         'build_stock_p1_readback_worker_offline.py'),
        ('emulate_remaining_backup_worker.py', '7424fd3ff665f7644d1c8e3d61681b4d1462d08d9e4d8ea67f0946c57ad84e5e',
         'emulate_stock_p1_readback_worker_offline.py')]
    for old_name, digest, new_name in donors:
        raw = (ROOT / 'tools' / old_name).read_bytes()
        if hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError('Sealed donor hash changed')
        text = raw.decode()
        text = change(text, 'camera-remaining-offline-worker/1', 'camera-stock-p1-readback-offline-worker/1')
        if old_name.startswith('build_'):
            text = change(text, 'from camera_stream_profiles import PROFILES, profile',
                'from camera_stream_profiles import RemainingProfile\n'
                'PROFILES = (RemainingProfile("cnflasha1", 129, 25100288, 9728),)\n\n'
                'def profile(name):\n'
                '    if name != "cnflasha1":\n'
                '        raise ValueError("Only fixed P1 readback admitted")\n'
                '    return PROFILES[0]\n')
            text = change(text, 'out.mkdir(mode=0o700, parents=True)',
                          'out.mkdir(mode=0o700, parents=True, exist_ok=False)')
        else:
            start = text.index('PROFILES = {\n')
            end = text.index('\n}\n', start) + 3
            text = change(text, text[start:end], 'PROFILES = {"cnflasha1": (129, 25100288, 9728)}\n')
            text = change(text, 'tools/build_remaining_backup_worker.py',
                          'tools/build_stock_p1_readback_worker_offline.py')
        banner = ('# Derived OFFLINE for fixed cn1 only; donor ' + old_name + ' SHA256 ' + digest + '\n')
        with (ROOT / 'tools' / new_name).open('x') as f:
            os.fchmod(f.fileno(), 0o600)
            f.write(banner + text)
        print(new_name)


if __name__ == '__main__':
    main()
