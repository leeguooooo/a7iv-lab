"""Create a separate P1-only bootstrap builder from a sealed offline donor."""
import hashlib
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    donor = ROOT / 'tools/prepare_remaining_bootstrap.py'
    raw = donor.read_bytes()
    digest = 'ad02ccc68cdb559a782866c2947c5fa35ecaa5857304df28458673e4dc2bc85e'
    if hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError('Sealed bootstrap donor changed')
    text = raw.decode()
    for old, new in (
        ('from tools.emulate_remaining_backup_worker import',
         'from tools.emulate_stock_p1_readback_worker_offline import'),
        ('tools/emulate_remaining_backup_worker.py', 'tools/emulate_stock_p1_readback_worker_offline.py'),
        ('camera-remaining-bootstrap-offline/1', 'camera-stock-p1-readback-bootstrap-offline/1'),
    ):
        if text.count(old) != 1:
            raise ValueError('Donor structure changed')
        text = text.replace(old, new)
    with (ROOT / 'tools/prepare_stock_p1_readback_bootstrap_offline.py').open('x') as f:
        os.fchmod(f.fileno(), 0o600)
        f.write('# Offline fixed-P1 derivation; donor SHA256 ' + digest + '\n' + text)


if __name__ == '__main__':
    main()
