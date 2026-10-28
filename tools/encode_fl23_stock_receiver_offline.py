"""Encode an offline research container. No camera, card copy or installer.

Uses ONLY the exact upstream intentionally-public research signing key, whose
publication is documented under keys/published/README.md. This signature gives
no publisher authentication and is not a Sony signature or installation permit.
"""
import hashlib
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
REF = ROOT / 'ref/sony-a7m4-custom-firmware'
sys.path.insert(0, str(ROOT));sys.path.insert(0, str(REF))
from a7m4.firmware import encode, decode
from a7m4.offline import resign
from verify_sd_package_local import verify
from cryptography.hazmat.primitives import serialization

PLAIN = ROOT / 'output/fl23-stock-receiver-plain-01/plain.DO_NOT_INSTALL.bin'
TEMPLATE = ROOT / 'output/fl23-sd-version-02-UNTESTED/BODYDATA.DAT'
KEYS = REF / 'keys/published'
OUT = ROOT / 'output/fl23-stock-receiver-container-01'


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def main():
    os.umask(0o077)
    require(sha(REF / 'a7m4/firmware.py') == '102546f152d429300f4dc98e416f070592618b7fd40ae73fa7790080ef0abc94'
            and sha(REF / 'a7m4/offline.py') == '60ff6f49d2ff72f40ab134e677750bb12408e8e790342ce393bfd52d52ce5320',
            'Pinned codec/signing implementation changed')
    require(sha(PLAIN) == 'ebc7f537c21b685609f646670ab8b381db15d7283d259cbb587a2c0a008a51bf'
            and sha(TEMPLATE) == '6faf585139a508ab8a27cabab42880a316143f7e90928faa6bc3938b15bc768a',
            'Bound plaintext/template changed')
    public, private = KEYS / 'A7M4_updater_public.pem', KEYS / 'A7M4_updater_private.pem'
    require(sha(public) == 'c39f3d878e129bbac87ad346182df754d7dd99d80c35c38bbb6517e37ca8e449'
            and sha(private) == '2f69f8feade5f651484a5ff44f9b3e8e2aa471f0c025507d82b55542894a82fe',
            'Only the intentionally published upstream research pair admitted')
    pub = public.read_bytes()
    key = serialization.load_pem_public_key(pub)
    fingerprint = hashlib.sha256(key.public_bytes(serialization.Encoding.DER,
                                                  serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()
    require(fingerprint == 'eed3fd52e3adc60ef13b584bc0b50345ee96639be81efa02e0031a6eccc65e76',
            'Research public identity changed')
    audit = json.loads((PLAIN.parent / 'independent-root-audit.json').read_text())
    require(audit['all_passed'] is True and audit['plaintext_sha256'] == sha(PLAIN),
            'Independent plaintext audit missing')
    OUT.mkdir(mode=0o700)
    unsigned = OUT / 'UNSIGNED_DO_NOT_INSTALL.DAT'
    final = OUT / 'BODYDATA.UNTESTED_DO_NOT_INSTALL.DAT'
    encoding = encode(TEMPLATE, PLAIN, unsigned)
    print('Encoding/frame roundtrip passed; signing public research container', flush=True)
    signing = resign(unsigned, private, final)
    decoding = decode(final, compare=PLAIN)
    independent = verify(final, PLAIN, pub)
    require(independent['blocks_verified'] == 739727 and independent['plaintext_sha256'] == sha(PLAIN)
            and independent['rsa_signature_verified'] and independent['dend_crc_verified']
            and independent['compared_byte_for_byte'], 'Independent encrypted-container verification failed')
    for p in (unsigned, final):
        with p.open('r+b') as f:
            f.flush();os.fsync(f.fileno())
    report = dict(status='OFFLINE_RESEARCH_CONTAINER_NOT_ADMITTED_FOR_INSTALL',
        plaintext_sha256=sha(PLAIN), container_sha256=sha(final), container_bytes=final.stat().st_size,
        public_key_fingerprint=fingerprint, signing_identity='INTENTIONALLY_PUBLIC_RESEARCH_KEY_NOT_SONY',
        private_key_source='exact pinned upstream keys/published pair; explicitly public',
        personal_private_keys_accessed=False, publisher_authentication_proven=False,
        encoding=encoding, signing=signing, decoding=decoding, independent_verification=independent,
        SD_package_accepted_by_camera=False, installation_approved=False, camera_operations=0,
        LUT_or_sound_installed=False, experimental_RAW_patch_included=False,
        builder_sha256=sha(Path(__file__)), independent_verifier_sha256=sha(ROOT / 'verify_sd_package_local.py'))
    with (OUT / 'manifest.json').open('x') as f:
        json.dump(report, f, indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
    unsigned.unlink()  # Reproducible intermediate only; final, plaintext and all audit records retained.
    print(json.dumps({k: report[k] for k in ('status', 'container_sha256', 'container_bytes', 'camera_operations')}))


if __name__ == '__main__':
    main()
