"""Pack the exact-v7 RAW matrix repair into a new offline-only SD candidate."""
from pathlib import Path
import hashlib
import json
import shutil
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT/'ref/sony-a7m4-custom-firmware'))
from a7m4.fat import Fat
from a7m4.fl23 import patch_program
from a7m4.firmware import tar_index, update_sum, encode, decode
from a7m4.offline import resign, sha256


def main():
    before = ROOT/'output/fl23-sd-version-02-UNTESTED'
    rawfix = ROOT/'output/fl23-v7-raw-candidate-01'
    out = ROOT/'output/fl23-sd-version-03-raw-UNTESTED'
    assert not out.exists()
    old_record = json.loads((before/'verification.json').read_text())
    assert sha256(before/'BODYDATA.DAT') == old_record['output_DAT_sha256'] == '6faf585139a508ab8a27cabab42880a316143f7e90928faa6bc3938b15bc768a'
    assert sha256(before/'work/plain.bin') == old_record['plaintext_sha256']
    candidate = (rawfix/'CPAPP-B.BIN').read_bytes()
    assert hashlib.sha256(candidate).hexdigest() == '8554826b1ef501436be1bf19c66f0a21cf055abd49e9a9a98676eaff03085af5'
    recipe = json.loads((rawfix/'cp-v7-raw-lossless-recipe.json').read_text())
    out.mkdir(mode=0o700)
    (out/'work').mkdir()
    plain = out/'work/plain.bin'
    shutil.copyfile(before/'work/plain.bin', plain)
    index = tar_index(plain)
    member, manifest = '0700_part_image/dev/nflasha8', '0701_part_image_sum/part_image.sum'
    changes = {}
    with plain.open('r+b') as f:
        def read(name):
            offset, size = index[name]
            f.seek(offset)
            data = f.read(size)
            assert len(data) == size
            return data
        def write(name, old, new):
            offset, size = index[name]
            assert len(old) == len(new) == size
            f.seek(offset)
            f.write(new)
            changes[name] = dict(offset=offset, bytes=size,
                before_sha256=hashlib.sha256(old).hexdigest(), after_sha256=hashlib.sha256(new).hexdigest())
        old = read(member)
        fs = Fat(old)
        cp_before = fs.read('CPAPP-B.BIN')
        assert patch_program(cp_before, recipe) == candidate
        fs.replace('CPAPP-B.BIN', candidate)
        new = fs.bytes()
        assert Fat(new).read('CPAPP-B.BIN') == candidate
        # The packaged CP volume is flat. Compare every other regular entry.
        assert Fat(old).entries() == Fat(new).entries()
        for name, (_, _, _, attr) in Fat(old).entries().items():
            if attr & 16 or name == 'CPAPP-B.BIN':
                continue
            assert Fat(old).read(name) == Fat(new).read(name)
        write(member, old, new)
        old_manifest = read(manifest)
        write(manifest, old_manifest, update_sum(old_manifest, {'dev/nflasha8': (old, new)}))
    assert tar_index(plain) == index
    with (before/'work/plain.bin').open('rb') as a, plain.open('rb') as b:
        cursor = 0
        for row in sorted(changes.values(), key=lambda r:r['offset']):
            while cursor < row['offset']:
                n = min(4<<20, row['offset']-cursor)
                assert a.read(n) == b.read(n)
                cursor += n
            cursor += row['bytes']
            a.seek(cursor)
            b.seek(cursor)
        while True:
            x, y = a.read(4<<20), b.read(4<<20)
            assert x == y
            if not x:
                break
    print(json.dumps({'stage':'CP_and_manifest_only','CP_SHA256':hashlib.sha256(candidate).hexdigest()}),flush=True)
    unsigned = out/'work/UNSIGNED_DO_NOT_INSTALL.DAT'
    encoding = encode(before/'BODYDATA.DAT', plain, unsigned)
    key = ROOT/'ref/sony-a7m4-custom-firmware/keys/published/A7M4_updater_private.pem'
    signing = resign(unsigned, key, out/'BODYDATA.DAT')
    checked = decode(out/'BODYDATA.DAT', compare=plain)
    assert checked['blocks_verified'] == 739727 and checked['compared_byte_for_byte']
    report = dict(status='OFFLINE_ONLY_NOT_INSTALLABLE', camera_io=False, camera_tested=False,
        source_DAT_sha256=old_record['output_DAT_sha256'], output_DAT_sha256=sha256(out/'BODYDATA.DAT'),
        plaintext_sha256=sha256(plain), changed_members=changes, other_plaintext_bytes_unchanged=True,
        CP_before_sha256=hashlib.sha256(cp_before).hexdigest(), CP_after_sha256=hashlib.sha256(candidate).hexdigest(),
        CP_recipe_sha256=sha256(rawfix/'cp-v7-raw-lossless-recipe.json'),
        receiver_and_target_version_gate=1, AP_and_updater_and_colour_templates_unchanged=True,
        RAW_models_verified=True, RAW_physical_acceptance=False,
        encoding=encoding, signing=signing, final_decoding=checked,
        remaining=['Full SR2 serializer/broader mode and photographed RAW validation',
                   'Independent NOR readback/recovery and safe transfer lifecycle',
                   'Normal menu preflight and installation/cold boot acceptance'])
    (out/'verification.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'status':report['status'],'output_DAT_sha256':report['output_DAT_sha256'],
                      'signature_verified':signing['signature_verified'],'blocks_verified':checked['blocks_verified']}),flush=True)


if __name__ == '__main__':
    main()
