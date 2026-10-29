"""Pinned offline inputs for a fixed previous-receipt current RAM observation."""
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from menu_window_profile import (ROOT, APP, COMPILER, COMPILER_SHA, MODULES,
    input_evidence as stock_evidence, require, read_regular, sha, mapped)
sys.path.insert(0, str(ROOT))
import camera_install_patch_read as contract

SCHEMA = 'camera-install-patch-read-offline/1'
PROFILE = 'fixed_previous_patch_current_ram_read'
SOURCE_PATHS = ('native/install_patch_read.c', 'tools/install_patch_read_profile.py',
    'tools/build_install_patch_read_offline.py', 'tools/verify_install_patch_read_offline.py',
    'tools/emulate_install_patch_read_offline.py', 'camera_install_patch_read.py',
    'camera_install_volatile.py', 'tools/menu_window_profile.py', 'tools/verify_menu_window_offline.py',
    'tools/emulate_stream_bootstrap.py', 'tools/model_toolchain_bootstraps_offline.py')


def input_evidence():
    sources, libraries = stock_evidence()
    for name in SOURCE_PATHS:
        sources[name] = hashlib.sha256(read_regular(ROOT / name)).hexdigest()
    require(contract.MAGIC == b'M4IPR001' and contract.START_MAGIC == b'M4RSTART'
            and contract.VERSION == 1 and len(contract.FIELDS) == 44
            and contract.FRAME.format == '<8s16s16s32s44q' and contract.FRAME.size == 424,
            'Current read contract differs')
    return sources, libraries


def derive(path, body_sha256, plan_sha256):
    path = Path(path).absolute()
    require('..' not in path.parts and path.is_relative_to(ROOT / 'output'), 'Workspace pending receipt required')
    raw = read_regular(path)
    spec = contract.derive_target_spec(raw, body_sha256=body_sha256, plan_sha256=plan_sha256)
    return raw, spec


def header(nonce, spec):
    def array(name, values):
        return 'static const ' + ('volatile ' if name == 'target_spec_sha256' else '') + 'unsigned char ' + name + '[]={' + ','.join(map(str, values)) + '};\n'
    lines = [f'#define JOB_DIR "/tmp_wbshd/m4ipr_{nonce.hex()}"', '#define FIELD_COUNT 44']
    lines += [f'#define F_{name} {i}' for i, name in enumerate(contract.FIELDS)]
    for name, prefix in (('lib', 'LIB'), ('app', 'APP')):
        item = spec['targets'][name]
        lines += [f'#define {prefix}_PID {item["pid"]}', f'#define {prefix}_BASE {item["base_addr"]}L',
                  f'#define {prefix}_ADDR {item["target_addr"]}L']
    text = '\n'.join(lines) + '\n'
    text += array('job_nonce', nonce)
    text += array('patch_nonce', bytes.fromhex(spec['original_patch_nonce']))
    text += array('target_spec_sha256', bytes.fromhex(contract.spec_sha256(spec)))
    text += array('anchor', bytes.fromhex(MODULES['libupdaterufp.so']['anchor_hex']))
    text += array('app_anchor', bytes.fromhex(MODULES['appFw.so']['anchor_hex']))
    return text.encode('ascii')
