"""Offline source and stock-ELF evidence for the one-shot volatile patch."""
import hashlib
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from menu_window_profile import (ROOT, APP, COMPILER, COMPILER_SHA, MODULES,
    OBSERVATION_OFFSETS, OBSERVATION_SIZES, FIELDS, BASE_FIELDS, APP_FIELDS, STATUS_FIELDS,
    DEFS as MENU_DEFS, input_evidence as menu_input_evidence, read_regular, require, sha, mapped)

MAGIC = 'M4IVP001'
VERSION = 2
START_MAGIC = 'M4ISTART'
START_VERSION = 2
SCHEMA = 'camera-install-volatile-offline/1'
PROFILE = 'install_volatile_stock_6.02'
DEFS = {key: value for key, value in MENU_DEFS.items() if key != 'HOLD_SECONDS'}
SOURCE_PATHS = ('native/install_volatile_patch.c', 'tools/install_volatile_profile.py',
    'tools/build_install_volatile_offline.py', 'tools/verify_install_volatile_offline.py',
    'tools/menu_window_profile.py', 'tools/verify_menu_window_offline.py',
    'camera_install_volatile.py')


def input_evidence():
    sources, libraries = menu_input_evidence()
    for relative in SOURCE_PATHS:
        sources[relative] = hashlib.sha256(read_regular(ROOT / relative)).hexdigest()
    import sys
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    import camera_install_volatile as contract
    require(contract.MAGIC == MAGIC.encode() and contract.VERSION == VERSION
            and contract.START_MAGIC == START_MAGIC.encode() and tuple(contract.FIELDS) == FIELDS
            and contract.FRAME.format == '<8s16s51q' and contract.FRAME.size == 432,
            'Install volatile decoder/profile contract differs')
    return sources, libraries
