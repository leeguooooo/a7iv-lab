"""Fixed offline stock M4 menu profile; no SDK or device imports."""
import hashlib
import io
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from elftools.elf.elffile import ELFFile

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / 'ref/sony-a7m4-custom-firmware/no-fastboot-install/software/app'
COMPILER = ROOT / 'local/zig-aarch64-macos-0.15.2/zig'
COMPILER_SHA = 'c65cd34917923f575448cc0603dd7c2326da0af0e5c323043d090662dcdf351c'
PINS = {
    'menu_stock/dual_worker.c': '4a0b88e53b752503f71c10d1dd333298d27fbecb334cd7d85faba48e518662d3',
    'menu_stock/layout.json': '4eb33ab9d5204da8e77aba5d83ee98fe1d200dbca8e3da00e283f025f5a96070',
    'menu_stock/dual_job.py': 'c09049843c3c038f077b31dbd9fb21c219b2882c4f85e509090d872680d9ca84',
    'native/bootstrap.c': '4e4dcb37eceab654a25b4a7f0d16626d1764f2a9708a48b3275da10c173b19a1',
    'native/linux_a64.h': '827bfa50c9d5e2a1ee8eacc032303844cd3c0a8a9b4f5ea1bfa640a987eedd88',
    'workflow/version_labels.h': '132f0a58f33df174ebf095bb5ede704dde43a0c0b7321cb101731b2445a15b1f',
}
MODULES = {
    'libupdaterufp.so': {
        'path': 'local/firmware/a7m4-6.02/nor-research/libs/libupdaterufp.so',
        'bytes': 22768,
        'sha256': 'f2e7d27602e3f7b236fc41dd93fccf53ba24f0793fd454e7fec171ae378beca7',
        'anchor_offset': 8004, 'anchor_hex': 'a0000090012044792001009000c844793f00006b',
        'patch_offset': 8016, 'original_hex': '00c84479', 'patch_hex': '00c08052',
        'global_version_offset': 152164, 'version_bytes': 2,
        'original_instruction': ['ldrh', 'w0, [x0, #0x264]'],
        'patched_instruction': ['mov', 'w0, #0x600'],
    },
    'appFw.so': {
        'path': 'local/firmware/a7m4-6.02/stock/appFw.so',
        'bytes': 98212632,
        'sha256': '1e1b9202eaa69198f20df03dbfdab2f103b206cc4ebcd2e7bd817e6a710018a2',
        'anchor_offset': 40219316,
        'anchor_hex': '010040b9a05f40b9e80313aa3f00006ba03740f9e30500544a6ffc9740008052',
        'patch_offset': 40219336, 'original_hex': 'e3050054', 'patch_hex': '2f000014',
        'global_version_offset': 134261208, 'version_bytes': 4,
        'original_instruction': ['b.lo', '#0x265b384'],
        'patched_instruction': ['b', '#0x265b384'],
    },
}
OBSERVATIONS = ('usb_stream', 'network_stream', 'slot1_mount', 'media_error',
                'target_version', 'query_error', 'inhibited', 'debug_exclusion')
OBSERVATION_OFFSETS = (134605304, 134152080, 134223368, 134063528,
                       134633200, 134633360, 139210037, 134109776)
OBSERVATION_SIZES = (4, 4, 4, 4, 4, 4, 1, 1)
BASE_FIELDS = ('version', 'phase', 'error', 'euid', 'pid', 'ppid', 'loader_pid', 'cleanup',
               'maps_bytes', 'polls', 'target_addr', 'base_addr', 'machine_version',
               'patched', 'restored', 'hold_seconds', 'flags', 'mem_status', 'restore_status')
APP_FIELDS = ('app_pid', 'app_target_addr', 'app_base_addr', 'app_machine_version',
              'app_patched', 'app_restored', 'app_mem_status', 'app_restore_status', 'app_write_attempted')
STATUS_FIELDS = ('app_maps_bytes', 'proc_candidates', 'identity_checks', 'lib_identity_status',
                 'app_identity_status', 'snapshot_before_status', 'snapshot_end_status')
FIELDS = BASE_FIELDS + APP_FIELDS + STATUS_FIELDS + tuple(
    f'{phase}_{name}' for phase in ('before', 'end') for name in OBSERVATIONS)
DEFS = {'START_TIMEOUT': 120, 'MAPS_WAIT_SECONDS': 300, 'HOLD_SECONDS': 600,
        'PATCH_OFFSET': 8016, 'ANCHOR_OFFSET': 8004, 'GLOBAL_OFFSET': 152164,
        'APP_PATCH_OFFSET': 40219336, 'APP_ANCHOR_OFFSET': 40219316,
        'APP_GLOBAL_OFFSET': 134261208}


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def read_regular(path):
    path = Path(path).absolute()
    require(not any(p.is_symlink() for p in (path, *path.parents)), 'Symlink input forbidden')
    require(path.is_file(), 'Regular input file required: ' + str(path))
    return path.read_bytes()


def mapped(elf, address, count, *, file_backed=True, executable=False):
    hits = [s for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD'
            and s['p_vaddr'] <= address and address + count <= s['p_vaddr'] +
            (s['p_filesz'] if file_backed else s['p_memsz'])]
    require(len(hits) == 1, 'Ambiguous/unmapped ELF address ' + hex(address))
    s = hits[0]
    require(not executable or s['p_flags'] & 1, 'Instruction outside executable segment')
    return address - s['p_vaddr'] + s['p_offset']


def input_evidence():
    sources = {}
    for relative, expected in PINS.items():
        path = APP / relative
        raw = read_regular(path)
        require(hashlib.sha256(raw).hexdigest() == expected, 'Reference source changed: ' + relative)
        sources[str(path.relative_to(ROOT))] = expected
    require(sha(COMPILER) == COMPILER_SHA, 'Pinned Mac Zig changed')
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    result = {}
    for name, profile in MODULES.items():
        raw = read_regular(ROOT / profile['path'])
        require(len(raw) == profile['bytes'] and hashlib.sha256(raw).hexdigest() == profile['sha256'],
                'Complete saved stock ELF differs: ' + name)
        elf = ELFFile(io.BytesIO(raw))
        require(elf.elfclass == 64 and elf.little_endian and elf['e_machine'] == 'EM_AARCH64'
                and elf['e_type'] == 'ET_DYN', 'Wrong saved ELF architecture')
        va, anchor = profile['patch_offset'], bytes.fromhex(profile['anchor_hex'])
        off = mapped(elf, va, 4, executable=True)
        ao = mapped(elf, profile['anchor_offset'], len(anchor), executable=True)
        require(raw[ao:ao + len(anchor)] == anchor and raw[off:off + 4].hex() == profile['original_hex'],
                'Anchor/preimage differs: ' + name)
        original = list(md.disasm(raw[off:off + 4], va))
        patch = list(md.disasm(bytes.fromhex(profile['patch_hex']), va))
        require(len(original) == len(patch) == 1 and
                [original[0].mnemonic, original[0].op_str] == profile['original_instruction'] and
                [patch[0].mnemonic, patch[0].op_str] == profile['patched_instruction'],
                'Patch instruction semantic mismatch')
        mapped(elf, profile['global_version_offset'], profile['version_bytes'], file_backed=False)
        if name == 'appFw.so':
            for address, count in zip(OBSERVATION_OFFSETS, OBSERVATION_SIZES):
                mapped(elf, address, count, file_backed=False)
        result[name] = dict(profile, file_offset=off, anchor_file_offset=ao,
                            observed_original_instruction=[original[0].mnemonic, original[0].op_str],
                            observed_patch_instruction=[patch[0].mnemonic, patch[0].op_str])
    return sources, result
