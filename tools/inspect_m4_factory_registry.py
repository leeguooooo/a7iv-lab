"""Inspect original M4 controller factory records; never alter firmware or register a menu."""
import argparse
from dataclasses import dataclass
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import struct

from elftools.elf.elffile import ELFFile

AP_IDENTITIES = {
    '1e1b9202eaa69198f20df03dbfdab2f103b206cc4ebcd2e7bd817e6a710018a2': 'stock_6_02',
    'd17e61fb4ba193d8e7d802196edff5f578d5691b3fcc4abcd1cbbb6e58bdd8ff': 'FL23_offline_candidate',
}
AP_BYTES = 98212632
TABLE = 0x5118520
TABLE_POINTER = 0x59e0668
RECORD_BYTES = 96
MAX_NATIVE_MODE = 0x4ce
MODE_SENTINEL = 0x4cf
MENU_MODE = 0x354
MENU_VPTR = 0x599e090
MENU_GOT = 0x5a300a0
MENU_FACTORY = 0x1dc769c
CONSUMER_SPANS = {
    'presenter_dispatch': (0x1ed6a58, 0x78, 'ff1d0c127c1822c55640c4c695e91e52c106d83774dd5d59e76041f2a1982513'),
    'controller_dispatch': (0x1ed6af4, 0x40, 'b64e7d92cbeaa0582f02d924a580cdb9d4d7cfad5854f86cd75f7a0ea7c7bb6b'),
    'sentinel_return': (0x1ed6a1c, 0x10, '681bdac76d6fb6fbdb96ce01073b240a0d40bdb317f02aea6734fe31feda2370'),
    'signed_upper_bound': (0x1ed6e30, 0x24, '5436d5bc0cc98d9485ce28de0189e90e45d4fcc906a3837911ea528c135561b4'),
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


@dataclass(frozen=True)
class FactoryRecord:
    presenter_factory: int
    controller_factory: int
    metadata_16: int
    metadata_20: int
    opaque_tail: bytes

    def __post_init__(self):
        require(type(self.opaque_tail) is bytes and len(self.opaque_tail) == 72,
                'Factory record requires seventy-two opaque tail bytes')
        require(all(type(pointer) is int and 0 <= pointer < 1 << 64
                    for pointer in (self.presenter_factory, self.controller_factory)),
                'Factory pointers must be uint64 values')
        require(all(type(value) is int and 0 <= value < 1 << 32
                    for value in (self.metadata_16, self.metadata_20)), 'Raw metadata must be uint32 values')

    @classmethod
    def decode(cls, raw):
        require(type(raw) is bytes and len(raw) == RECORD_BYTES, 'Exactly 96 record bytes required')
        return cls(*struct.unpack_from('<QQII', raw), raw[24:])

    def encode(self):
        return struct.pack('<QQII', self.presenter_factory, self.controller_factory,
                           self.metadata_16, self.metadata_20) + self.opaque_tail


class ElfView:
    def __init__(self, raw):
        self.raw = raw
        self.elf = ELFFile(io.BytesIO(raw))
        require(self.elf['e_machine'] == 'EM_AARCH64' and self.elf['e_type'] == 'ET_DYN'
                and self.elf.little_endian, 'Little-endian AArch64 ET_DYN required')
        self.loads = [s for s in self.elf.iter_segments() if s['p_type'] == 'PT_LOAD']

    def offset(self, address, size):
        require(type(address) is int and type(size) is int and address >= 0 and size > 0,
                'Positive bounded virtual range required')
        matches = [s for s in self.loads if s['p_vaddr'] <= address
                   and address + size <= s['p_vaddr'] + s['p_filesz']]
        require(len(matches) == 1, 'Unique file-backed PT_LOAD range required')
        result = address - matches[0]['p_vaddr'] + matches[0]['p_offset']
        require(0 <= result and result + size <= len(self.raw), 'ELF range exceeds file')
        return result

    def read(self, address, size):
        start = self.offset(address, size)
        return self.raw[start:start + size]

    def qword(self, address):
        return struct.unpack('<Q', self.read(address, 8))[0]

    def executable(self, address):
        return address != 0 and any(s['p_flags'] & 1 and s['p_vaddr'] <= address < s['p_vaddr'] + s['p_filesz']
                   for s in self.loads)


def _read_ap(path):
    descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_size == AP_BYTES, 'Exact-sized regular AP file required')
        raw = stream.read(AP_BYTES + 1)
        after = os.fstat(stream.fileno())
    identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
    require(len(raw) == AP_BYTES and identity(before) == identity(after), 'AP changed while read')
    return raw


def inspect(path, modes=(MENU_MODE,)):
    modes = tuple(modes)
    require(bool(modes) and len(modes) == len(set(modes)) and all(type(i) is int
            and 0 <= i <= MAX_NATIVE_MODE for i in modes), 'Unique nonnegative modes in range 0..0x4ce required')
    raw = _read_ap(path)
    digest = hashlib.sha256(raw).hexdigest()
    require(digest in AP_IDENTITIES, 'Unsupported AP identity; no hash override exists')
    view = ElfView(raw)
    consumer_proof = {}
    for name, (address, size, expected) in CONSUMER_SPANS.items():
        require(hashlib.sha256(view.read(address, size)).hexdigest() == expected,
                'Original registry consumer differs: ' + name)
        consumer_proof[name] = dict(address=hex(address), bytes=size, sha256=expected)
    require(view.qword(TABLE_POINTER) == TABLE, 'Factory table pointer differs')
    require(view.qword(MENU_GOT) + 16 == MENU_VPTR, 'Menu vtable GOT differs')
    typeinfo = view.qword(MENU_VPTR - 8)
    name_address = view.qword(typeinfo + 8)
    expected_name = b'19rep_menu_controller\0'
    require(view.read(name_address, len(expected_name)) == expected_name, 'Menu RTTI differs')
    require(view.qword(TABLE + MENU_MODE * RECORD_BYTES + 8) == MENU_FACTORY,
            'Menu factory differs')
    require(view.read(0x1dc7518, 4) == bytes.fromhex('816a8052'), 'Menu constructor mode instruction differs')
    require(view.executable(MENU_FACTORY), 'Menu factory is not file-backed executable code')
    records = []
    for mode in sorted(modes):
        address = TABLE + mode * RECORD_BYTES
        encoded = view.read(address, RECORD_BYTES)
        record = FactoryRecord.decode(encoded)
        require(record.encode() == encoded, 'Factory record round trip changed bytes')
        records.append(dict(mode=mode, address=hex(address), file_offset=view.offset(address, RECORD_BYTES),
            presenter_factory=hex(record.presenter_factory), controller_factory=hex(record.controller_factory),
            raw_metadata_16=record.metadata_16, raw_metadata_20=record.metadata_20, raw_hex=encoded.hex(),
            raw_sha256=hashlib.sha256(encoded).hexdigest(), round_trip_equal=True,
            factory_points_into_executable_segment=view.executable(record.controller_factory),
            opaque_bytes=72, metadata_semantics_proven=False))
    selected_modes = set(modes)
    referenced = {TABLE_POINTER, MENU_GOT, MENU_VPTR - 8, typeinfo + 8}
    relocations = []
    for section in view.elf.iter_sections():
        if section['sh_type'] != 'SHT_RELA':
            continue
        for item in section.iter_relocations():
            address = item['r_offset']
            in_selected_record = (TABLE <= address < TABLE + (MAX_NATIVE_MODE + 1) * RECORD_BYTES
                                  and (address - TABLE) // RECORD_BYTES in selected_modes)
            if address in referenced or in_selected_record:
                relocations.append(dict(address=hex(address), type=item['r_info_type'],
                    symbol_index=item['r_info_sym'], addend=hex(item['r_addend'])))
    return dict(schema='camera-m4-controller-registry-inspection/1',
        input=dict(path=str(Path(path).absolute()), bytes=len(raw), sha256=digest, kind=AP_IDENTITIES[digest]),
        table=dict(address=hex(TABLE), pointer_address=hex(TABLE_POINTER), stride=RECORD_BYTES,
                   native_signed_upper_bound=MAX_NATIVE_MODE, native_upper_bound_proven=True,
                   sentinel=MODE_SENTINEL, native_lower_bound_proven=False, nonnegative_inspector_policy=True),
        menu_anchor=dict(mode=MENU_MODE, vptr=hex(MENU_VPTR), factory=hex(MENU_FACTORY),
                         rtti_name='19rep_menu_controller'), records=records, relocations=relocations,
        consumer_proof=consumer_proof, factory_record_encoding_verified=True, menu_node_encoding_proven=False,
        original_instructions_executed=False, firmware_modified=False,
        custom_menu_registered=False, hardware_operations=0, installation_authorized=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ap', type=Path, required=True)
    parser.add_argument('--mode', type=lambda value: int(value, 0), action='append')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = inspect(args.ap, args.mode if args.mode is not None else (MENU_MODE,))
    with args.output.open('x') as stream:
        os.fchmod(stream.fileno(), 0o600)
        json.dump(result, stream, indent=2)
        stream.write('\n')
    print(json.dumps(dict(records=len(result['records']), round_trip_equal=True,
                          firmware_modified=False, hardware_operations=0)))


if __name__ == '__main__':
    main()
