"""Loader-visible contracts on synthetic ELF fixtures, no firmware/devices."""
from io import BytesIO
import struct
import unittest

from elftools.elf.elffile import ELFFile
from camera_elf_extension import extend_ap_elf, digest


EH = struct.Struct("<16sHHIQQQIHHHHHH")
PH = struct.Struct("<IIQQQQQQ")
SH = struct.Struct("<IIQQQQIIQQ")
R = struct.Struct("<QQq")
IDENT = b"\x7fELF\x02\x01\x01" + bytes(9)
CODE, DATA = 0x30000, 0x50000


def original_fixture():
    data = bytearray(b"\xa5" * 0x2400)
    names = b"\0.shstrtab\0.rela.dyn\0.dynamic\0"
    data[0x1c00:0x1c00 + len(names)] = names
    headers = [
        (1, 5, 0, 0, 0, 0x1000, 0x1000, 0x1000),
        (1, 6, 0x1000, 0x10000, 0x10000, 0x800, 0x1000, 0x1000),
        (2, 6, 0x1100, 0x10100, 0x10100, 128, 128, 8),
        (0x6474e551, 6, 0, 0, 0, 0, 0, 16),
        (0x6474e552, 4, 0x1000, 0x10000, 0x10000, 0x80, 0x80, 1),
        (0x6474e550, 4, 0x700, 0x700, 0x700, 16, 16, 4),
    ]
    for i, p in enumerate(headers):
        PH.pack_into(data, 64 + i * PH.size, *p)
    rela = R.pack(0x10200, 1027, 0x400) + R.pack(0x10240, 1027, 0x500)
    data[0x300:0x300 + len(rela)] = rela
    for i, pair in enumerate([(7, 0x300), (8, len(rela)), (9, 24), (0x6ffffff9, 2),
                              (12, 0x400), (25, 0x10240), (27, 8), (0, 0)]):
        struct.pack_into("<QQ", data, 0x1100 + i * 16, *pair)
    sections = [bytes(64),
        SH.pack(names.index(b".shstrtab"), 3, 0, 0, 0x1c00, len(names), 0, 0, 1, 0),
        SH.pack(names.index(b".rela.dyn"), 4, 2, 0x300, 0x300, len(rela), 0, 0, 8, 24),
        SH.pack(names.index(b".dynamic"), 6, 3, 0x10100, 0x1100, 128, 1, 0, 8, 16)]
    for i, sh in enumerate(sections):
        data[0x2000 + i * 64:0x2000 + (i + 1) * 64] = sh
    EH.pack_into(data, 0, IDENT, 3, 183, 1, 0, 64, 0x2000, 0, 64, 56, 6, 64, 4, 1)
    return bytes(data)


def module_fixture(*, narrow=False, readonly_pointer=False, same_page=False, bad_pointer=False,
                   unsupported_instruction=False, zero_got=False):
    data = bytearray(0x1800)
    names_list = ["", ".text", ".rodata", ".got", ".data", ".bss", ".symtab", ".strtab",
                  ".rela.data", ".debug_info", ".rela.debug_info", ".shstrtab"]
    names = bytearray()
    offsets = []
    for name in names_list:
        offsets.append(len(names)); names.extend(name.encode() + b"\0")
    data[0x1000:0x1000 + len(names)] = names
    text = bytes.fromhex("c0035fd6") * 8
    data[0x200:0x220] = text
    data[0x240:0x250] = b"owned constants\0"
    got_va = CODE+0x80 if same_page else DATA
    struct.pack_into("<Q", data, 0x300, 0 if zero_got else DATA+16)
    struct.pack_into("<Q", data, 0x308, 0x12345678 if bad_pointer else CODE)
    strings = b"\0entry\0"
    data[0x600:0x600 + len(strings)] = strings
    data[0x500:0x530] = bytes(24) + struct.pack("<IBBHQQ", 1, 0x12, 0, 1, CODE, 4)
    target, site = (2, CODE+32) if readonly_pointer else (4, DATA+8)
    if readonly_pointer:
        struct.pack_into("<Q", data, 0x240, CODE)
    if unsupported_instruction:target,site=1,CODE
    kind=263 if unsupported_instruction else (258 if narrow else 257)
    data[0x700:0x718] = R.pack(site, (1 << 32) | kind, 0)
    data[0x800:0x818] = R.pack(0xdeadbeef, (1 << 32) | 257, 0)
    specs = [None,
        (1, 6, CODE, 0x200, 32, 0, 0, 16, 0),
        (1, 2, CODE+32, 0x240, 16, 0, 0, 16, 0),
        (1, 3, got_va, 0x300, 8, 0, 0, 8, 0),
        (1, 3, DATA+8, 0x308, 8, 0, 0, 8, 0),
        (8, 3, DATA+16, 0x310, 16, 0, 0, 8, 0),
        (2, 0, 0, 0x500, 48, 7, 1, 8, 24),
        (3, 0, 0, 0x600, len(strings), 0, 0, 1, 0),
        (4, 0, 0, 0x700, 24, 6, target, 8, 24),
        (1, 0, 0, 0x900, 8, 0, 0, 1, 0),
        (4, 0, 0, 0x800, 24, 6, 9, 8, 24),
        (3, 0, 0, 0x1000, len(names), 0, 0, 1, 0)]
    for i, spec in enumerate(specs):
        sh = bytes(64) if spec is None else SH.pack(offsets[i], *spec)
        data[0x1200 + i * 64:0x1200 + (i + 1) * 64] = sh
    EH.pack_into(data, 0, IDENT, 2, 183, 1, CODE, 64, 0x1200, 0, 64, 56, 0, 64, len(specs), 11)
    return bytes(data)


def dynamic(elf):
    return {t.entry.d_tag: t.entry.d_val for s in elf.iter_segments() if s["p_type"] == "PT_DYNAMIC"
            for t in s.iter_tags()}


class ExtensionTests(unittest.TestCase):
    def extend(self, original=None, module=None):
        original = original_fixture() if original is None else original
        module = module_fixture() if module is None else module
        return extend_ap_elf(original, module, original_sha256=digest(original), module_sha256=digest(module))

    def test_preserves_original_headers_and_relocates_program_table(self):
        old = original_fixture(); new, report = self.extend(old)
        left, right = ELFFile(BytesIO(old)), ELFFile(BytesIO(new))
        self.assertEqual([dict(s.header) for s in left.iter_segments()],
                         [dict(s.header) for s in right.iter_segments()][:6])
        self.assertGreaterEqual(right["e_phoff"], len(old))
        self.assertEqual(old[0x190:0x1c8], new[0x190:0x1c8])
        self.assertEqual([s["p_flags"] for s in list(right.iter_segments())[-3:]], [5, 6, 4])
        for tag in ("DT_INIT", "DT_INIT_ARRAY", "DT_INIT_ARRAYSZ", "DT_RELACOUNT"):
            self.assertEqual(dynamic(left)[tag], dynamic(right)[tag])
        self.assertFalse(report["module_activation"])
        self.assertFalse(report["installable"])
        loads=[s for s in right.iter_segments() if s['p_type']=='PT_LOAD']
        kernel_delta=loads[0]['p_vaddr']-loads[0]['p_offset']
        containing=next(s for s in loads if s['p_offset']<=right['e_phoff']<s['p_offset']+s['p_filesz'])
        mapped=containing['p_vaddr']+right['e_phoff']-containing['p_offset']
        self.assertEqual(kernel_delta+right['e_phoff'],mapped)

    def test_runtime_pointer_relocations_exclude_debug_records(self):
        old = original_fixture(); new, report = self.extend(old)
        e = ELFFile(BytesIO(new)); d = dynamic(e)
        s = e.get_section_by_name(".rela.dyn")
        table = s.data()
        self.assertEqual(table[:48], old[0x300:0x330])
        self.assertEqual(d["DT_RELA"], s["sh_addr"])
        self.assertEqual(d["DT_RELASZ"], len(table))
        self.assertEqual(set(R.iter_unpack(table[48:])),
                         {(DATA, 1027, DATA+16), (DATA+8, 1027, CODE)})
        self.assertEqual(report["additional_relative_relocations"], 2)
        self.assertEqual(report["ignored_debug_abs64"], 1)

    def test_loader_memory_and_pointers_at_two_nonzero_biases(self):
        new, report = self.extend(); e = ELFFile(BytesIO(new))
        for bias in (0x100000000, 0x510000000):
            memory = [(bias+s["p_vaddr"], bytearray(s.data())+bytearray(s["p_memsz"]-s["p_filesz"]))
                      for s in e.iter_segments() if s["p_type"] == "PT_LOAD"]
            def access(address, value=None):
                for base, blob in memory:
                    if base <= address and address+8 <= base+len(blob):
                        offset = address-base
                        if value is not None: struct.pack_into("<Q", blob, offset, value)
                        return struct.unpack_from("<Q", blob, offset)[0]
                self.fail(hex(address))
            for offset, info, addend in R.iter_unpack(e.get_section_by_name(".rela.dyn").data()):
                self.assertEqual(info, 1027); access(bias+offset, bias+addend)
            self.assertEqual(access(bias+0x10200), bias+0x400)
            self.assertEqual(access(bias+DATA), bias+DATA+16)
            self.assertEqual(access(bias+DATA+8), bias+CODE)
            self.assertEqual(access(bias+DATA+16), 0)
            self.assertEqual(report["BSS_zero_fill_bytes"], 16)

    def test_digest_mismatch_rejects_before_build(self):
        with self.assertRaisesRegex(ValueError, "digest"):
            extend_ap_elf(original_fixture(), module_fixture(), original_sha256="0"*64,
                          module_sha256=digest(module_fixture()))

    def test_narrow_runtime_pointer_rejected(self):
        with self.assertRaisesRegex(ValueError, "Narrow"):
            self.extend(module=module_fixture(narrow=True))

    def test_readonly_absolute_pointer_rejected(self):
        with self.assertRaisesRegex(ValueError, "writable"):
            self.extend(module=module_fixture(readonly_pointer=True))

    def test_shared_code_storage_page_rejected(self):
        with self.assertRaisesRegex(ValueError, "boundaries"):
            self.extend(module=module_fixture(same_page=True))

    def test_unclassified_pointer_rejected(self):
        with self.assertRaisesRegex(ValueError, "Unclassified"):
            self.extend(module=module_fixture(bad_pointer=True))

    def test_absolute_instruction_relocation_rejected(self):
        with self.assertRaisesRegex(ValueError, "Unsupported runtime relocation"):
            self.extend(module=module_fixture(unsupported_instruction=True))

    def test_zero_GOT_entry_not_guessed_as_image_base(self):
        with self.assertRaisesRegex(ValueError, "Zero GOT"):
            self.extend(module=module_fixture(zero_got=True))

    def test_incomplete_dynamic_contract_rejected(self):
        old = bytearray(original_fixture());struct.pack_into("<Q", old, 0x1120, 0)
        with self.assertRaisesRegex(ValueError, "RELA"):
            self.extend(original=bytes(old))


if __name__ == "__main__":
    unittest.main()
