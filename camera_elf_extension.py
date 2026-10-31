"""Offline ELF64/AArch64 extension, preserving the original loader contracts.

This creates an unactivated research image. It performs no device operation.
The caller owns compatibility, activation and whole-firmware admission.
"""
from io import BytesIO
import hashlib
import struct

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection


EH = struct.Struct("<16sHHIQQQIHHHHHH")
PH = struct.Struct("<IIQQQQQQ")
SH = struct.Struct("<IIQQQQIIQQ")
RELA = struct.Struct("<QQq")
PAGE = 65536
RELATIVE = 1027
ABS64 = 257
# Linked instruction displacements used by the verified A64 component.
# These remain valid when instruction and target receive the same page bias.
BIAS_SAFE_LINKED = {275, 277, 278, 282, 283, 285, 286, 299, 311, 312}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def align(value, size=PAGE):
    return (value + size - 1) // size * size


def _elf(data, kind):
    if len(data) < EH.size:
        raise ValueError("Short ELF header")
    h = list(EH.unpack_from(data))
    if h[0][:7] != b"\x7fELF\x02\x01\x01" or h[1] != kind or h[2] != 183:
        raise ValueError("Expected little-endian ELF64/AArch64 image")
    if h[8] != EH.size or h[9] != PH.size or h[11] != SH.size:
        raise ValueError("Unsupported ELF record size")
    if not (0 < h[12] < 0xff00 and 0 <= h[13] < h[12]):
        raise ValueError("Ordinary section headers are required")
    if h[6] > len(data) or h[12] * SH.size > len(data) - h[6]:
        raise ValueError("Section table outside file")
    if h[5] > len(data) or h[10] * PH.size > len(data) - h[5]:
        raise ValueError("Program table outside file")
    return ELFFile(BytesIO(data)), h


def _span_in(address, length, ranges):
    return length >= 0 and any(lo <= address and address + length <= hi for lo, hi in ranges)


def extend_ap_elf(original, module, *, original_sha256, module_sha256):
    """Return (new bytes, provenance) after exact caller-selected digest checks.

    The module is a fully linked ET_EXEC with explicit .text/.rodata and
    .got/.data/.bss sections, with writable storage on different64KiB pages.
    Its static relocation records classify runtime pointer fixups; debug
    relocation records are never treated as runtime data.
    No constructor or event hook is added, and installable remains false.
    """
    if digest(original) != original_sha256 or digest(module) != module_sha256:
        raise ValueError("Input digest mismatch")
    source, eh = _elf(original, 3)  # ET_DYN
    added, mh = _elf(module, 2)     # ET_EXEC, already statically linked
    symbol_table = added.get_section_by_name(".symtab")
    if symbol_table is None or any(s.name and s["st_shndx"] == "SHN_UNDEF" for s in symbol_table.iter_symbols()):
        raise ValueError("Module must have a complete resolved symbol table")
    if eh[10] > 65531:
        raise ValueError("Too many program headers")
    headers = [list(PH.unpack_from(original, eh[5] + i * PH.size)) for i in range(eh[10])]
    if any(p[0] == 6 for p in headers):
        raise ValueError("An existing PT_PHDR needs a separate relocation contract")
    loads = [p for p in headers if p[0] == 1]
    if not loads:
        raise ValueError("No original load segments")
    if loads[0][2] != 0 or loads[0][3] % PAGE:
        raise ValueError("Original first load must map file offset0 on a64KiB boundary")
    for p in loads:
        if p[5] > p[6] or p[2] > len(original) or p[5] > len(original) - p[2]:
            raise ValueError("Invalid original load extent")
    old_ranges = [(p[3], p[3] + p[6]) for p in loads]
    old_end = max(hi for _, hi in old_ranges)

    expected_names = {".text", ".rodata", ".got", ".data", ".bss"}
    sections = [s for s in added.iter_sections() if s["sh_flags"] & 2 and s["sh_size"]]
    if {s.name for s in sections} != expected_names or len(sections) != 5:
        raise ValueError("Unexpected module allocated sections")
    if any(s["sh_type"] not in ("SHT_PROGBITS", "SHT_NOBITS") for s in sections):
        raise ValueError("Unsupported module section representation")
    code = [s for s in sections if not s["sh_flags"] & 1]
    writable = [s for s in sections if s["sh_flags"] & 1]
    if any(s["sh_flags"] & 4 for s in writable):
        raise ValueError("Writable executable module section")
    if {s.name for s in code} != {".text", ".rodata"}:
        raise ValueError("Code/constant section policy mismatch")
    code_start = min(s["sh_addr"] for s in code)
    code_end = max(s["sh_addr"] + s["sh_size"] for s in code)
    data_start = min(s["sh_addr"] for s in writable)
    data_end = max(s["sh_addr"] + s["sh_size"] for s in writable)
    file_data_end = max(s["sh_addr"] + s["sh_size"] for s in writable if s["sh_type"] != "SHT_NOBITS")
    if code_start % PAGE or data_start % PAGE or code_start < align(old_end):
        raise ValueError("Module base must follow original loads on64KiB boundaries")
    if align(code_end) > data_start or code_end <= code_start or data_end <= data_start:
        raise ValueError("Module code/storage overlap")
    ordered = sorted(sections, key=lambda s: s["sh_addr"])
    for left, right in zip(ordered, ordered[1:]):
        if left["sh_addr"] + left["sh_size"] > right["sh_addr"]:
            raise ValueError("Overlapping module sections")
    if code_end - code_start > 16 * 1024 * 1024 or data_end - data_start > 16 * 1024 * 1024:
        raise ValueError("Unexpected module extent")
    new_ranges = [(s["sh_addr"], s["sh_addr"] + s["sh_size"]) for s in sections]
    runtime_writable = [(s["sh_addr"], s["sh_addr"] + s["sh_size"]) for s in writable]

    dynamics = [p for p in headers if p[0] == 2]
    if len(dynamics) != 1 or dynamics[0][5] % 16:
        raise ValueError("Expected one complete PT_DYNAMIC")
    dp = dynamics[0]
    if dp[2] > len(original) or dp[5] > len(original) - dp[2]:
        raise ValueError("Dynamic table outside file")
    tags = {}
    terminated = False
    for at in range(dp[2], dp[2] + dp[5], 16):
        tag, value = struct.unpack_from("<QQ", original, at)
        if tag == 0:
            terminated = True
            break
        if tag in (7, 8, 9, 0x6ffffff9):
            if tag in tags:
                raise ValueError("Ambiguous relocation dynamic tag")
            tags[tag] = (at, value)
    if not terminated or not {7, 8, 9}.issubset(tags) or tags[9][1] != RELA.size:
        raise ValueError("Missing ordinary RELA contract")
    rela_va, rela_size = tags[7][1], tags[8][1]
    if rela_size % RELA.size:
        raise ValueError("Partial original RELA entry")
    matches = [p for p in loads if p[3] <= rela_va and rela_va + rela_size <= p[3] + p[5]]
    if len(matches) != 1:
        raise ValueError("Original RELA not uniquely file-backed")
    rela_off = matches[0][2] + rela_va - matches[0][3]
    original_rela = original[rela_off:rela_off + rela_size]
    count = tags.get(0x6ffffff9, (0, 0))[1]
    if count > rela_size // RELA.size:
        raise ValueError("Invalid original RELACOUNT")
    for _, info, _ in RELA.iter_unpack(original_rela[:count * RELA.size]):
        if info != RELATIVE:
            raise ValueError("Original RELACOUNT prefix is not symbol-free RELATIVE")

    pointers = {}
    ignored_debug_abs64 = 0
    for relocations in added.iter_sections():
        if not isinstance(relocations, RelocationSection):
            continue
        target = added.get_section(relocations["sh_info"])
        if not target["sh_flags"] & 2:
            ignored_debug_abs64 += sum(r["r_info_type"] == ABS64 for r in relocations.iter_relocations())
            continue
        if target.name not in expected_names:
            raise ValueError("Relocation targets unknown module allocation")
        for r in relocations.iter_relocations():
            kind, site = r["r_info_type"], r["r_offset"]
            if kind in (258, 259):
                raise ValueError("Narrow absolute runtime relocation is not load-bias safe")
            if kind != ABS64:
                if kind not in BIAS_SAFE_LINKED:
                    raise ValueError("Unsupported runtime relocation requires its own load-bias contract")
                continue
            if target["sh_type"] == "SHT_NOBITS" or not target["sh_flags"] & 1 or not _span_in(site, 8, runtime_writable):
                raise ValueError("Absolute pointer target must be writable during relocation")
            off = site - target["sh_addr"]
            if off < 0 or off + 8 > target["sh_size"]:
                raise ValueError("Absolute pointer outside target section")
            if site in pointers:
                raise ValueError("Duplicate absolute runtime relocation")
            pointers[site] = struct.unpack_from("<Q", target.data(), off)[0]
    got = added.get_section_by_name(".got")
    if got["sh_size"] % 8 or not got["sh_flags"] & 1:
        raise ValueError("Invalid module GOT")
    for offset in range(0, got["sh_size"], 8):
        site = got["sh_addr"] + offset
        value = struct.unpack_from("<Q", got.data(), offset)[0]
        if value == 0 and site not in pointers:
            raise ValueError("Zero GOT slot lacks explicit pointer relocation provenance")
        if site in pointers and pointers[site] != value:
            raise ValueError("GOT relocation disagreement")
        pointers[site] = value
    for site, value in pointers.items():
        if site % 8 or value >= 1 << 63 or not _span_in(value, 1, old_ranges + new_ranges):
            raise ValueError("Unclassified absolute pointer value")
    additional_rela = b"".join(RELA.pack(site, RELATIVE, value) for site, value in sorted(pointers.items()))
    relocated_table = original_rela + additional_rela

    code_blob = bytearray(code_end - code_start)
    data_blob = bytearray(file_data_end - data_start)
    for s in sections:
        if s["sh_type"] == "SHT_NOBITS":
            continue
        base, blob = (data_start, data_blob) if s["sh_flags"] & 1 else (code_start, code_blob)
        offset = s["sh_addr"] - base
        blob[offset:offset + s["sh_size"]] = s.data()
    code_off = align(len(original))
    data_off = align(code_off + len(code_blob))
    # Linux's older direct-exec AT_PHDR calculation uses the first load's
    # vaddr-offset delta, while ld.so can locate the table in any mapped load.
    # Preserve both contracts, rather than assuming this file is only dlopened.
    first_delta = loads[0][3] - loads[0][2]
    earliest_metadata_off = align(data_off + len(data_blob))
    metadata_off = align(max(earliest_metadata_off, data_end - first_delta))
    if metadata_off - earliest_metadata_off > 128 * 1024 * 1024:
        raise ValueError("Unexpected metadata padding exceeds this offline builder's128MiB limit")
    metadata_va = metadata_off + first_delta
    phnum = len(headers) + 3
    rela_delta = align(phnum * PH.size, 8)
    metadata = bytearray(rela_delta) + relocated_table
    load_code = [1, 5, code_off, code_start, code_start, len(code_blob), len(code_blob), PAGE]
    load_data = [1, 6, data_off, data_start, data_start, len(data_blob), data_end - data_start, PAGE]
    load_meta = [1, 4, metadata_off, metadata_va, metadata_va, len(metadata), len(metadata), PAGE]
    all_headers = headers + [load_code, load_data, load_meta]
    for index, ph in enumerate(all_headers):
        PH.pack_into(metadata, index * PH.size, *ph)

    # Keep original section indexes. Only the string table and relocated RELA
    # descriptor get new locations; the old header-table bytes remain untouched.
    section_headers = [list(SH.unpack_from(original, eh[6] + i * SH.size)) for i in range(eh[12])]
    shstr = section_headers[eh[13]]
    names = bytearray(original[shstr[4]:shstr[4] + shstr[5]])
    found_rela = 0
    for sh in section_headers:
        if sh[1] == 4 and sh[3] == rela_va and sh[5] == rela_size:
            sh[3], sh[4], sh[5] = metadata_va + rela_delta, metadata_off + rela_delta, len(relocated_table)
            found_rela += 1
    if found_rela != 1:
        raise ValueError("Original RELA section descriptor is ambiguous")
    placements = []
    for s in sections:
        label = ".camera" + s.name
        name_at = len(names)
        names.extend(label.encode() + b"\0")
        base, file_start = (data_start, data_off) if s["sh_flags"] & 1 else (code_start, code_off)
        section_headers.append([name_at, 8 if s["sh_type"] == "SHT_NOBITS" else 1,
            int(s["sh_flags"]), int(s["sh_addr"]), file_start + s["sh_addr"] - base,
            int(s["sh_size"]), 0, 0, int(s["sh_addralign"]), int(s["sh_entsize"])])
        placements.append(dict(section=s.name,virtual=int(s["sh_addr"]),bytes=int(s["sh_size"]),
                               file_offset=section_headers[-1][4]))
    label_at = len(names)
    names.extend(b".camera.phdr\0")
    section_headers.append([label_at, 1, 2, metadata_va, metadata_off, phnum * PH.size, 0, 0, 8, 0])
    if len(section_headers) >= 0xff00:
        raise ValueError("Extended section-index encoding is not supported")
    names_off = align(metadata_off + len(metadata), 8)
    shstr[4], shstr[5] = names_off, len(names)
    section_off = align(names_off + len(names), 8)
    result = bytearray(section_off + len(section_headers) * SH.size)
    result[:len(original)] = original
    result[code_off:code_off + len(code_blob)] = code_blob
    result[data_off:data_off + len(data_blob)] = data_blob
    result[metadata_off:metadata_off + len(metadata)] = metadata
    result[names_off:names_off + len(names)] = names
    for index, sh in enumerate(section_headers):
        SH.pack_into(result, section_off + index * SH.size, *sh)
    eh[5], eh[6], eh[10], eh[12] = metadata_off, section_off, phnum, len(section_headers)
    EH.pack_into(result, 0, *eh)
    struct.pack_into("<Q", result, tags[7][0] + 8, metadata_va + rela_delta)
    struct.pack_into("<Q", result, tags[8][0] + 8, len(relocated_table))

    # An independent prefix comparison constrains every original-file mutation.
    expected = bytearray(original)
    EH.pack_into(expected, 0, *eh)
    struct.pack_into("<Q", expected, tags[7][0] + 8, metadata_va + rela_delta)
    struct.pack_into("<Q", expected, tags[8][0] + 8, len(relocated_table))
    if result[:len(original)] != expected:
        raise AssertionError("Unexpected original-file modification")
    output = bytes(result)
    verified, _ = _elf(output, 3)
    if len(list(verified.iter_segments())) != phnum:
        raise AssertionError("Output program table mismatch")
    report = dict(schema="camera-AP-ELF-extension/1",original_sha256=original_sha256,
        module_sha256=module_sha256,output_sha256=digest(output),output_bytes=len(output),
        original_program_headers_preserved=True,new_program_headers=3,
        program_table_file_offset=metadata_off,program_table_virtual=metadata_va,
        first_load_vaddr_offset_delta=first_delta,
        kernel_AT_PHDR_layout_matches_mapped_table=True,
        metadata_file_padding_bytes=metadata_off-earliest_metadata_off,
        original_rela_sha256=digest(original_rela),original_rela_bytes=len(original_rela),
        additional_relative_relocations=len(pointers),ignored_debug_abs64=ignored_debug_abs64,
        original_relative_prefix_count=count,placements=placements,
        new_loads=all_headers[-3:],BSS_zero_fill_bytes=data_end-file_data_end,
        original_init_and_init_array_unchanged=True,module_activation=False,
        hardware_operations=0,installable=False)
    return output, report
