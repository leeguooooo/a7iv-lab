"""Host checks for the AP SHT2 byte boundary; no device or transport access."""

import ctypes as C
import hashlib
import importlib.util
import json
import inspect
import os
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHECKS = ROOT / "output/expanded-features-20261030/shutter-wire-checks"
CP = ROOT / "output/expanded-features-20261030/single-shutter-owner"
CP_SHA = "c7fef8e7197436ab8606cbf57c11f1007ff2f1b4928fd3800af3c04f6c25ece5"
CP_MODEL_SHA = "230a6728af3be4c2c5c7c9a506faf5bb2a8a4dd0c462361ef966bda4d0da8c06"
BASE_MODEL = ROOT / "output/expanded-features-20261030/cp-owner-fresh-build/instruction_model.py"
BASE_MODEL_SHA = "68a7318edfed936c41679a623e46c7a853da60018ac356bc697503ff7d03cc79"
OK, NULL, CAPACITY, LENGTH, HEADER, RESERVED, SESSION, CORRELATION, OPERATION, ARGUMENT, PAYLOAD, MISMATCH, PHASE, OVERLAP = range(14)
BIND, PREPARE, COMMIT, POLICY, QUERY, COPY = range(1, 7)


class Bind(C.Structure):
    _fields_ = [("handle", C.c_uint32 * 3)]


class Prepare(C.Structure):
    _fields_ = [("generation", C.c_uint32), ("revision", C.c_uint32)]


class Commit(C.Structure):
    _fields_ = [("generation", C.c_uint32), ("revision", C.c_uint32),
                ("encoded_length", C.c_uint32), ("crc32", C.c_uint32)]


class Policy(C.Structure):
    _fields_ = [("generation", C.c_uint32), ("revision", C.c_uint32), ("enable", C.c_uint32)]


class Query(C.Structure):
    _fields_ = [("mode", C.c_uint32)]


class Copy(C.Structure):
    _fields_ = [("generation", C.c_uint32), ("revision", C.c_uint32),
                ("offset", C.c_uint32), ("length", C.c_uint32)]


class Args(C.Union):
    _fields_ = [("bind", Bind), ("prepare", Prepare), ("commit", Commit),
                ("policy", Policy), ("query", Query), ("copy", Copy)]


class Request(C.Structure):
    _fields_ = [("operation", C.c_int), ("session", C.c_uint32),
                ("correlation", C.c_uint16), ("args", Args),
                ("payload", C.POINTER(C.c_uint8)), ("payload_length", C.c_size_t)]


class Expected(C.Structure):
    _fields_ = [("session", C.c_uint32), ("operation", C.c_int),
                ("correlation", C.c_uint16)]


class Reply(C.Structure):
    _fields_ = [("session", C.c_uint32), ("operation", C.c_int),
                ("correlation", C.c_uint16), ("phase", C.c_uint32),
                ("fields", C.c_uint32 * 5)]


def compile_codec(build_dir):
    CHECKS.mkdir(parents=True, exist_ok=True)
    library = build_dir / "libshutter_wire_host.dylib"
    cmd = ["/usr/bin/clang", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic",
           "-fPIC", "-shared", str(ROOT / "native/shutter_wire.c"), "-o", str(library)]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    (CHECKS / f"host-build-{os.getpid()}.log").write_text(
        "$ " + " ".join(cmd) + "\n" + result.stdout + result.stderr + f"exit={result.returncode}\n"
    )
    assert result.returncode == 0, result.stderr
    lib = C.CDLL(str(library))
    lib.shutter_wire_encode.argtypes = [C.POINTER(Request), C.POINTER(C.c_uint8), C.c_size_t,
                                        C.POINTER(C.c_size_t)]
    lib.shutter_wire_encode.restype = C.c_int
    lib.shutter_wire_decode_reply.argtypes = [C.POINTER(C.c_uint8), C.c_size_t,
                                              C.POINTER(Expected), C.POINTER(Reply)]
    lib.shutter_wire_decode_reply.restype = C.c_int
    return lib


def req(op=BIND, session=55, corr=7):
    r = Request()
    r.operation, r.session, r.correlation = op, session, corr
    if op == BIND:
        r.args.bind.handle[:] = (101, 102, 103)
    elif op == PREPARE:
        r.args.prepare.generation, r.args.prepare.revision = 1, 1
    elif op == COMMIT:
        r.args.commit.generation, r.args.commit.revision = 1, 1
        r.args.commit.encoded_length, r.args.commit.crc32 = 32, 0x11223344
    elif op == POLICY:
        r.args.policy.generation, r.args.policy.revision, r.args.policy.enable = 1, 1, 1
    elif op == QUERY:
        r.args.query.mode = 1
    elif op == COPY:
        r.args.copy.generation, r.args.copy.revision = 1, 1
        r.args.copy.offset, r.args.copy.length = 0, 4
    return r


def payload(r, data):
    backing = (C.c_uint8 * len(data)).from_buffer_copy(data)
    r.payload = C.cast(backing, C.POINTER(C.c_uint8))
    r.payload_length = len(data)
    return backing


def encode(codec, r, capacity=1000):
    out = (C.c_uint8 * capacity)(*([0xA5] * capacity))
    written = C.c_size_t(0xBEEF)
    code = codec.shutter_wire_encode(C.byref(r), out, capacity, C.byref(written))
    return code, bytes(out), written.value


def decode(codec, data, expected=None):
    expected = expected or Expected(55, BIND, 7)
    inp = (C.c_uint8 * len(data)).from_buffer_copy(data)
    out = Reply()
    C.memset(C.byref(out), 0xA5, C.sizeof(out))
    before = C.string_at(C.byref(out), C.sizeof(out))
    code = codec.shutter_wire_decode_reply(inp, len(data), C.byref(expected), C.byref(out))
    return code, out, before


def reply_bytes(op=BIND, session=55, corr=7, phase=0, fields=(1, 2, 3, 4, 5)):
    b = bytearray.fromhex("7e 80 00 00 18 00 00 00" + " 00" * 32)
    b[6:8] = corr.to_bytes(2, "little")
    for off, value in [(8, session), (12, op), (16, phase),
                       *[(20 + 4 * i, field) for i, field in enumerate(fields)]]:
        b[off:off + 4] = value.to_bytes(4, "little")
    return bytes(b)


def test_independent_bind_vector(codec):
    code, data, size = encode(codec, req())
    assert code == OK and size == 40
    assert data[:size] == bytes.fromhex(
        "7e 00 00 00 01 00 00 00 37 00 00 00 53 48 54 32 "
        "37 00 00 00 07 00 00 00 65 00 00 00 66 00 00 00 "
        "67 00 00 00 00 00 00 00")
    assert data[size:] == b"\xa5" * (len(data) - size)


def test_operation_words(codec, op, words):
    code, data, size = encode(codec, req(op))
    assert code == OK and size == 40
    assert tuple(int.from_bytes(data[i:i + 4], "little") for i in (24, 28, 32, 36)) == words


def test_encode_rejects_without_writes(codec, change, error):
    r = req()
    change(r)
    code, data, written = encode(codec, r)
    assert code == error and data == b"\xa5" * 1000 and written == 0xBEEF


def test_bad_operation_arguments(codec, op, change):
    r = req(op)
    change(r)
    code, data, written = encode(codec, r)
    assert code == ARGUMENT and data == b"\xa5" * 1000 and written == 0xBEEF


def test_copy_bounds_and_capacity(codec):
    r = req(COPY)
    r.args.copy.offset, r.args.copy.length = 123872 - 960, 960
    backing = payload(r, bytes(i % 256 for i in range(960)))
    code, data, written = encode(codec, r)
    assert code == OK and written == 1000 and data[40:] == bytes(backing)
    assert data[32:36] == (123872 - 960).to_bytes(4, "little")
    code, data, written = encode(codec, r, 999)
    assert code == CAPACITY and data == b"\xa5" * 999 and written == 0xBEEF
    r.args.copy.offset = 123872 - 959
    assert encode(codec, r)[0] == ARGUMENT
    r.args.copy.offset = 0xFFFFFFFE
    assert encode(codec, r)[0] == ARGUMENT
    r.args.copy.offset, r.args.copy.length = 0, 4
    assert encode(codec, r)[0] == PAYLOAD


def test_max_commit_and_correlation_boundary(codec):
    r = req(COMMIT, corr=65534)
    r.args.commit.encoded_length = 123872
    code, data, written = encode(codec, r)
    assert code == OK and written == 40
    assert data[20:22] == b"\xfe\xff"
    assert data[32:36] == (123872).to_bytes(4, "little")


def test_one_byte_copy_and_payload_length(codec):
    r = req(COPY)
    r.args.copy.offset, r.args.copy.length = 123871, 1
    backing = payload(r, b"Z")
    code, data, written = encode(codec, r)
    assert code == OK and written == 41 and data[40] == ord("Z")
    r.payload_length = 0
    assert encode(codec, r)[0] == PAYLOAD


def test_copy_overlap_and_null(codec):
    r = req(COPY)
    area = (C.c_uint8 * 64)(*([0xA5] * 64))
    r.payload = C.cast(C.byref(area, 36), C.POINTER(C.c_uint8))
    r.payload_length = 4
    written = C.c_size_t(0xBEEF)
    assert codec.shutter_wire_encode(C.byref(r), area, 64, C.byref(written)) == OVERLAP
    assert bytes(area) == b"\xa5" * 64 and written.value == 0xBEEF
    r.payload = C.POINTER(C.c_uint8)()
    assert codec.shutter_wire_encode(C.byref(r), area, 64, C.byref(written)) == NULL
    assert bytes(area) == b"\xa5" * 64


def test_request_and_written_overlap_rejected(codec):
    r = req()
    written = C.c_size_t(0xBEEF)
    original = C.string_at(C.byref(r), C.sizeof(r))
    assert codec.shutter_wire_encode(C.byref(r), C.cast(C.byref(r), C.POINTER(C.c_uint8)),
                                     C.sizeof(r), C.byref(written)) == OVERLAP
    assert C.string_at(C.byref(r), C.sizeof(r)) == original and written.value == 0xBEEF
    area = (C.c_uint8 * 40)(*([0xA5] * 40))
    written_inside = C.cast(area, C.POINTER(C.c_size_t))
    assert codec.shutter_wire_encode(C.byref(r), area, 40, written_inside) == OVERLAP
    assert bytes(area) == b"\xa5" * 40


def test_reply_vector_and_raw_fields(codec):
    data = bytes.fromhex(
        "7e 80 00 00 18 00 07 00 37 00 00 00 01 00 00 00 "
        "06 00 00 00 01 00 00 00 02 00 00 00 03 00 00 00 "
        "04 00 00 00 05 00 00 00")
    code, out, _ = decode(codec, data)
    assert code == OK
    assert (out.session, out.operation, out.correlation, out.phase) == (55, BIND, 7, 6)
    assert list(out.fields) == [1, 2, 3, 4, 5]


def test_reserved_reply_correlation_does_not_modify_output(codec):
    wire = bytearray(reply_bytes())
    wire[6:8] = b"\xff\xff"
    raw = (C.c_uint8 * 40).from_buffer_copy(wire)
    expected = Expected(55, BIND, 65535)
    result = Reply()
    C.memset(C.byref(result), 0xA5, C.sizeof(result))
    before = C.string_at(C.byref(result), C.sizeof(result))
    assert codec.shutter_wire_decode_reply(raw, 40, C.byref(expected), C.byref(result)) == CORRELATION
    assert C.string_at(C.byref(result), C.sizeof(result)) == before


def test_bad_reply_does_not_modify_output(codec, mutation, error):
    data = bytearray(reply_bytes())
    mutation(data)
    code, out, before = decode(codec, data)
    assert code == error and C.string_at(C.byref(out), C.sizeof(out)) == before


def test_exact_reply_length(codec, length):
    code, out, before = decode(codec, (reply_bytes() + b"\x00" * 960)[:length])
    assert code == LENGTH and C.string_at(C.byref(out), C.sizeof(out)) == before


def test_null_arguments(codec):
    out = (C.c_uint8 * 40)()
    written = C.c_size_t(123)
    assert codec.shutter_wire_encode(None, out, 40, C.byref(written)) == NULL
    assert written.value == 123
    assert codec.shutter_wire_decode_reply(None, 40, C.byref(Expected(55, BIND, 7)),
                                           C.byref(Reply())) == NULL


def test_actual_cp_arm_instruction_exchange(codec):
    """Real current CP ELF instructions with synthetic RAM and original-helper mocks."""
    elf = CP / "owner.MODEL_ONLY.elf"
    script = CP / "instruction_model.py"
    present = [p.exists() or p.is_symlink() for p in (elf, script)]
    if not any(present):
        raise unittest.SkipTest("current private CP peer unavailable")
    assert all(present) and all(p.is_file() and not p.is_symlink() for p in (elf, script)), "private CP peer incomplete or unsafe"
    assert hashlib.sha256(elf.read_bytes()).hexdigest() == CP_SHA, "current CP ELF SHA differs"
    assert hashlib.sha256(script.read_bytes()).hexdigest() == CP_MODEL_SHA, "current CP model SHA differs"
    assert BASE_MODEL.exists(), "current CP model depends on missing base model"
    assert hashlib.sha256(BASE_MODEL.read_bytes()).hexdigest() == BASE_MODEL_SHA, "base CP model SHA differs"
    try:
        from elftools.elf.elffile import ELFFile
        import unicorn  # noqa: F401
    except ImportError as exc:
        raise AssertionError("private CP materials exist but ARM model dependencies are missing") from exc
    spec = importlib.util.spec_from_file_location("current_shutter_cp_model", script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert Path(inspect.getfile(module.OldModel)).resolve() == BASE_MODEL.resolve(), "wrong base CP model loaded"
    with elf.open("rb") as f:
        parsed = ELFFile(f)
        sym = parsed.get_section_by_name(".symtab")
        names = ("csnd_cp_receive_capture", "csnd_cp_owner_reply",
                 "csnd_cp_lookup_original", "csnd_cp_exists_original",
                 "csnd_cp_start_original", "csnd_cp_validate_original")
        symbols = {name: {"va": sym.get_symbol_by_name(name)[0]["st_value"]} for name in names}
        loads = [(s["p_vaddr"], s.data(), s["p_memsz"])
                 for s in parsed.iter_segments() if s["p_type"] == "PT_LOAD"]
    model = module.Model(symbols, loads)
    observations = []

    def exchange(r, expect_phase):
        code, packet, length = encode(codec, r)
        assert code == OK
        model.uc.mem_write(module.REQUEST, packet[:length])
        model.call("csnd_cp_receive_capture", r.session, module.REQUEST, length)
        assert model.call("csnd_cp_owner_reply", module.REQUEST, module.OUTPUT) == 2
        wire = bytes(model.uc.mem_read(module.OUTPUT, 40))
        raw = (C.c_uint8 * 40).from_buffer_copy(wire)
        result = Reply()
        expected = Expected(r.session, r.operation, r.correlation)
        assert codec.shutter_wire_decode_reply(raw, 40, C.byref(expected), C.byref(result)) == OK
        assert result.phase == expect_phase
        observations.append({"operation": r.operation, "phase": result.phase,
                             "raw_fields": list(result.fields)})

    exchange(req(BIND, corr=65534), 0)
    exchange(req(PREPARE), 5)
    data = b"a" * 32
    r = req(COPY)
    r.args.copy.length = len(data)
    backing = payload(r, data)
    exchange(r, 0)
    r = req(COMMIT)
    r.args.commit.crc32 = zlib.crc32(data)
    exchange(r, 6)
    exchange(req(QUERY), 0)
    reserved = bytearray(encode(codec, req(BIND))[1][:40])
    reserved[20:22] = b"\xff\xff"
    before_reserved = bytes(model.uc.mem_read(module.OWNER, module.OWNER_SIZE))
    model.uc.mem_write(module.REQUEST, bytes(reserved))
    model.call("csnd_cp_receive_capture", 55, module.REQUEST, 40)
    model.call("csnd_cp_owner_reply", module.REQUEST, module.OUTPUT)
    assert bytes(model.uc.mem_read(module.OWNER, module.OWNER_SIZE)) == before_reserved
    assert int.from_bytes(model.uc.mem_read(module.OUTPUT + 16, 4), "little") == 2
    # Old magic must not enter the current private owner transaction path.
    old = bytearray(encode(codec, req(BIND))[1][:40])
    old[12:16] = b"CSSN"
    before = bytes(model.uc.mem_read(module.OWNER, module.OWNER_SIZE))
    model.uc.mem_write(module.REQUEST, bytes(old))
    model.call("csnd_cp_receive_capture", 55, module.REQUEST, 40)
    model.call("csnd_cp_owner_reply", module.REQUEST, module.OUTPUT)
    assert bytes(model.uc.mem_read(module.OWNER, module.OWNER_SIZE)) == before
    assert int.from_bytes(model.uc.mem_read(module.OUTPUT + 16, 4), "little") == 2
    (CHECKS / f"arm-exchange-{os.getpid()}.json").write_text(json.dumps({
        "scope": "current CP ELF instructions, synthetic RAM, named original helper mocks",
        "elf_sha256": CP_SHA, "model_sha256": CP_MODEL_SHA,
        "base_model_sha256": BASE_MODEL_SHA, "physical_camera_acceptance": False,
        "stock_native_abi_proven": False, "exchanges": observations,
        "old_magic_rejected": True,
        "reserved_correlation_rejected": True,
    }, indent=2) + "\n")


def test_optional_cp_peer_cannot_silently_skip_partial_materials(codec):
    case = unittest.TestCase()
    with tempfile.TemporaryDirectory() as folder, patch.dict(globals(), {"CP": Path(folder)}):
        elf, model = CP / "owner.MODEL_ONLY.elf", CP / "instruction_model.py"
        with case.assertRaises(unittest.SkipTest):
            test_actual_cp_arm_instruction_exchange(None)
        elf.write_bytes(b"partial peer")
        with case.assertRaisesRegex(AssertionError, "incomplete or unsafe"):
            test_actual_cp_arm_instruction_exchange(None)
        elf.unlink()
        model.write_text("partial peer")
        with case.assertRaisesRegex(AssertionError, "incomplete or unsafe"):
            test_actual_cp_arm_instruction_exchange(None)
        model.unlink()
        elf.symlink_to(CP / "missing")
        with case.assertRaisesRegex(AssertionError, "incomplete or unsafe"):
            test_actual_cp_arm_instruction_exchange(None)


class TestShutterWire(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        CHECKS.mkdir(parents=True, exist_ok=True)
        cls.build_dir = tempfile.TemporaryDirectory(prefix="host-", dir=CHECKS)
        try:
            cls.codec = compile_codec(Path(cls.build_dir.name))
        except BaseException:
            cls.build_dir.cleanup()
            raise

    @classmethod
    def tearDownClass(cls):
        cls.codec = None
        cls.build_dir.cleanup()


def register(name, function, *arguments):
    def run(self):
        function(self.codec, *arguments)
    setattr(TestShutterWire, "test_" + name, run)


for function in (
    test_independent_bind_vector, test_copy_bounds_and_capacity,
    test_max_commit_and_correlation_boundary, test_one_byte_copy_and_payload_length,
    test_copy_overlap_and_null, test_request_and_written_overlap_rejected,
    test_reply_vector_and_raw_fields, test_reserved_reply_correlation_does_not_modify_output, test_null_arguments,
    test_actual_cp_arm_instruction_exchange,
    test_optional_cp_peer_cannot_silently_skip_partial_materials,
):
    register(function.__name__[5:], function)

for name, op, words in (
    ("prepare", PREPARE, (1, 1, 0, 0)),
    ("commit", COMMIT, (1, 1, 32, 0x11223344)),
    ("policy", POLICY, (1, 1, 1, 0)),
    ("query", QUERY, (1, 0, 0, 0)),
):
    register("operation_words_" + name, test_operation_words, op, words)

for name, change, error in (
    ("zero_session", lambda r: setattr(r, "session", 0), SESSION),
    ("max_session", lambda r: setattr(r, "session", 0xFFFFFFFF), SESSION),
    ("zero_correlation", lambda r: setattr(r, "correlation", 0), CORRELATION),
    ("reserved_correlation", lambda r: setattr(r, "correlation", 65535), CORRELATION),
    ("unknown_operation", lambda r: setattr(r, "operation", 8), OPERATION),
    ("duplicate_bind_handle", lambda r: r.args.bind.handle.__setitem__(1, 101), ARGUMENT),
    ("invalid_bind_handle", lambda r: r.args.bind.handle.__setitem__(2, 0xFFFFFFFF), ARGUMENT),
    ("noncopy_payload", lambda r: setattr(r, "payload_length", 1), PAYLOAD),
):
    register("encode_rejects_" + name, test_encode_rejects_without_writes, change, error)

for name, op, change in (
    ("prepare_generation", PREPARE, lambda r: setattr(r.args.prepare, "generation", 0)),
    ("commit_alignment", COMMIT, lambda r: setattr(r.args.commit, "encoded_length", 31)),
    ("commit_length", COMMIT, lambda r: setattr(r.args.commit, "encoded_length", 123904)),
    ("policy_enable", POLICY, lambda r: setattr(r.args.policy, "enable", 2)),
    ("query_mode", QUERY, lambda r: setattr(r.args.query, "mode", 2)),
    ("copy_offset", COPY, lambda r: setattr(r.args.copy, "offset", 0xFFFFFFFF)),
    ("copy_length", COPY, lambda r: setattr(r.args.copy, "length", 961)),
):
    register("bad_" + name, test_bad_operation_arguments, op, change)

for name, mutation, error in (
    ("command", lambda b: b.__setitem__(slice(0, 2), b"\x7e\x00"), HEADER),
    ("reserved", lambda b: b.__setitem__(slice(2, 4), b"\x01\x00"), RESERVED),
    ("payload_bytes", lambda b: b.__setitem__(slice(4, 6), b"\x00\x00"), HEADER),
    ("correlation", lambda b: b.__setitem__(slice(6, 8), b"\x08\x00"), MISMATCH),
    ("session", lambda b: b.__setitem__(slice(8, 12), b"\x38\x00\x00\x00"), MISMATCH),
    ("operation", lambda b: b.__setitem__(slice(12, 16), b"\x02\x00\x00\x00"), MISMATCH),
    ("phase", lambda b: b.__setitem__(slice(16, 20), b"\x08\x00\x00\x00"), PHASE),
):
    register("bad_reply_" + name, test_bad_reply_does_not_modify_output, mutation, error)

for length in (0, 39, 41, 1000):
    register("exact_reply_length_" + str(length), test_exact_reply_length, length)


if __name__ == "__main__":
    unittest.main()
