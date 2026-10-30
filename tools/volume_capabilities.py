"""Read Darwin volume capability declarations without changing the filesystem."""
import argparse
import ctypes
import json
import os
from pathlib import Path
import sys


class AttrList(ctypes.Structure):
    _fields_ = [
        ("bitmapcount", ctypes.c_uint16),
        ("reserved", ctypes.c_uint16),
        ("commonattr", ctypes.c_uint32),
        ("volattr", ctypes.c_uint32),
        ("dirattr", ctypes.c_uint32),
        ("fileattr", ctypes.c_uint32),
        ("forkattr", ctypes.c_uint32),
    ]


class CapabilityReply(ctypes.Structure):
    _fields_ = [
        ("length", ctypes.c_uint32),
        ("capabilities", ctypes.c_uint32 * 4),
        ("valid", ctypes.c_uint32 * 4),
    ]


INTERFACE_CAPABILITIES = {
    "RENAME_EXCL": 0x00080000,
    "RENAME_SWAP": 0x00040000,
    "EXCHANGEDATA": 0x00000010,
    "FLOCK": 0x00000200,
    "BARRIERFSYNC": 0x01000000,
}


def inspect(path):
    if sys.platform != "darwin":
        raise RuntimeError("Darwin getattrlist is required")
    if ctypes.sizeof(AttrList) != 24 or ctypes.sizeof(CapabilityReply) != 36:
        raise RuntimeError("Unexpected native attrlist or reply size")
    path = Path(path).absolute()
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError("Nonsymlink path required")
    before = path.stat()
    attributes = AttrList(bitmapcount=5, volattr=0x80020000)
    reply = CapabilityReply()
    library = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    function = library.getattrlist
    function.argtypes = [ctypes.c_char_p, ctypes.POINTER(AttrList),
                         ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong]
    function.restype = ctypes.c_int
    ctypes.set_errno(0)
    result = function(os.fsencode(path), ctypes.byref(attributes),
                      ctypes.byref(reply), ctypes.sizeof(reply), 0)
    if result != 0:
        number = ctypes.get_errno()
        raise OSError(number, os.strerror(number), str(path))
    if reply.length != ctypes.sizeof(reply):
        raise RuntimeError("Unexpected volume capability reply length")
    after = path.stat()
    if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
        raise RuntimeError("Queried path identity changed")
    capabilities, valid = reply.capabilities[1], reply.valid[1]
    declarations = {}
    for name, bit in INTERFACE_CAPABILITIES.items():
        known = bool(valid & bit)
        declarations[name] = {"bit": hex(bit), "valid": known,
                              "declared_supported": bool(capabilities & bit) if known else None}
    return {
        "scope": "read-only getattrlist declaration; no rename or write probe",
        "path": str(path),
        "path_device": before.st_dev,
        "path_inode": before.st_ino,
        "request_attrlist_bytes": ctypes.sizeof(attributes),
        "reply_bytes": reply.length,
        "capabilities": [hex(value) for value in reply.capabilities],
        "valid": [hex(value) for value in reply.valid],
        "interfaces": declarations,
        "mutating_operation_tested": False,
        "actual_atomicity_proven": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path")
    arguments = parser.parse_args()
    try:
        report = inspect(arguments.path)
    except (OSError, ValueError, RuntimeError) as error:
        print(json.dumps({"scope": "read-only capability query", "query_succeeded": False,
                          "error_type": type(error).__name__, "error": str(error),
                          "errno": getattr(error, "errno", None)}))
        return 1
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
