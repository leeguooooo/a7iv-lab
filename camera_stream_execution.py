"""One-shot pilot orchestration on an injected, authenticated Senser device.

No USB discovery or service entry. Source verification must precede this call.
Module staging touches the camera's FAT scratch directory; sources stay read-only.
"""
import hashlib
import json
import os
from pathlib import Path
import struct
import time
from camera_stream_channel import StreamFileChannel
from camera_stream_collect import NATIVE, collect, native_status

SLOT = "/tmp/jiritsu/libJit.so"
LIBRARIES = {"/usr/lib/libJiritsu.so": "3b19665f84bcd1b837a3b9377b40a91893010ff9732be71a430f3d0265c72c69",
             "/lib/ld-2.25.so": "90b4fe734ba7faa08d4591b1363bff478e7bde399a821fc0b2d021c062a58a9a"}
LAUNCH = struct.Struct("<8s16s10q")


def durable_new(path, value):
    path = Path(path)
    with path.open("x") as f:
        os.chmod(path, 0o600)
        json.dump(value, f, indent=2)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class BootstrapChannel(StreamFileChannel):
    """The only extra writable camera path is the fixed libJit scratch slot."""
    def __init__(self, device, nonce, clock=time.monotonic):
        super().__init__(device, nonce, clock)
        self.module_attempted = False

    def _select_fixed(self, path):
        if path not in (*LIBRARIES, SLOT):
            raise ValueError("Fixed loader paths only")
        target = path if path == SLOT else "/tmp/jiritsu/../.." + path
        if self._packet(15, b"\0" + target.encode("ascii") + b"\0", 0) != b"":
            self.healthy = False
            raise ValueError("Select response changed")

    def read_loader(self, path):
        self._select_fixed(path)
        return self._packet(17, b"\0\xff\0", 65520 if path == SLOT else 300000, path == SLOT)

    def upload_once(self, module, expected_hash, attempt_path):
        if self.module_attempted:
            raise RuntimeError("Module already attempted; never replay")
        if not 0 < len(module) <= 65520 or hashlib.sha256(module).hexdigest() != expected_hash:
            raise ValueError("Module bytes differ from reviewed artifact")
        self.module_attempted = True
        durable_new(attempt_path, {"nonce": self.nonce.hex(), "module_sha256": expected_hash,
                                   "automatic_retry": False, "state": "ATTEMPT_RESERVED_BEFORE_USB"})
        self._select_fixed(SLOT)
        if self._packet(16, b"\0\xff\0" + module, 0) != b"":
            self.healthy = False
            raise ValueError("Module upload response changed")


def validate_launch(raw, nonce):
    values = LAUNCH.unpack(raw)
    if (values[:3] != (b"M4BOOT01", nonce, 1) or values[3:6] != (3, 0, 0)
            or values[6] <= 1 or values[7] != 0 or values[8] <= 0
            or values[8] != values[9] or values[10] != 0):
        raise ValueError("Bootstrap launch rejected")
    return values[6]


def poll_record(channel, name, length, seconds, clock=time.monotonic, sleep=time.sleep):
    deadline = clock() + seconds
    while clock() < deadline:
        raw = channel.read(name, missing=True)
        if raw is not None:
            if len(raw) == length:
                return raw
            if len(raw) > length:
                raise ValueError("Oversized native record")
            # Old lifecycle save_new writes may briefly expose a short file.
            # It is a known read result; re-observe without replaying a write.
        if channel.read("exec_failure", missing=True) is not None:
            raise RuntimeError("Native exec failed")
        final = channel.read("result", missing=True) if name != "result" else None
        if final is not None and len(final) == NATIVE.size:
            status = native_status(final, channel.nonce)
            if status["phase"] == 90 or status["error"] or status["cleanup"]:
                raise RuntimeError("Native lifecycle failed")
        sleep(0.1)
    raise TimeoutError("Native record deadline; no upload retry")


def _execute_profile(channel, module, expected_hash, evidence, target, chunks, collector,
                     clock=time.monotonic, sleep=time.sleep):
    """Caller owns normal-body verification, authentication and USB exit policy."""
    evidence = Path(evidence)
    if not evidence.is_dir():
        raise ValueError("Fresh evidence directory must already exist")
    for path, expected in LIBRARIES.items():
        if hashlib.sha256(channel.read_loader(path)).hexdigest() != expected:
            raise ValueError("Camera loader library differs from reviewed profile")
    if channel.read_loader(SLOT) is not None:
        raise RuntimeError("Existing module slot belongs to another operation")
    channel.upload_once(module, expected_hash, evidence / "module-attempt.json")
    raw_launch = poll_record(channel, "launch", LAUNCH.size, 30, clock, sleep)
    loader_pid = validate_launch(raw_launch, channel.nonce)
    raw_ready = poll_record(channel, "ready", NATIVE.size, 30, clock, sleep)
    ready = native_status(raw_ready, channel.nonce)
    if (ready["phase"] != 1 or ready["error"] or ready["euid"] or ready["ppid"] != 1
            or ready["cleanup"] or ready["loader_pid"] != loader_pid or ready["flags"] != 3):
        raise ValueError("Worker readiness rejected")
    durable_new(evidence / "launch-and-ready.json", {"loader_pid": loader_pid, "ready": ready})
    channel.write_control("start", b"M4START1" + channel.nonce + struct.pack("<Q", 1))
    backup = collector(channel, evidence / "capture", clock=clock, sleep=sleep)
    final = native_status(poll_record(channel, "result", NATIVE.size, 10, clock, sleep), channel.nonce)
    if (final["phase"] != 6 or final["error"] or final["cleanup"] or final["flags"] != 63
            or final["offset"] != target[2] or final["chunks"] != chunks):
        raise ValueError("Final native status rejected")
    captured = json.loads((evidence / "capture/status.json").read_text())
    if final["first_sha256"] != final["second_sha256"] or final["first_sha256"] != captured["sha256"]:
        raise ValueError("Final native digests differ from verified capture")
    if channel.read_loader(SLOT) is not None:
        raise RuntimeError("Bootstrap slot cleanup was not confirmed")
    durable_new(evidence / "completed.json", {"partition": target[0], "bytes": target[2],
                                             "backup": str(backup), "native": final,
                                             "whole_emmc_backup": False, "physical_NOR_backup": False,
                                             "restoration_verified": False})
    return backup


def execute_authenticated(channel, module, expected_hash, evidence,
                          clock=time.monotonic, sleep=time.sleep):
    return _execute_profile(channel, module, expected_hash, evidence,
                            ("cnflasha7", 135, 16777216), 2, collect, clock, sleep)
