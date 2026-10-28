"""Evidence classification only. This module cannot command or modify a camera.

A missing/timeout USB receipt never proves that the autonomous native writer
stopped. A trusted final receipt is a userspace descriptor-closure proof from
the reviewed native code, not a universal controller/other-writer guarantee.
"""
from dataclasses import dataclass
import struct

FRAME = struct.Struct("<8s16s15q32s32s")
FIELDS = ("version", "phase", "error", "euid", "pid", "ppid", "loader_pid", "cleanup",
          "mode", "rows", "write_calls", "write_bytes", "rollback", "flags", "io_status")
P1_BYTES = 25100288


def _sha256(value):
    return (isinstance(value, str) and len(value) == 64
            and all(c in "0123456789abcdef" for c in value))


@dataclass(frozen=True)
class Proposal:
    nonce: bytes
    mode: int
    rows: int
    forward_bytes: int
    source_sha256: str
    target_sha256: str

    def __post_init__(self):
        if (not isinstance(self.nonce, bytes) or len(self.nonce) != 16
                or type(self.mode) is not int or type(self.rows) is not int
                or type(self.forward_bytes) is not int
                or self.mode not in (1, 2) or not 1 <= self.rows <= 768
                or not 0 < self.forward_bytes <= P1_BYTES):
            raise ValueError("Invalid fixed P1 proposal")
        for value in (self.source_sha256, self.target_sha256):
            if not _sha256(value):
                raise ValueError("Full SHA-256 required")
        if self.source_sha256 == self.target_sha256:
            raise ValueError("Positive write proposal requires distinct images")


def decode_final(raw, expected):
    if len(raw) != FRAME.size:
        raise ValueError("Incomplete native final receipt")
    magic, nonce, *v = FRAME.unpack(raw)
    result = dict(zip(FIELDS, v[:15])) | {"before_sha256": v[15].hex(), "after_sha256": v[16].hex()}
    if (magic != b"M4P1WR01" or nonce != expected.nonce or result["version"] != 1
            or result["mode"] != expected.mode or result["rows"] != expected.rows
            or result["phase"] not in (6, 90) or result["euid"] != 0
            or result["pid"] <= 1 or result["ppid"] != 1 or result["loader_pid"] <= 1
            or result["pid"] == result["loader_pid"] or result["cleanup"] != 0
            or result["rollback"] not in (0, 1, 2) or not 0 <= result["flags"] <= 255
            or result["io_status"] > 0
            or not 0 <= result["write_calls"] <= 2 * expected.rows * 4096
            or not 0 <= result["write_bytes"] <= 2 * expected.forward_bytes
            or (result["write_calls"] == 0 and result["write_bytes"] != 0)):
        raise ValueError("Unbound, nonterminal or contradictory receipt")
    return result


def classify(expected, final_receipt=None, independent_read=None):
    """Caller first verifies approved native artifacts and final-file provenance.

    Independent read must be a separately nonce-bound full P1 capture with two
    source passes plus host readback, from the same identified camera. This
    function returns evidence states; it does not grant user authorization.
    """
    answer = {"state": "UNKNOWN_WITHOUT_NATIVE_TERMINAL_PROOF",
              "native_writer_terminal_proven": False,
              "evidence_supports_session_end": False,
              "automatic_recommit": False, "automatic_host_rollback": False,
              "automatic_camera_reboot": False, "camera_commands_executed": 0}
    observed = None
    if independent_read is not None:
        value = independent_read
        if (value.get("bytes") != P1_BYTES or value.get("camera_body_matched") is not True
                or value.get("source_reads_equal") is not True or value.get("host_readback_verified") is not True
                or not isinstance(value.get("reader_nonce"), str) or len(value["reader_nonce"]) != 32
                or len(bytes.fromhex(value["reader_nonce"])) != 16
                or bytes.fromhex(value["reader_nonce"]) == expected.nonce
                or not _sha256(value.get("host_sha256"))
                or value.get("first_sha256") != value.get("second_sha256")
                or value.get("first_sha256") != value.get("host_sha256")):
            raise ValueError("Not a bound independent full P1 read")
        observed = value["host_sha256"]
        answer["independent_host_sha256"] = observed
        answer["independent_read_nonce"] = bytes.fromhex(value["reader_nonce"]).hex()
        answer["independent_read_state"] = ("target" if observed == expected.target_sha256 else
                                             "source" if observed == expected.source_sha256 else "neither_known_image")
    if final_receipt is None:
        return answer  # Even a matching image cannot prove a still-live writer won't roll back.
    result = decode_final(final_receipt, expected)
    if result["io_status"] != 0:
        answer["state"] = "NATIVE_CLOSE_FAILED_REQUIRES_MANUAL_REVIEW"
        return answer
    answer["native_writer_terminal_proven"] = True
    if result["phase"] == 6:
        if (result["error"] or result["io_status"] or result["rollback"] or result["flags"] != 255
                or result["before_sha256"] != expected.source_sha256
                or result["after_sha256"] != expected.target_sha256
                or result["write_calls"] < expected.rows or result["write_bytes"] != expected.forward_bytes):
            raise ValueError("Inconsistent native success")
        answer["state"] = "NATIVE_TARGET_VERIFIED_INDEPENDENT_READ_REQUIRED"
        if observed is not None:
            if observed != expected.target_sha256:
                answer["state"] = "NATIVE_AND_INDEPENDENT_READ_CONTRADICT"
            else:
                answer["state"] = "TARGET_VERIFIED_AND_INDEPENDENTLY_RECONCILED"
                answer["evidence_supports_session_end"] = True
    else:
        if result["error"] >= 0:
            raise ValueError("Error phase without error")
        if result["rollback"] == 1:
            if (result["after_sha256"] != expected.source_sha256 or result["before_sha256"] != expected.source_sha256
                    or result["io_status"] or not result["flags"] & 32 or result["write_calls"] == 0):
                raise ValueError("Invalid native rollback proof")
            answer["state"] = "NATIVE_ROLLBACK_VERIFIED_INDEPENDENT_READ_REQUIRED"
            if observed is not None:
                if observed != expected.source_sha256:
                    answer["state"] = "NATIVE_AND_INDEPENDENT_READ_CONTRADICT"
                else:
                    answer["state"] = "ORIGINAL_VERIFIED_AFTER_NATIVE_ROLLBACK"
                    answer["evidence_supports_session_end"] = True
        elif result["write_calls"] == 0 and result["rollback"] == 0:
            answer["state"] = "NATIVE_REFUSED_WITH_ZERO_PWRITE_CALLS"
            answer["evidence_supports_session_end"] = observed == expected.source_sha256 and result["io_status"] == 0
        else:
            answer["state"] = "NATIVE_ERROR_OR_ROLLBACK_FAILURE_REQUIRES_MANUAL_REVIEW"
    return answer
