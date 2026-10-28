"""Offline-first receiving protocol. No USB, loader, or device executor.

Transport adapters must STOP after any unknown result. A receiver instance is
single-use and never resumes a partial session. Only the fixed pilot is admitted.
"""
import hashlib
import json
import os
from pathlib import Path
import struct

CHUNK = 8 * 1024 * 1024
PILOT = ("cnflasha7", 135, 16777216)
RECORD = struct.Struct("<8s16sQQQ32s")
ACK = struct.Struct("<8s16sQ32s")


class StreamReceiver:
    ALLOWED_TARGETS = (PILOT,)

    def __init__(self, directory, nonce, target=PILOT, *, source_is_hardware=False):
        if not isinstance(nonce, bytes) or len(nonce) != 16:
            raise ValueError("16-byte nonce required")
        if tuple(target) not in self.ALLOWED_TARGETS:
            raise ValueError("Only the fixed pilot geometry is admitted")
        self.directory = Path(directory)
        self.directory.mkdir(mode=0o700)  # Existing/partial session is refused.
        self.nonce, self.target = nonce, target
        self.source_is_hardware = bool(source_is_hardware)
        self.index = self.offset = 0
        self.full = hashlib.sha256()
        self.stopped = self.verified = False
        self.file = (self.directory / (target[0] + ".partial")).open("xb")
        os.chmod(self.file.name, 0o600)
        self.manifest = (self.directory / "chunks.jsonl").open("x")
        os.chmod(self.manifest.name, 0o600)
        try:
            self._status("PARTIAL")
        except BaseException:
            self.stopped = True
            self.file.close()
            self.manifest.close()
            raise

    def _sync_dir(self):
        fd = os.open(self.directory, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _status(self, state, **extra):
        with (self.directory / "status.tmp").open("x") as f:
            os.chmod(f.name, 0o600)
            json.dump({"state": state, "partition": self.target[0],
                       "nonce": self.nonce.hex(), "bytes": self.offset,
                       "source_is_hardware": self.source_is_hardware,
                       "hardware_source_read_verified": self.source_is_hardware and state == "TWO_READS_MATCHED",
                       "restore_verified": False,
                       **extra}, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(self.directory / "status.tmp", self.directory / "status.json")
        self._sync_dir()

    def _require_active(self):
        if self.stopped or self.verified:
            raise RuntimeError("Session is terminal; no replay/resume")

    def accept(self, record, payload):
        """Return ACK only after validated data AND manifest have been fsynced."""
        self._require_active()
        try:
            magic, nonce, index, offset, length, digest = RECORD.unpack(record)
            expected = min(CHUNK, self.target[2] - self.offset)
            if (magic != b"M4CHNK01" or nonce != self.nonce or index != self.index
                    or offset != self.offset or length != expected or length <= 0
                    or len(payload) != length or hashlib.sha256(payload).digest() != digest):
                raise ValueError("Chunk identity, order, geometry, or hash rejected")
            if self.file.write(payload) != length:
                raise OSError("Short host write")
            self.file.flush()
            os.fsync(self.file.fileno())
            entry = {"nonce": nonce.hex(), "index": index, "offset": offset,
                     "bytes": length, "sha256": digest.hex()}
            self.manifest.write(json.dumps(entry) + "\n")
            self.manifest.flush()
            os.fsync(self.manifest.fileno())
            # Directory entries must also be durable before the first ACK.
            self._sync_dir()
            self.full.update(payload)
            self.index += 1
            self.offset += length
            return ACK.pack(b"M4SACK01", nonce, index, digest)
        except BaseException:
            self.abort("CHUNK_REJECTED_OR_UNKNOWN")
            raise

    def finish(self, record):
        """A final native second-pass digest must agree with local first pass."""
        self._require_active()
        try:
            magic, nonce, chunks, size, error, digest = RECORD.unpack(record)
            if (magic != b"M4DONE01" or nonce != self.nonce or chunks != self.index
                    or size != self.offset or size != self.target[2] or error
                    or digest != self.full.digest()):
                raise ValueError("Whole-partition second read did not verify")
            self.file.flush()
            os.fsync(self.file.fileno())
            # Re-read the actual host file, not only the transfer hash object.
            self.file.close()
            path = self.directory / (self.target[0] + ".partial")
            check = hashlib.sha256()
            with path.open("rb") as f:
                while block := f.read(65536):
                    check.update(block)
            if path.stat().st_size != size or check.digest() != digest:
                raise ValueError("Host on-disk readback mismatch")
            self.manifest.close()
            # Publish the verification marker last. A crash before it leaves
            # an unverified session even if the .bin hardlink already exists.
            final = self.directory / (self.target[0] + ".bin")
            os.link(path, final)  # Never overwrite an existing final file.
            self._sync_dir()
            self._status("TWO_READS_MATCHED", sha256=digest.hex(),
                         source_reads_equal_at_capture=True)
            self.verified = True
            # Keep the partial hardlink: no correctness-critical cleanup after
            # the terminal marker; a later explicit cleanup can remove it.
            return final
        except BaseException:
            self.abort("FINAL_REJECTED_OR_UNKNOWN")
            raise

    def abort(self, reason="UNKNOWN_TRANSPORT_RESULT"):
        if self.verified or self.stopped:
            return
        self.stopped = True
        for f in (self.file, self.manifest):
            if not f.closed:
                f.close()
        self._status("UNVERIFIED", reason=reason)
