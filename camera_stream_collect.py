"""Collect one started pilot from an injected channel. No connection/upload API."""
import struct
import time
from camera_stream_receiver import CHUNK, PILOT, RECORD, StreamReceiver

NATIVE = struct.Struct("<8s16s12q32s32s")


def native_status(raw, nonce):
    magic, got, *values = NATIVE.unpack(raw)
    if magic != b"M4STR001" or got != nonce or values[0] != 1:
        raise ValueError("Native status identity mismatch")
    return dict(zip(("version", "phase", "error", "euid", "pid", "ppid", "loader_pid",
                     "cleanup", "index", "offset", "chunks", "flags"), values[:12])) | {
                         "first_sha256": values[12].hex(), "second_sha256": values[13].hex()}


def _collect_profile(channel, directory, target, receiver_type, clock=time.monotonic, sleep=time.sleep):
    """No START here: the caller must independently validate launch/readiness.

    Successful known-missing polls are allowed. Unknown results are never retried.
    Re-observing the just-ACKed record is allowed, but its ACK is never replayed.
    """
    receiver = receiver_type(directory, channel.nonce, target=target,
                              source_is_hardware=getattr(channel, "source_is_hardware", False))
    last = None
    deadline = clock() + 240
    try:
        while receiver.offset < target[2]:
            if clock() >= deadline:
                raise TimeoutError("No next chunk; stop without replay")
            raw = channel.read("chunk.ready", missing=True)
            if raw is not None and raw != last:
                # Validate metadata BEFORE pulling the up-to-8MiB payload.
                magic, nonce, index, offset, length, digest = RECORD.unpack(raw)
                if (magic != b"M4CHNK01" or nonce != channel.nonce
                        or index != receiver.index or offset != receiver.offset
                        or length != min(CHUNK, target[2] - receiver.offset)):
                    raise ValueError("Unexpected chunk metadata")
                payload = channel.read("chunk.bin")
                ack = receiver.accept(raw, payload)
                channel.write_control("ack", ack)
                last = raw
                deadline = clock() + 240
                continue
            final = channel.read("result", missing=True)
            if final is not None:
                status = native_status(final, channel.nonce)
                if status["error"] or status["cleanup"] or status["phase"] == 90:
                    raise RuntimeError("Native worker stopped with error")
                raise RuntimeError("Native worker ended before full first-pass capture")
            if channel.read("exec_failure", missing=True) is not None:
                raise RuntimeError("Native worker exec failed")
            sleep(0.1)
        deadline = clock() + 180
        while clock() < deadline:
            done = channel.read("done", missing=True)
            if done is not None:
                return receiver.finish(done)
            final = channel.read("result", missing=True)
            if final is not None:
                status = native_status(final, channel.nonce)
                if status["error"] or status["cleanup"] or status["phase"] != 6:
                    raise RuntimeError("Native second pass failed")
                # DONE must precede the successful result; seeing result after
                # a known-missing DONE is a publication race. Re-read DONE once,
                # with a known result, never retry an unknown transport error.
                return receiver.finish(channel.read("done"))
            sleep(0.1)
        raise TimeoutError("Second-pass completion deadline")
    except BaseException:
        receiver.abort()
        raise


def collect(channel, directory, clock=time.monotonic, sleep=time.sleep):
    return _collect_profile(channel, directory, PILOT, StreamReceiver, clock, sleep)
