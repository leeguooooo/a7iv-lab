"""Bounded tmpfs file protocol on an ALREADY supplied Senser device.

No enumeration, service-mode transition, module upload, or execution entry point.
This channel only reads fixed job files and uploads fixed START/ACK records.
"""
import struct
import time
from camera_stream_receiver import ACK, CHUNK
from camera_stream_transport_bounds import BoundedSink, ReadGuard
from camera_stream_senser import send_senser_packet

READ_LIMITS = {"launch": 104, "ready": 184, "result": 184, "exec_failure": 8,
               "loader_maps": 524288, "loader_fds": 131072,
               "chunk.ready": 80, "chunk.bin": CHUNK, "done": 80}


class _DriverProxy:
    def __init__(self, driver, deadline, clock):
        self.original, self.clock, self.deadline = driver, clock, deadline
        self.reader = ReadGuard(driver, deadline, clock)

    def getId(self):
        return self.original.getId()

    def reset(self):
        # SonySenserAuthDevice's inherited constructor calls driver.reset().
        # Preserve the existing driver's host-interface setup, with the same
        # deadline/terminal-error boundary as reads and writes.
        if self.reader.failed:
            raise RuntimeError("Driver already stopped")
        try:
            if self.clock() >= self.deadline:
                raise TimeoutError("Driver setup deadline")
            result = self.original.reset()
            if self.clock() >= self.deadline:
                raise TimeoutError("Driver setup deadline")
            return result
        except BaseException as error:
            self.reader.failed = True
            error.camera_stream_operation = "reset"
            raise

    def read(self, count):
        try:
            return self.reader.read(count)
        except BaseException as error:
            error.camera_stream_operation = "read"
            error.camera_stream_requested_bytes = count
            raise

    def read_padding(self, count):
        try:
            return self.reader.read(count, allow_empty=True)
        except BaseException as error:
            error.camera_stream_operation = "read_padding"
            error.camera_stream_requested_bytes = count
            raise

    def write(self, data):
        if self.reader.failed:
            raise RuntimeError("Driver already stopped")
        try:
            if self.clock() >= self.deadline:
                raise TimeoutError("Packet write deadline")
            if not data or len(data) > 0x100000 + 12:
                raise ValueError("Unexpected packet write bound")
            result = self.original.write(data)
            if result is not None and result != len(data):
                raise OSError("Short driver write")
            if self.clock() >= self.deadline:
                raise TimeoutError("Packet write deadline")
            return result
        except BaseException as error:
            self.reader.failed = True
            error.camera_stream_operation = "write"
            error.camera_stream_requested_bytes = len(data) if isinstance(data, (bytes, bytearray, memoryview)) else 0
            raise


class StreamFileChannel:
    ACK_CHUNKS = 2

    def __init__(self, senser_device, nonce, clock=time.monotonic, *, send_packet=send_senser_packet):
        if not isinstance(nonce, bytes) or len(nonce) != 16:
            raise ValueError("16-byte job nonce required")
        self.device, self.nonce, self.clock = senser_device, nonce, clock
        self.send_packet = send_packet
        self.directory = "/tmp_wbshd/m4stream_" + nonce.hex()
        self.healthy = True

    def _packet(self, command, data, maximum, missing=False):
        if not self.healthy:
            raise RuntimeError("Unknown/failed USB result; session stopped, no retry")
        original = self.device.driver
        try:
            self.device.driver = _DriverProxy(original, self.clock() + 120, self.clock)
            with BoundedSink(maximum + 4) as sink:
                response, _ = self.send_packet(self.device,
                    0x40, struct.pack("<HH", 0x1001, command) + data, sink)
                raw = sink.getvalue()
            if response != 0 or len(raw) < 4:
                raise ValueError("Malformed Senser response")
            status = struct.unpack_from("<I", raw)[0]
            if status == 0x10000006 and missing and command == 17 and len(raw) == 4:
                return None
            if status:
                raise RuntimeError("Camera file status 0x%08x" % status)
            return raw[4:]
        except BaseException:
            self.healthy = False
            raise
        finally:
            self.device.driver = original

    def _select(self, name):
        path = "/tmp/jiritsu/../.." + self.directory + "/" + name
        if self._packet(15, b"\0" + path.encode("ascii") + b"\0", 0) != b"":
            self.healthy = False
            raise ValueError("Select response changed")

    def read(self, name, missing=False):
        if name not in READ_LIMITS:
            raise ValueError("Only fixed job files may be read")
        self._select(name)
        return self._packet(17, b"\0\xff\0", READ_LIMITS[name], missing)

    def write_control(self, name, data):
        if name == "start":
            expected = b"M4START1" + self.nonce + struct.pack("<Q", 1)
            if data != expected:
                raise ValueError("Invalid START")
        elif name == "ack":
            magic, nonce, index, digest = ACK.unpack(data)
            if magic != b"M4SACK01" or nonce != self.nonce or index >= self.ACK_CHUNKS:
                raise ValueError("Invalid pilot ACK")
        else:
            raise ValueError("Only START and ACK may be uploaded")
        self._select(name)
        if self._packet(16, b"\0\xff\0" + data, 0) != b"":
            self.healthy = False
            raise ValueError("Control upload response changed")
