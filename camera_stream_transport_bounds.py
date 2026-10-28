"""Receive-only guards for a future USB adapter; no connection or execution."""
import io
import time


class BoundedSink(io.BytesIO):
    def __init__(self, maximum):
        if not isinstance(maximum, int) or maximum <= 0:
            raise ValueError("Positive receive bound required")
        super().__init__()
        self.maximum = maximum
        self.failed = False

    def write(self, data):
        if self.failed:
            raise RuntimeError("Oversized response already stopped this receive")
        if self.tell() + len(data) > self.maximum:
            self.failed = True
            raise ValueError("Response exceeds predeclared receive bound; stop session")
        return super().write(data)


class ReadGuard:
    """Guards an existing driver's reads, without changing or retrying writes.

    The underlying driver MUST have its own finite blocking-read timeout.
    A clock check cannot interrupt a driver blocked inside a native read.
    Empty, oversized, failed, or expired reads are terminal to the caller.
    """
    def __init__(self, driver, deadline, clock=time.monotonic):
        self.driver, self.deadline, self.clock = driver, deadline, clock
        self.failed = False

    def read(self, count, *, allow_empty=False):
        if self.failed:
            raise RuntimeError("Unknown/failed receive; no retry")
        try:
            if not isinstance(count, int) or count <= 0 or count > 32768:
                raise ValueError("Read outside protocol subchunk bound")
            if self.clock() >= self.deadline:
                raise TimeoutError("Receive deadline")
            data = self.driver.read(count)
            if not isinstance(data, bytes) or not (0 if allow_empty else 1) <= len(data) <= count:
                raise ValueError("Empty or oversized driver read")
            if self.clock() >= self.deadline:
                raise TimeoutError("Receive deadline")
            return data
        except BaseException:
            self.failed = True
            raise
