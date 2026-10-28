"""Bounded Senser packet framing, preserving the SDK's explicit ZLP consume.

No connection/discovery here. The caller supplies a driver with strict read()
and a separate read_padding() operation. Only the latter permits an empty USB
packet, once at a protocol-defined separator; payload/header empties still stop.
"""


def send_senser_packet(device, pfunc, data, sink):
    header_type = device.SenserPacketHeader
    maximum = device.SenserMaxSize
    minimum = 0 if device.driver.getId()[1] == 0x0336 else device.SenserMinSize
    if not 0 < len(data) <= 65527:
        raise ValueError("Request outside reviewed single-upload bound")
    sequence = device._sequence
    header = header_type.pack(size=len(data), pFunc=pfunc, sequence=sequence,
                              version=0, miconType=0, offsetType=0, response=0)
    device.driver.write(header + data)

    def read_exact(count):
        chunks, done = [], 0
        while done < count:
            raw = device.driver.read(count - done)  # Empty DATA is forbidden.
            chunks.append(raw)
            done += len(raw)
        return b"".join(chunks)

    # A logical response uses <=ceil(bound/1MiB) nonempty fragments. Allow one
    # extra terminal header but never an unbounded stream of oversized headers.
    fragment_limit = (sink.maximum + maximum - 1) // maximum + 1
    for fragment in range(fragment_limit):
        initial = device.driver.read(max(minimum, header_type.size))
        if len(initial) < header_type.size:
            raise ValueError("Short Senser header")
        reply = header_type.unpack(initial)
        if reply.sequence != sequence:
            raise ValueError("Wrong Senser sequence")
        if fragment == 0 and reply.size > sink.maximum:
            raise ValueError("Declared response exceeds receive bound")
        data_length = min(reply.size, maximum)
        prefix = initial[header_type.size:]
        if len(prefix) > data_length:
            raise ValueError("Header payload exceeds declared fragment")
        sink.write(prefix)
        done = len(prefix)
        chunk_length = device.SenserChunkSize - minimum
        while done < data_length:
            count = min(data_length - done, chunk_length)
            sink.write(read_exact(count))
            done += count
            if not (count & (device.SenserMinSize - 1)):
                # This is the SDK's discarded USB separator read. A genuine
                # zero-length packet is valid ONLY in this explicitly marked slot.
                device.driver.read_padding(device.SenserMinSize)
            chunk_length = device.SenserChunkSize
        if reply.size <= maximum:
            device._sequence += 1
            return reply.response, None
    raise ValueError("Response fragment budget exceeded")
