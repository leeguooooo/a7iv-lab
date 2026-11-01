"""Two fixed OSAL library reads on an already authenticated Senser device.

The caller owns discovery, authentication, the host lease/history check and
service exit. This module sends only existing filename-select and GET packets.
"""
from camera_stream_channel import StreamFileChannel


LIBRARIES = {
    'libosal_utm.so': '/usr/lib/libosal_utm.so',
    'libosal_uipc.so': '/usr/lib/libosal_uipc.so',
}
MAXIMUM_BYTES = 65536


class NativeLibraryReader:
    def __init__(self, device, nonce, *, send_packet=None):
        options = {} if send_packet is None else dict(send_packet=send_packet)
        self._channel = StreamFileChannel(device, nonce, **options)
        self._attempted = set()

    def read(self, name):
        if name not in LIBRARIES:
            raise ValueError('Only the two fixed OSAL libraries may be read')
        if name in self._attempted or not self._channel.healthy:
            raise RuntimeError('Library read already attempted or channel stopped')
        self._attempted.add(name)
        target = '/tmp/jiritsu/../..' + LIBRARIES[name]
        selected = self._channel._packet(15, b'\0' + target.encode('ascii') + b'\0', 0)
        if selected != b'':
            self._channel.healthy = False
            raise ValueError('Select response changed')
        return self._channel._packet(17, b'\0\xff\0', MAXIMUM_BYTES)
