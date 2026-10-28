import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from camera_stream_receiver import ACK, RECORD, StreamReceiver
from stock_p1_readback import TARGET, CHUNKS, P1ReadbackReceiver, P1ReadbackChannel, collect_p1_readback
from camera_stream_collect import NATIVE
from camera_stream_execution import LAUNCH


class P1ReadbackTests(unittest.TestCase):
    def test_final_worker_identity_bound_to_launch_and_ready(self):
        nonce = bytes(range(16))
        def status(pid=234, phase=1):
            return NATIVE.pack(b'M4STR001', nonce, 1, phase, 0, 0, pid, 1, 123,
                               0, 0, 0, 0, 3 if phase == 1 else 63, bytes(32), bytes(32))
        for final_pid in (234, 235):
            channel = P1ReadbackChannel(Mock(), nonce, writer_nonce=bytes(16))
            launch = LAUNCH.pack(b'M4BOOT01', nonce, 1, 3, 0, 0, 123, 0, 234, 234, 0, 409600000)
            with patch('camera_stream_channel.StreamFileChannel.read',
                       side_effect=[launch, status(), status(final_pid, 6)]):
                channel.read('launch')
                channel.read('ready')
                if final_pid == 234:
                    channel.read('result')
                    self.assertTrue(channel.healthy)
                else:
                    with self.assertRaises(ValueError):
                        channel.read('result')
                    self.assertFalse(channel.healthy)

    def test_final_without_readiness_is_rejected(self):
        nonce = bytes(range(16))
        channel = P1ReadbackChannel(Mock(), nonce, writer_nonce=bytes(16))
        raw = NATIVE.pack(b'M4STR001', nonce, 1, 6, 0, 0, 234, 1, 123, 0,
                          3, TARGET[2], 3, 63, bytes(32), bytes(32))
        with patch('camera_stream_channel.StreamFileChannel.read', return_value=raw):
            with self.assertRaises(ValueError):
                channel.read('result')
        self.assertFalse(channel.healthy)

    def test_only_fixed_p1_geometry_admitted(self):
        with tempfile.TemporaryDirectory() as temp:
            for target in (('cnflasha1', 129, 32768), ('cnflasha1', 130, TARGET[2]),
                           ('cnflasha7', 135, 16777216)):
                with self.assertRaises(ValueError):
                    P1ReadbackReceiver(Path(temp) / 'wrong', bytes(16), target=target)
            with self.assertRaises(ValueError):
                StreamReceiver(Path(temp) / 'pilot', bytes(16), target=TARGET)

    def test_nonce_separation_and_three_ack_bound(self):
        for nonce in (bytes(16), 'a' * 16, bytes(15)):
            with self.assertRaises(ValueError):
                P1ReadbackChannel(Mock(), nonce, writer_nonce=bytes(16))
        nonce = bytes(range(16))
        channel = P1ReadbackChannel(Mock(), nonce, writer_nonce=bytes(16))
        channel._packet = Mock(return_value=b'')
        channel.write_control('ack', ACK.pack(b'M4SACK01', nonce, 2, b'x' * 32))
        count = channel._packet.call_count
        with self.assertRaises(ValueError):
            channel.write_control('ack', ACK.pack(b'M4SACK01', nonce, 3, b'x' * 32))
        self.assertEqual(channel._packet.call_count, count)

    def test_full_real_geometry_and_short_last_chunk(self):
        payload = bytes(range(256)) * (TARGET[2] // 256)
        digest = hashlib.sha256(payload).digest()
        class Channel:
            nonce = bytes(range(16))
            index = 0
            lengths = []
            def read(self, name, missing=False):
                start = self.index * 8388608
                part = payload[start:start + 8388608]
                if name == 'chunk.ready':
                    return RECORD.pack(b'M4CHNK01', self.nonce, self.index, start, len(part),
                                       hashlib.sha256(part).digest())
                if name == 'chunk.bin':
                    self.lengths.append(len(part))
                    return part
                if name == 'done':
                    return RECORD.pack(b'M4DONE01', self.nonce, self.index, len(payload), 0, digest)
                raise AssertionError(name)
            def write_control(self, name, raw):
                magic, nonce, index, got = ACK.unpack(raw)
                assert name == 'ack' and magic == b'M4SACK01' and nonce == self.nonce and index == self.index
                self.index += 1
        channel = Channel()
        with tempfile.TemporaryDirectory() as temp:
            result = collect_p1_readback(channel, Path(temp) / 'capture', sleep=lambda _: None)
            self.assertEqual(result.read_bytes(), payload)
        self.assertEqual(channel.index, CHUNKS)
        self.assertEqual(channel.lengths, [8388608, 8388608, 8323072])


if __name__ == '__main__':
    unittest.main()
