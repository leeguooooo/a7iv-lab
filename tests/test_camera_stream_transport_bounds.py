import unittest
from unittest.mock import Mock
from camera_stream_transport_bounds import BoundedSink, ReadGuard


class BoundsTests(unittest.TestCase):
    def test_incremental_limit(self):
        sink = BoundedSink(8)
        sink.write(b"1234")
        sink.write(b"5678")
        with self.assertRaises(ValueError):
            sink.write(b"9")
        self.assertEqual(sink.getvalue(), b"12345678")

    def test_empty_read_is_terminal(self):
        driver = Mock()
        driver.read.return_value = b""
        guard = ReadGuard(driver, 10, clock=lambda: 1)
        with self.assertRaises(ValueError):
            guard.read(100)
        with self.assertRaises(RuntimeError):
            guard.read(100)
        self.assertEqual(driver.read.call_count, 1)

    def test_expired_before_read(self):
        driver = Mock()
        with self.assertRaises(TimeoutError):
            ReadGuard(driver, 1, clock=lambda: 1).read(100)
        driver.read.assert_not_called()

    def test_expired_after_read(self):
        driver = Mock()
        driver.read.return_value = b"abc"
        with self.assertRaises(TimeoutError):
            ReadGuard(driver, 2, clock=Mock(side_effect=[1, 3])).read(100)

    def test_oversized_read(self):
        driver = Mock()
        driver.read.return_value = b"abc"
        with self.assertRaises(ValueError):
            ReadGuard(driver, 10, clock=lambda: 1).read(2)

    def test_short_read_allowed(self):
        driver = Mock()
        driver.read.return_value = b"abc"
        self.assertEqual(ReadGuard(driver, 10, clock=lambda: 1).read(100), b"abc")


if __name__ == "__main__":
    unittest.main()
