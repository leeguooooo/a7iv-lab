from types import SimpleNamespace
from collections import deque
import hashlib
from unittest.mock import Mock
import unittest
from camera_stream_service import START_REQUEST, STOP_REQUEST, service_transaction
from camera_stream_service import usb_error_diagnostic, known_start_stall


class ServiceDevice:
    def __init__(self):
        self.driver = Mock()


class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.normal = SimpleNamespace(driver=Mock())
        self.service = ServiceDevice()
        self.auth, self.work = Mock(), Mock(return_value="verified")

    def run_transaction(self, discover=None, clock=lambda: 1):
        return service_transaction(self.normal, discover or (lambda: [self.service]),
                                   self.auth, self.work, ServiceDevice,
                                   clock=clock, sleep=lambda _: None)

    def test_success_exits_once(self):
        self.assertEqual(self.run_transaction(), "verified")
        self.assertEqual(self.normal.driver.vendorRequestOut.call_args_list[0].args, START_REQUEST)
        self.assertEqual([c.args for c in self.service.driver.vendorRequestOut.call_args_list],
                         [START_REQUEST, STOP_REQUEST])
        self.assertEqual(self.auth.call_count, 2)

    def test_unknown_work_never_sends_exit(self):
        self.work.side_effect = OSError("USB result unknown")
        with self.assertRaises(OSError):
            self.run_transaction()
        self.assertEqual([c.args for c in self.service.driver.vendorRequestOut.call_args_list],
                         [START_REQUEST])

    def test_auth_error_never_sends_more_requests(self):
        self.auth.side_effect = OSError("auth read failed")
        with self.assertRaises(OSError):
            self.run_transaction()
        self.service.driver.vendorRequestOut.assert_not_called()
        self.work.assert_not_called()

    def test_service_auth_error_never_sends_exit(self):
        self.auth.side_effect = [None, OSError("service auth failed")]
        with self.assertRaises(OSError):
            self.run_transaction()
        self.assertEqual(self.service.driver.vendorRequestOut.call_count, 1)
        self.work.assert_not_called()

    def test_start_unknown_does_not_authenticate(self):
        self.normal.driver.vendorRequestOut.side_effect = OSError("start unknown")
        with self.assertRaises(OSError):
            self.run_transaction()
        self.auth.assert_not_called()

    def test_exit_unknown_is_never_retried(self):
        self.service.driver.vendorRequestOut.side_effect = [None, OSError("exit unknown")]
        with self.assertRaises(OSError):
            self.run_transaction()
        self.assertEqual(self.service.driver.vendorRequestOut.call_count, 2)

    def test_discovery_failure_is_not_retried(self):
        discovery = Mock(side_effect=OSError("enumeration outcome unknown"))
        with self.assertRaises(OSError):
            self.run_transaction(discovery)
        self.assertEqual(discovery.call_count, 1)
        self.service.driver.vendorRequestOut.assert_not_called()

    def test_multiple_devices_refused(self):
        with self.assertRaises(RuntimeError):
            self.run_transaction(lambda: [self.service, ServiceDevice()])
        self.service.driver.vendorRequestOut.assert_not_called()

    def test_known_empty_discovery_can_poll(self):
        discovery = Mock(side_effect=[[], [self.service]])
        self.assertEqual(self.run_transaction(discovery), "verified")
        self.assertEqual(discovery.call_count, 2)

    def test_discovery_timeout_does_not_reenter(self):
        with self.assertRaises(TimeoutError):
            self.run_transaction(lambda: [], clock=Mock(side_effect=[1, 12]))
        self.assertEqual(self.normal.driver.vendorRequestOut.call_count, 1)

    def test_explicit_normal_start_pipe_proceeds_without_repeating_start(self):
        from usb.core import USBError
        self.normal.driver.vendorRequestOut.side_effect = USBError("synthetic STALL", -9, 32)
        events = []
        result = service_transaction(self.normal, lambda: [self.service], self.auth,
                                     self.work, ServiceDevice, clock=lambda: 1,
                                     sleep=lambda _: None, accept_known_start_stall=True,
                                     record_event=events.append)
        self.assertEqual(result, "verified")
        self.assertEqual(self.normal.driver.vendorRequestOut.call_count, 1)
        self.assertEqual(self.auth.call_count, 2)
        self.assertTrue(events[0]["known_pipe_response"])
        self.assertEqual(events[0]["error_chain"][0]["backend_error_code"], -9)

    def test_explicit_service_start_pipe_proceeds_without_replay(self):
        from usb.core import USBError
        self.service.driver.vendorRequestOut.side_effect = [USBError("synthetic STALL", -9, 32), None]
        service_transaction(self.normal, lambda: [self.service], self.auth,
                            self.work, ServiceDevice, clock=lambda: 1, sleep=lambda _: None,
                            accept_known_start_stall=True)
        self.assertEqual(self.service.driver.vendorRequestOut.call_count, 2)  # START then STOP
        self.assertEqual(self.auth.call_count, 2)

    def test_timeout_or_disconnect_never_continues_auth(self):
        from usb.core import USBError
        for code, number in [(-7, 110), (-4, 19), (-9, 110), (None, 32)]:
            with self.subTest(code=code, number=number):
                self.normal.driver.vendorRequestOut.side_effect = USBError("synthetic", code, number)
                self.auth.reset_mock()
                with self.assertRaises(USBError):
                    service_transaction(self.normal, lambda: [self.service], self.auth,
                                        self.work, ServiceDevice, clock=lambda: 1,
                                        sleep=lambda _: None, accept_known_start_stall=True)
                self.auth.assert_not_called()

    def test_known_pipe_can_be_found_in_wrapped_error(self):
        from usb.core import USBError
        try:
            try:
                raise USBError("secret-not-for-logs", -9, 32)
            except USBError:
                raise RuntimeError("wrapper-secret-not-for-logs")
        except RuntimeError as error:
            self.assertTrue(known_start_stall(error))
            diagnostic = usb_error_diagnostic(error)
        self.assertEqual(diagnostic, [{"type": "RuntimeError"},
                                      {"type": "USBError", "errno": 32, "backend_error_code": -9}])
        self.assertNotIn("secret", str(diagnostic))

    def test_plain_pipe_text_is_not_evidence(self):
        self.assertFalse(known_start_stall(OSError("PIPE EPIPE -9")))

    def test_real_SDK_auth_trace_matches_reference_reset_start_auth_order(self):
        from pmca.usb.sony import SonySenserAuthDevice
        from pmca.usb.driver.generic import GenericUsbException
        from usb.core import USBError
        from camera_stream_channel import _DriverProxy

        class AuthDriver:
            def __init__(self, mode, trace):
                self.mode, self.trace = mode, trace
                self.responses = deque(SonySenserAuthDevice.AuthPacket.pack(
                    cmd=(~ret & 0xffff), salt=0,
                    data=(b"\x01" + b"\0" * 511 if ret == 6 else b"\0" * 512))
                    for ret in [8, 4, 8, 4, 8, 4, 6])

            def reset(self):
                self.trace.append((self.mode, "reset"))

            def getId(self):
                return 0x054c, 0x0336 if self.mode == "service" else 0x0da5

            def vendorRequestOut(self, *args):
                self.trace.append((self.mode, "vendor", args))
                if args == START_REQUEST:
                    try:
                        raise USBError("synthetic STALL", -9, 32)
                    except USBError:
                        raise GenericUsbException()

            def write(self, data):
                self.trace.append((self.mode, "write", len(data), hashlib.sha256(data).hexdigest()))

            def read(self, count):
                self.trace.append((self.mode, "read", count))
                return self.responses.popleft()

        reference = []
        for mode in ("normal", "service"):
            auth = SonySenserAuthDevice(AuthDriver(mode, reference))
            auth.start()
            auth.authenticate()
        auth.stop()
        actual = []
        normal = SimpleNamespace(driver=AuthDriver("normal", actual))
        service = ServiceDevice()
        service.driver = AuthDriver("service", actual)
        def prepare(raw):
            return SonySenserAuthDevice(_DriverProxy(raw, 10, lambda: 1)).authenticate
        service_transaction(normal, lambda: [service], None, lambda _: None,
                            ServiceDevice, clock=lambda: 1, sleep=lambda _: None,
                            accept_known_start_stall=True, prepare_auth=prepare)
        self.assertEqual(actual, reference)


if __name__ == "__main__":
    unittest.main()
