"""Mocked session boundaries only: no SDK discovery or USB operations."""
from contextlib import contextmanager, redirect_stdout, redirect_stderr
import hashlib
import io
import sys
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import camera_stream_usb_session as session
from camera_stream_service import START_REQUEST, STOP_REQUEST, service_transaction


class SessionTests(unittest.TestCase):
    def setUp(self):
        self.trace, self.events, self.stages = [], [], []
        self.serial = "synthetic-private-body-identifier"
        self.expected = hashlib.sha256(self.serial.encode()).hexdigest()
        trace = self.trace

        class GenericDriver:
            def __init__(inner, mode):
                inner.mode = mode
                inner.backend = SimpleNamespace(dev=SimpleNamespace(default_timeout=5000,
                                                                    serial_number=self.serial))
                inner.start_error = None
                inner.stop_error = None
                inner.on_start = None

            def getId(inner):
                return (0x054c, 0x0da5 if inner.mode == "normal" else 0x0336)

            def reset(inner):
                trace.append((inner.mode, "reset"))

            def vendorRequestOut(inner, *request):
                trace.append((inner.mode, request))
                if request == START_REQUEST:
                    if inner.on_start:
                        inner.on_start()
                    if inner.start_error:
                        raise inner.start_error
                elif request == STOP_REQUEST and inner.stop_error:
                    raise inner.stop_error

        class NormalDevice:
            def __init__(inner):
                inner.driver = GenericDriver("normal")

        class ServiceDevice:
            def __init__(inner):
                inner.driver = GenericDriver("service")

        self.normal, self.service = NormalDevice(), ServiceDevice()
        self.auth_error = None
        self.model = "ILCE-7M4"

        class ExtCamera:
            def __init__(inner, normal):
                self.assertIs(normal, self.normal)

            def getCameraInfo(inner):
                trace.append(("normal", "camera_info"))
                print(self.serial)
                return SimpleNamespace(modelName=self.model)

        class AuthDevice:
            def __init__(inner, driver):
                inner.driver = driver
                driver.reset()

            def authenticate(inner):
                trace.append((inner.driver.original.mode, "authenticate"))
                print("synthetic-auth-secret", file=sys.stderr)
                if self.auth_error:
                    raise self.auth_error

        @contextmanager
        def import_driver(name):
            self.assertEqual(name, "libusb")
            trace.append(("driver", "open"))
            yield object()

        self.discovery = Mock(side_effect=lambda *_args, **_kwargs:
                              [self.normal] if not any(x == ("normal", "authenticate") for x in trace)
                              else [self.service])
        command = ModuleType("pmca.commands.usb")
        command.importDriver, command.listDevices = import_driver, self.discovery
        sony = ModuleType("pmca.usb.sony")
        sony.SonyMscExtCmdDevice, sony.SonySenserDevice = NormalDevice, ServiceDevice
        sony.SonyExtCmdCamera, sony.SonySenserAuthDevice = ExtCamera, AuthDevice
        generic = ModuleType("pmca.usb.driver.generic")
        generic.GenericUsbDriver = GenericDriver
        self.sdk = {"pmca.commands.usb": command, "pmca.usb.sony": sony,
                    "pmca.usb.driver.generic": generic}
        self.hasp = Mock(side_effect=lambda device: trace.append(("service", "read_hasp")))
        self.work = Mock(side_effect=lambda device: trace.append(("service", "work")) or "verified")

        def transaction(*args, **kwargs):
            self.assertIs(kwargs["accept_known_start_stall"], True)
            self.assertIs(kwargs["accept_known_stop_stall"], True)
            return service_transaction(*args, **kwargs, sleep=lambda _: None, clock=lambda: 1)

        self.transaction = Mock(side_effect=transaction)

    def run_session(self, expected=None):
        with patch.dict(sys.modules, self.sdk), \
                patch.object(session, "read_hasp_once", self.hasp), \
                patch.object(session, "service_transaction", self.transaction):
            return session.run_normal_session(expected or self.expected, self.work,
                                              record_event=self.events.append,
                                              set_stage=self.stages.append)

    def requests(self, mode):
        return [value for owner, value in self.trace if owner == mode and isinstance(value, tuple)]

    def test_success_order_and_safe_events(self):
        captured_out, captured_err = io.StringIO(), io.StringIO()
        with redirect_stdout(captured_out), redirect_stderr(captured_err):
            self.assertEqual(self.run_session(), "verified")
        self.assertEqual(captured_out.getvalue(), "")
        self.assertEqual(captured_err.getvalue(), "")
        for mode in ("normal", "service"):
            ordered = [value for owner, value in self.trace if owner == mode]
            self.assertLess(ordered.index("reset"), ordered.index(START_REQUEST))
            self.assertLess(ordered.index(START_REQUEST), ordered.index("authenticate"))
        self.assertEqual(self.requests("normal"), [START_REQUEST])
        self.assertEqual(self.requests("service"), [START_REQUEST, STOP_REQUEST])
        self.assertEqual(self.trace[-3:], [("service", "read_hasp"), ("service", "work"),
                                         ("service", STOP_REQUEST)])
        self.assertEqual(self.stages[-1], "VERIFIED_BEFORE_SERVICE_EXIT")
        self.assertEqual(self.events[0], {"model": "ILCE-7M4", "body_matched": True})
        self.assertNotIn(self.serial, repr(self.events))
        self.assertNotIn("auth-secret", repr(self.events))
        self.work.assert_called_once_with(self.service)
        self.hasp.assert_called_once_with(self.service)

    def test_explicit_stop_pipe_is_known_reply_without_health_claim(self):
        from usb.core import USBError
        self.service.driver.stop_error = USBError("synthetic STALL", -9, 32)
        self.assertEqual(self.run_session(), "verified")
        self.assertEqual(self.requests("service"), [START_REQUEST, STOP_REQUEST])
        self.assertFalse(any("HEALTHY" in stage or "CAMERA_NORMAL" in stage for stage in self.stages))

    def test_unknown_stop_propagates_without_replay(self):
        self.service.driver.stop_error = OSError("unknown STOP outcome")
        with self.assertRaises(OSError):
            self.run_session()
        self.assertEqual(self.requests("service"), [START_REQUEST, STOP_REQUEST])
        self.work.assert_called_once()

    def test_body_mismatch_stops_before_auth(self):
        with self.assertRaisesRegex(RuntimeError, "body mismatch"):
            self.run_session("0" * 64)
        self.assertEqual(self.requests("normal"), [])
        self.assertEqual(self.requests("service"), [])
        self.assertFalse(any(value == "reset" for _, value in self.trace))
        self.work.assert_not_called()
        self.assertEqual(self.events, [])

    def test_missing_timeout_stops_before_camera_info(self):
        del self.normal.driver.backend.dev.default_timeout
        with self.assertRaisesRegex(RuntimeError, "Finite libusb"):
            self.run_session()
        self.assertNotIn(("normal", "camera_info"), self.trace)
        self.transaction.assert_not_called()

    def test_unbounded_timeout_stops_before_camera_info(self):
        for value in (None, 0, -1, 5001, float("inf"), float("nan"), True):
            with self.subTest(timeout=value):
                self.normal.driver.backend.dev.default_timeout = value
                with self.assertRaisesRegex(RuntimeError, "Finite libusb"):
                    self.run_session()
        self.assertNotIn(("normal", "camera_info"), self.trace)
        self.transaction.assert_not_called()

    def test_service_timeout_checked_before_auth_constructor(self):
        self.service.driver.backend.dev.default_timeout = 0
        with self.assertRaisesRegex(RuntimeError, "Finite authentication"):
            self.run_session()
        self.assertEqual(self.requests("service"), [])
        self.assertNotIn(("service", "reset"), self.trace)
        self.work.assert_not_called()

    def test_timeout_rechecked_immediately_before_authenticate(self):
        self.normal.driver.on_start = lambda: setattr(self.normal.driver.backend.dev, "default_timeout", 0)
        with self.assertRaisesRegex(RuntimeError, "Finite authentication"):
            self.run_session()
        self.assertEqual(self.requests("normal"), [START_REQUEST])
        self.assertNotIn(("normal", "authenticate"), self.trace)
        self.assertEqual(self.requests("service"), [])

    def test_callback_unknown_never_sends_stop(self):
        self.work.side_effect = OSError("unknown callback outcome")
        with self.assertRaises(OSError):
            self.run_session()
        self.assertEqual(self.requests("service"), [START_REQUEST])
        self.assertNotIn("VERIFIED_BEFORE_SERVICE_EXIT", self.stages)

    def test_hasp_failure_never_runs_work_or_sends_stop(self):
        self.hasp.side_effect = OSError("unknown initialization outcome")
        with self.assertRaises(OSError):
            self.run_session()
        self.assertEqual(self.requests("service"), [START_REQUEST])
        self.work.assert_not_called()

    def test_auth_failure_never_enters_service(self):
        self.auth_error = OSError("unknown authentication outcome")
        with self.assertRaises(OSError):
            self.run_session()
        self.assertEqual(self.requests("normal"), [START_REQUEST])
        self.assertEqual(self.requests("service"), [])
        self.work.assert_not_called()

    def test_unknown_start_never_authenticates_or_sends_more_requests(self):
        self.normal.driver.start_error = OSError("unknown START outcome")
        with self.assertRaises(OSError):
            self.run_session()
        self.assertEqual(self.requests("normal"), [START_REQUEST])
        self.assertNotIn(("normal", "authenticate"), self.trace)
        self.assertEqual(self.requests("service"), [])

    def test_multiple_normal_devices_refused(self):
        self.discovery.side_effect = None
        self.discovery.return_value = [self.normal, self.normal]
        with self.assertRaisesRegex(RuntimeError, "Exactly one"):
            self.run_session()
        self.transaction.assert_not_called()

    def test_wrong_model_refused_before_auth(self):
        self.model = "OTHER"
        with self.assertRaisesRegex(RuntimeError, "Model changed"):
            self.run_session()
        self.transaction.assert_not_called()


if __name__ == "__main__":
    unittest.main()
