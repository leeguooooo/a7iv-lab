from unittest.mock import Mock, patch
from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
import camera_stream_pilot as pilot


class PilotGates(unittest.TestCase):
    def test_run_without_flag_never_calls_hardware(self):
        with patch.object(pilot, "run_authorized") as run, \
                patch("sys.argv", ["pilot", "run"]), patch("builtins.print"):
            with self.assertRaises(SystemExit):
                pilot.main()
        run.assert_not_called()


    def test_preflight_failure_never_reserves_or_imports_USB(self):
        with patch.object(pilot, "preflight", side_effect=RuntimeError("stale sources")), \
                patch.object(pilot, "durable_new") as reserve:
            with self.assertRaises(RuntimeError):
                pilot.run_authorized()
        reserve.assert_not_called()

    def test_inspect_is_local_only(self):
        with patch.object(pilot, "preflight", return_value=({"target": ["cnflasha7", 135, 16777216]}, b"module", "x")), \
                patch.object(pilot, "run_authorized") as run, \
                patch("sys.argv", ["pilot", "inspect"]), patch("builtins.print"):
            pilot.main()
        run.assert_not_called()

    def test_platform_start_read_is_bounded_and_not_logged(self):
        original = Mock()
        device = SimpleNamespace(driver=original)
        calls = []
        def packet(function, data, sink):
            calls.append((function, data))
            sink.write(b"synthetic-sensitive-reply")
            return 1, None
        device.sendSenserPacket = packet
        with patch.object(pilot, "send_senser_packet", side_effect=lambda d, p, data, sink: d.sendSenserPacket(p, data, sink)):
            self.assertIsNone(pilot.read_hasp_once(device))
        self.assertEqual(calls, [(0x10, b"\0\0\x1f\0\0")])
        self.assertIs(device.driver, original)

    def test_platform_start_failure_restores_driver(self):
        original = Mock()
        device = SimpleNamespace(driver=original, sendSenserPacket=Mock(side_effect=OSError("unknown")))
        with patch.object(pilot, "send_senser_packet", side_effect=lambda d, p, data, sink: d.sendSenserPacket(p, data, sink)):
            with self.assertRaises(OSError):
                pilot.read_hasp_once(device)
        self.assertIs(device.driver, original)


class FakeGenericDriver:
    def __init__(self, pid):
        self.pid = pid
        self.backend = SimpleNamespace(dev=SimpleNamespace(serial_number="synthetic-body", default_timeout=5000))
        self.requests = []

    def getId(self):
        return 0x054c, self.pid

    def vendorRequestOut(self, *args):
        self.requests.append(args)


class FakeNormal:
    def __init__(self):
        self.driver = FakeGenericDriver(0x0da5)


class FakeService:
    def __init__(self):
        self.driver = FakeGenericDriver(0x0336)


class EntryWithSyntheticSDK(unittest.TestCase):
    """Every SDK hardware boundary is replaced; no USB enumeration occurs."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.job = Path(self.tmp.name)
        self.normal, self.service = FakeNormal(), FakeService()
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        # Importing these modules is local Python initialization only. Replace
        # their discovery/context classes before run_authorized can use them.
        import pmca.commands.usb as usb_commands
        import pmca.usb.sony as sony
        import pmca.usb.driver.generic as generic
        body = hashlib.sha256(b"synthetic-body").hexdigest()
        self.stack.enter_context(patch.object(pilot, "preflight", return_value=(
            {"nonce": bytes(range(16)).hex()}, b"synthetic module", body)))
        self.context = Mock()
        self.context.__enter__ = Mock(return_value=object())
        self.context.__exit__ = Mock(return_value=False)
        self.stack.enter_context(patch.object(usb_commands, "importDriver", return_value=self.context))
        self.discovery = self.stack.enter_context(patch.object(usb_commands, "listDevices",
            side_effect=[[self.normal], [self.service]]))
        self.stack.enter_context(patch.object(sony, "SonyMscExtCmdDevice", FakeNormal))
        self.stack.enter_context(patch.object(sony, "SonySenserDevice", FakeService))
        self.stack.enter_context(patch.object(generic, "GenericUsbDriver", FakeGenericDriver))
        model = Mock()
        model.getCameraInfo.return_value.modelName = "ILCE-7M4"
        self.stack.enter_context(patch.object(sony, "SonyExtCmdCamera", return_value=model))
        self.auth = self.stack.enter_context(patch.object(sony, "SonySenserAuthDevice"))
        self.execution = self.stack.enter_context(patch.object(pilot, "execute_authenticated",
                                                              return_value=self.job / "synthetic.bin"))
        self.hasp = self.stack.enter_context(patch.object(pilot, "read_hasp_once"))
        self.stack.enter_context(patch("camera_stream_service.time.sleep", return_value=None))

    def test_successful_entry_report_and_single_attempt(self):
        result = pilot.run_authorized(self.job)
        self.assertEqual(result["stage"], "COMPLETED_SERVICE_EXIT_REQUEST_CONFIRMED")
        self.assertTrue(result["body_matched"])
        self.assertEqual(self.auth.return_value.authenticate.call_count, 2)
        self.assertEqual(len(self.service.driver.requests), 2)
        self.assertTrue((self.job / "run-attempt.json").exists())
        count = self.discovery.call_count
        with self.assertRaises(FileExistsError):
            pilot.run_authorized(self.job)
        self.assertEqual(self.discovery.call_count, count)

    def test_wrong_body_never_enters_service(self):
        self.normal.driver.backend.dev.serial_number = "different-synthetic-body"
        with self.assertRaises(RuntimeError):
            pilot.run_authorized(self.job)
        self.assertEqual(self.normal.driver.requests, [])
        self.execution.assert_not_called()
        report = json.loads((self.job / "execution/run.json").read_text())
        self.assertEqual(report["stage"], "NORMAL_USB_PREFLIGHT")
        self.assertFalse(report["module_attempt_reserved"])

    def test_callback_unknown_never_sends_stop(self):
        self.execution.side_effect = OSError("synthetic unknown transport")
        with self.assertRaises(OSError):
            pilot.run_authorized(self.job)
        self.assertEqual(len(self.service.driver.requests), 1)
        report = json.loads((self.job / "execution/run.json").read_text())
        self.assertEqual(report["error_type"], "OSError")
        self.assertTrue(report["session_stopped_no_more_application_USB_requests"])

    def test_unbounded_driver_timeout_refused_before_service(self):
        self.normal.driver.backend.dev.default_timeout = 0
        with self.assertRaises(RuntimeError):
            pilot.run_authorized(self.job)
        self.assertEqual(self.normal.driver.requests, [])

    def test_unbounded_service_timeout_refused_before_module(self):
        self.service.driver.backend.dev.default_timeout = None
        with self.assertRaises(RuntimeError):
            pilot.run_authorized(self.job)
        self.execution.assert_not_called()
        self.assertEqual(len(self.service.driver.requests), 0)  # Reject during preparation, before START.



if __name__ == "__main__":
    unittest.main()
