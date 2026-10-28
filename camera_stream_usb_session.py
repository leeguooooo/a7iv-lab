"""A bounded normal-MSC/auth/service session; importing this module touches no USB.

The caller reserves its execution attempt before calling run_normal_session().
A recognized service-exit reply does not establish physical camera health.
"""
import contextlib
import hashlib
import io
from pathlib import Path
import struct
import sys
import time

from camera_stream_channel import _DriverProxy
from camera_stream_senser import send_senser_packet
from camera_stream_service import service_transaction
from camera_stream_transport_bounds import BoundedSink

ROOT = Path(__file__).resolve().parent


def _require(condition, message):
    if not condition:
        raise RuntimeError(message)


def _finite_timeout(driver):
    try:
        timeout = driver.backend.dev.default_timeout
    except AttributeError:
        return False
    return type(timeout) in (int, float) and 0 < timeout <= 5000


def read_hasp_once(device):
    """Match the proven platform initialization, discarding security material."""
    original = device.driver
    try:
        device.driver = _DriverProxy(original, time.monotonic() + 60, time.monotonic)
        with BoundedSink(65536) as sink:
            response, _ = send_senser_packet(device, 0x10, struct.pack("<HHB", 0, 0x001f, 0), sink)
            _require(response == 1, "Senser platform initialization rejected")
    finally:
        device.driver = original


def run_normal_session(expected_body_sha256, work, *, record_event, set_stage):
    """Enter one service session, run work once, then request exit on success only."""
    _require(isinstance(expected_body_sha256, str) and len(expected_body_sha256) == 64
             and all(c in "0123456789abcdef" for c in expected_body_sha256),
             "Expected reference body SHA-256 required")
    set_stage("NORMAL_USB_PREFLIGHT")
    sys.path.insert(0, str(ROOT / "Sony-PMCA-RE"))
    # SDK diagnostics can contain authentication/identity material.
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        from pmca.commands.usb import importDriver, listDevices
        from pmca.usb.sony import SonyMscExtCmdDevice, SonyExtCmdCamera, SonySenserDevice, SonySenserAuthDevice
        from pmca.usb.driver.generic import GenericUsbDriver

        with importDriver("libusb") as driver:
            devices = list(listDevices(driver, quiet=True))
            _require(len(devices) == 1 and isinstance(devices[0], SonyMscExtCmdDevice),
                     "Exactly one normal Sony MSC camera required")
            normal = devices[0]
            _require(isinstance(normal.driver, GenericUsbDriver)
                     and normal.driver.getId() == (0x054c, 0x0da5), "Unsupported USB path")
            _require(_finite_timeout(normal.driver), "Finite libusb read timeout required")
            _require(SonyExtCmdCamera(normal).getCameraInfo().modelName == "ILCE-7M4", "Model changed")
            serial = normal.driver.backend.dev.serial_number
            _require(bool(serial) and hashlib.sha256(serial.encode()).hexdigest() == expected_body_sha256,
                     "Reference camera body mismatch")
            del serial
            record_event({"model": "ILCE-7M4", "body_matched": True})

            def prepare_auth(raw_driver):
                set_stage("AUTH_PREPARATION_NO_AUTOMATIC_RETRY")
                _require(_finite_timeout(raw_driver), "Finite authentication libusb timeout required")
                auth = SonySenserAuthDevice(_DriverProxy(raw_driver, time.monotonic() + 60,
                                                        time.monotonic))

                def authenticate():
                    set_stage("AUTHENTICATE_NO_AUTOMATIC_RETRY")
                    _require(_finite_timeout(raw_driver), "Finite authentication libusb timeout required")
                    auth.authenticate()

                return authenticate

            def service_work(device):
                set_stage("USERLAND_WORK")
                _require(isinstance(device.driver, GenericUsbDriver) and _finite_timeout(device.driver),
                         "Finite service libusb read timeout required")
                read_hasp_once(device)
                result = work(device)
                set_stage("VERIFIED_BEFORE_SERVICE_EXIT")
                return result

            set_stage("SERVICE_ENTRY_ATTEMPT")
            return service_transaction(normal, lambda: listDevices(driver, quiet=True),
                                       None, service_work, SonySenserDevice,
                                       accept_known_start_stall=True,
                                       accept_known_stop_stall=True,
                                       record_event=record_event, prepare_auth=prepare_auth)
