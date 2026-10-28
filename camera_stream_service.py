"""Single service transaction with no cleanup USB requests after an exception.

All discovery/auth/work dependencies are injected. This module has no USB imports
or entry point. Only a fully successful work callback permits one exit request.
"""
import time
import errno

START_REQUEST = (1, 0x37ff, 0xd7aa)
STOP_REQUEST = (1, 0xc800, 0x2855)


def usb_error_diagnostic(error):
    """Numbers and static type names only; no messages/auth/serial values."""
    chain, seen = [], set()
    while error is not None and id(error) not in seen and len(chain) < 8:
        seen.add(id(error))
        item = {"type": type(error).__name__[:100]}
        for field in ("errno", "backend_error_code"):
            value = getattr(error, field, None)
            if isinstance(value, int) and not isinstance(value, bool):
                item[field] = value
        operation = getattr(error, "camera_stream_operation", None)
        if operation in ("reset", "read", "read_padding", "write"):
            item["operation"] = operation
            count = getattr(error, "camera_stream_requested_bytes", None)
            if isinstance(count, int) and 0 <= count <= 0x100000 + 12:
                item["requested_bytes"] = count
        chain.append(item)
        error = error.__cause__ if error.__cause__ is not None else error.__context__
    return chain


def known_start_stall(error):
    """Only an actual libusb PIPE response; never infer from an error string.

    The public Sony SDK accepts GenericUsbException from START, then continues
    authentication without repeating START. We narrow that behavior to the
    explicit libusb PIPE (-9) response with matching EPIPE, if supplied.
    """
    from usb.core import USBError
    seen = set()
    while error is not None and id(error) not in seen and len(seen) < 8:
        seen.add(id(error))
        if (isinstance(error, USBError) and error.backend_error_code == -9
                and error.errno in (None, errno.EPIPE)):
            return True
        error = error.__cause__ if error.__cause__ is not None else error.__context__
    return False


def service_transaction(normal, discover, authenticate, work, service_type,
                        clock=time.monotonic, sleep=time.sleep,
                        accept_known_start_stall=False, record_event=None, prepare_auth=None,
                        accept_known_stop_stall=False):
    def start(driver, mode):
        try:
            driver.vendorRequestOut(*START_REQUEST)
        except BaseException as error:
            known = accept_known_start_stall and known_start_stall(error)
            if record_event is not None:
                record_event({"event": "START_RESPONSE", "mode": mode,
                              "known_pipe_response": bool(known),
                              "error_chain": usb_error_diagnostic(error)})
            if not known:
                raise
            # Known response, not a request replay: proceed to one auth exchange.
        else:
            if record_event is not None:
                record_event({"event": "START_RESPONSE", "mode": mode, "success": True})

    # Match Sony's constructor(reset) -> START -> authenticate ordering, keeping
    # the host-interface setup before the protocol transition.
    normal_auth = prepare_auth(normal.driver) if prepare_auth else lambda: authenticate(normal.driver)
    start(normal.driver, "normal")
    normal_auth()
    deadline = clock() + 10
    service = None
    while clock() < deadline:
        sleep(0.5)
        devices = list(discover())
        if len(devices) > 1:
            raise RuntimeError("Multiple Sony devices after mode transition")
        if devices and isinstance(devices[0], service_type):
            service = devices[0]
            break
    if service is None:
        raise TimeoutError("Service enumeration deadline; do not re-enter automatically")
    service_auth = prepare_auth(service.driver) if prepare_auth else lambda: authenticate(service.driver)
    start(service.driver, "service")
    service_auth()
    # Deliberately no finally: if auth/work/transport fails, no further vendor
    # request is safe to infer. The user may need to power-cycle the camera.
    result = work(service)
    try:
        service.driver.vendorRequestOut(*STOP_REQUEST)
    except BaseException as error:
        known = accept_known_stop_stall and known_start_stall(error)
        if record_event is not None:
            record_event({"event": "STOP_RESPONSE", "mode": "service",
                          "known_pipe_response": bool(known),
                          "error_chain": usb_error_diagnostic(error)})
        if not known:
            raise
        # SDK stop() accepts this response. It does not prove the viewfinder or
        # normal USB interface has returned; caller still asks physical health.
    else:
        if record_event is not None:
            record_event({"event": "STOP_RESPONSE", "mode": "service", "success": True})
    return result
