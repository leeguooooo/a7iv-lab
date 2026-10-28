"""Inspect offline by default; explicitly run ONE reviewed read-only pilot.

The run action requires fresh user authorization outside this program. It changes
service/temporary file state and uploads a userland module, so normal USB inquiry
authorization alone is insufficient. No kernel/DMA/NOR/firmware write path exists.
"""
import argparse
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import time

from camera_stream_execution import BootstrapChannel, durable_new, execute_authenticated
from camera_stream_service import service_transaction, usb_error_diagnostic
from camera_stream_channel import _DriverProxy
from camera_stream_transport_bounds import BoundedSink
from camera_stream_senser import send_senser_packet

ROOT = Path(__file__).resolve().parent
REVIEWED_MODULE = "c86bbc36a961868546da0e7b134085d6233f43c0b283404a08563036afabe11e"
JOB = ROOT / "output/stream-backup-bootstrap-offline-04"
SOURCE_FILES = ["camera_stream_pilot.py", "camera_stream_execution.py", "camera_stream_service.py",
                "camera_stream_channel.py", "camera_stream_transport_bounds.py",
                "camera_stream_senser.py", "camera_stream_collect.py", "camera_stream_receiver.py"]


def read_hasp_once(device):
    """Preserve the standard SenserPlatformBackend.start() initialization.

    Discard its reply; do not log device security/identity material.
    """
    import struct
    original = device.driver
    try:
        device.driver = _DriverProxy(original, time.monotonic() + 60, time.monotonic)
        with BoundedSink(65536) as sink:
            response, _ = send_senser_packet(device, 0x10, struct.pack("<HHB", 0, 0x001f, 0), sink)
            require(response == 1, "Senser platform initialization rejected")
    finally:
        device.driver = original


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def restore_task_owner(path, recursive=False):
    """Return only this run's new files to the invoking user after sudo."""
    if os.geteuid() != 0 or not os.environ.get("SUDO_UID") or not os.environ.get("SUDO_GID"):
        return
    uid, gid = int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"])
    path = Path(path)
    if recursive:
        for directory, dirs, files in os.walk(path, followlinks=False):
            for name in files + dirs:
                os.lchown(Path(directory) / name, uid, gid)
    os.lchown(path, uid, gid)


def preflight(job=JOB):
    # Import ELF tooling only for local inspection; no pmca/usb driver import.
    from tools.prepare_stream_bootstrap import checked_job
    from camera_inventory import NATIVE, COMMIT, UPSTREAM
    import subprocess
    job = Path(job).resolve()
    meta = json.loads((job / "bootstrap.json").read_text())
    module = (job / "libJit.so").read_bytes()
    require(len(module) == 12752 and hashlib.sha256(module).hexdigest() == REVIEWED_MODULE
            == meta["module"]["sha256"], "Only the reviewed module is admitted")
    require(meta["target"] == ["cnflasha7", 135, 16777216], "Wrong pilot target")
    nonce = bytes.fromhex(meta["nonce"])
    require(len(nonce) == 16 and meta["job_dir"] == "/tmp_wbshd/m4stream_" + nonce.hex(),
            "Job identity mismatch")
    prod_path, tiny_path = [ROOT / meta[k] for k in ("production_worker_job", "tiny_worker_job")]
    prod, _ = checked_job(prod_path)
    tiny, _ = checked_job(tiny_path)
    require(not prod["test_image"] and tiny["test_image"] and prod["sources"] == tiny["sources"],
            "Worker test binding mismatch")
    require(prod["nonce"] == meta["nonce"] and prod["job_dir"] == meta["job_dir"],
            "Production nonce mismatch")
    require(sha(job / "job.h") == meta["job_header_sha256"] == prod["header_sha256"],
            "Bootstrap header changed")
    expected_header = '#define JOB_DIR "' + meta["job_dir"] + '"\n'
    expected_header += 'static const unsigned char job_nonce[]={' + ','.join(map(str, nonce)) + '};\n'
    require((job / "job.h").read_text() == expected_header, "Nonce not bound to compiled job header")
    require(sha(job / "worker.elf") == meta["compact_worker_sha256"], "Compact worker changed")
    require(module.count((job / "worker.elf").read_bytes()) == 1, "Worker embedding changed")
    require(sha(NATIVE / "bootstrap.c") == meta["bootstrap_source_sha256"]
            and sha(NATIVE / "linux_a64.h") == meta["linux_helpers_sha256"], "Bootstrap helper changed")
    require(sha(ROOT / "tools/prepare_stream_bootstrap.py") == meta["builder_sha256"],
            "Bootstrap builder changed")
    emulation = json.loads((job / "emulation.json").read_text())
    require(emulation["all_passed"] and emulation["module_sha256"] == REVIEWED_MODULE
            and emulation["compact_worker_sha256"] == meta["compact_worker_sha256"]
            and all(t["passed"] for t in emulation["tests"]), "Bootstrap validation failed")
    require(sha(ROOT / "tools/emulate_stream_bootstrap.py") == emulation["emulator_sha256"],
            "Bootstrap emulator changed")
    require(subprocess.check_output(["git", "-C", str(UPSTREAM), "rev-parse", "HEAD"],
                                    text=True).strip() == COMMIT, "Helper revision changed")
    require(not subprocess.check_output(["git", "-C", str(UPSTREAM), "status", "--porcelain"]),
            "Helper checkout dirty")
    host = json.loads((ROOT / "output/camera-stream-host-tests.json").read_text())
    require(host["all_passed"] and all(sha(ROOT / p) == h for p, h in host["sources"].items()),
            "Host tests stale")
    require(all(p in host["sources"] for p in SOURCE_FILES), "Execution sources not covered by current host tests")
    expected_body = json.loads((ROOT / "output/backup-01/execution/run.json").read_text())["body"]["usb_serial_sha256"]
    require(len(expected_body) == 64, "Missing reference body identity")
    return meta, module, expected_body


def run_authorized(job=JOB):
    meta, module, expected_body = preflight(job)
    job = Path(job).resolve()
    # Never run a candidate twice, even after a crash or before a failed upload.
    durable_new(job / "run-attempt.json", {"nonce": meta["nonce"], "automatic_retry": False,
                                           "module_sha256": REVIEWED_MODULE, "time": time.time()})
    restore_task_owner(job / "run-attempt.json")
    evidence = job / "execution"
    evidence.mkdir(mode=0o700)
    report = {"partition": "cnflasha7", "source_bytes": 16777216, "module_bytes": len(module),
              "module_sha256": REVIEWED_MODULE, "automatic_retry": False,
              "block_writes": False, "kernel_code_loaded": False, "DMA": False,
              "NOR_access": False, "settings_writes": False, "firmware_writes": False,
              "whole_emmc_backup": False, "physical_NOR_backup": False,
              "restoration_verified": False, "stage": "NORMAL_USB_PREFLIGHT"}
    try:
        sys.path.insert(0, str(ROOT / "Sony-PMCA-RE"))
        # Suppress library diagnostics; neither a raw serial nor auth data is logged.
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            from pmca.commands.usb import importDriver, listDevices
            from pmca.usb.sony import SonyMscExtCmdDevice, SonyExtCmdCamera, SonySenserDevice, SonySenserAuthDevice
            from pmca.usb.driver.generic import GenericUsbDriver
            with importDriver("libusb") as driver:
                devices = list(listDevices(driver, quiet=True))
                require(len(devices) == 1 and isinstance(devices[0], SonyMscExtCmdDevice),
                        "Exactly one normal Sony MSC camera required")
                normal = devices[0]
                require(isinstance(normal.driver, GenericUsbDriver)
                        and normal.driver.getId() == (0x054c, 0x0da5), "Unsupported USB path")
                require(isinstance(normal.driver.backend.dev.default_timeout, (int, float))
                        and 0 < normal.driver.backend.dev.default_timeout <= 5000,
                        "Finite libusb read timeout required")
                require(SonyExtCmdCamera(normal).getCameraInfo().modelName == "ILCE-7M4", "Model changed")
                serial = normal.driver.backend.dev.serial_number
                require(bool(serial) and hashlib.sha256(serial.encode()).hexdigest() == expected_body,
                        "Reference camera body mismatch")
                del serial
                report["body_matched"] = True
                durable_new(evidence / "body-preflight.json", {"model": "ILCE-7M4", "body_matched": True})

                def prepare_auth(raw_driver):
                    report["stage"] = "AUTH_PREPARATION_NO_AUTOMATIC_RETRY"
                    require(isinstance(raw_driver.backend.dev.default_timeout, (int, float))
                            and 0 < raw_driver.backend.dev.default_timeout <= 5000,
                            "Finite authentication libusb timeout required")
                    auth = SonySenserAuthDevice(_DriverProxy(raw_driver, time.monotonic() + 60,
                                                            time.monotonic))
                    def authenticate():
                        report["stage"] = "AUTHENTICATE_NO_AUTOMATIC_RETRY"
                        auth.authenticate()
                    return authenticate

                def work(device):
                    report["stage"] = "USERLAND_PILOT"
                    require(isinstance(device.driver, GenericUsbDriver)
                            and isinstance(device.driver.backend.dev.default_timeout, (int, float))
                            and 0 < device.driver.backend.dev.default_timeout <= 5000,
                            "Finite service libusb read timeout required")
                    read_hasp_once(device)
                    report["platform_start_read_completed"] = True
                    channel = BootstrapChannel(device, bytes.fromhex(meta["nonce"]))
                    channel.source_is_hardware = True
                    backup = execute_authenticated(channel, module, REVIEWED_MODULE, evidence)
                    report["backup"] = str(backup)
                    report["two_source_reads_and_host_readback_verified"] = True
                    report["stage"] = "VERIFIED_BEFORE_SERVICE_EXIT"
                    return backup

                event_index = 0

                def event(value):
                    nonlocal event_index
                    durable_new(evidence / ("protocol-%02d.json" % event_index), value)
                    event_index += 1

                report["stage"] = "SERVICE_ENTRY_ATTEMPT"
                service_transaction(normal, lambda: listDevices(driver, quiet=True),
                                    None, work, SonySenserDevice,
                                    accept_known_start_stall=True, record_event=event,
                                    prepare_auth=prepare_auth)
                report["stage"] = "COMPLETED_SERVICE_EXIT_REQUEST_CONFIRMED"
                # This confirms the exit request, NOT the physical viewfinder/menu.
    except BaseException as error:
        report["error_type"] = type(error).__name__
        report["usb_error_chain_numeric_only"] = usb_error_diagnostic(error)
        report["session_stopped_no_more_application_USB_requests"] = True
        raise
    finally:
        report["module_attempt_reserved"] = (evidence / "module-attempt.json").exists()
        report["scratch_FAT_metadata_may_have_been_touched"] = report["module_attempt_reserved"]
        try:
            durable_new(evidence / "run.json", report)
        finally:
            restore_task_owner(evidence, recursive=True)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["inspect", "run"])
    parser.add_argument("--job", type=Path, default=JOB)
    parser.add_argument("--allow-single-pilot", action="store_true",
                        help="Use only after explicit approval for this reviewed userland pilot")
    args = parser.parse_args()
    try:
        if args.action == "inspect":
            meta, module, _ = preflight(args.job)
            print(json.dumps({"offline_preflight": "PASS", "partition": meta["target"][0],
                              "bytes": meta["target"][2], "module_bytes": len(module),
                              "module_sha256": REVIEWED_MODULE, "USB_calls": 0,
                              "run_requires_fresh_user_authorization": True}))
        else:
            require(args.allow_single_pilot, "Explicit single-pilot authorization flag required")
            result = run_authorized(args.job)
            print(json.dumps({"stage": result["stage"], "partition": "cnflasha7",
                              "source_read_verified": True, "physical_NOR_backup": False}))
    except BaseException as error:
        print(json.dumps({"state": "STOPPED", "error_type": type(error).__name__,
                          "automatic_retry": False}))
        raise SystemExit(1)


if __name__ == "__main__":
    main()
