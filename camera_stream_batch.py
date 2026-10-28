"""Prepare/inspect locally, or explicitly execute the planned backup batch.

The one-pilot authorization is consumed. RUN requires a separate user-approved
planned-program scope and a fresh healthy normal-MSC connection. No firmware write.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil

from camera_inventory import ROOT
from camera_stream_profiles import PROFILES
from camera_stream_remaining_plan import BATCH, all_candidates, sha, require, read
from camera_stream_remaining import RemainingChannel, execute_remaining_authenticated
from camera_stream_execution import durable_new
from camera_stream_pilot import restore_task_owner
from camera_stream_service import usb_error_diagnostic
from camera_stream_usb_session import run_normal_session

HOST_REPORT = ROOT / "output/camera-stream-host-tests.json"
RECOVERY = ROOT / "local/recovery/remaining-backup-batch-02"


def current_host_evidence():
    report = read(HOST_REPORT)
    require(report["all_passed"] is True and
            all(sha(ROOT / name) == digest for name, digest in report["sources"].items()),
            "Host tests stale")
    require(all(p.name in report["sources"] for p in ROOT.glob("camera_stream*.py")),
            "Host evidence missing stream source")
    return report


def seal(batch=BATCH):
    candidates, host = all_candidates(batch), current_host_evidence()
    value = {"schema": "camera-fixed-remaining-batch/2",
             "profiles": [list(p.target) for p in PROFILES],
             "total_source_bytes": sum(p.size for p in PROFILES), "source_passes": 2,
             "modules": [{"profile": m["profile"], "bytes": len(b), "sha256": m["module"]["sha256"],
                          "manifest_sha256": sha(Path(batch) / m["profile"] / "bootstrap/bootstrap.json")}
                         for m, b in candidates],
             "host_report_sha256": sha(HOST_REPORT), "host_sources": host["sources"],
             "reference_body_record_sha256": sha(ROOT / "output/backup-01/execution/run.json"),
             "automatic_retry": False, "hardware_executed": False,
             "whole_emmc_backup": False, "physical_NOR_backup": False, "restore_verified": False}
    for name, digest in host["sources"].items():
        destination = Path(batch) / "host-sources" / name
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not destination.exists():
            with destination.open("xb") as f:
                os.chmod(destination, 0o600)
                f.write((ROOT / name).read_bytes())
                f.flush()
                os.fsync(f.fileno())
        require(sha(destination) == digest, "Source snapshot changed")
    durable_new(Path(batch) / "batch.json", value)
    return value


def preflight(batch=BATCH):
    batch = Path(batch).resolve()
    value = read(batch / "batch.json")
    require(value["schema"] == "camera-fixed-remaining-batch/2"
            and value["profiles"] == [list(p.target) for p in PROFILES]
            and value["source_passes"] == 2 and value["automatic_retry"] is False,
            "Batch scope changed")
    host, candidates = current_host_evidence(), all_candidates(batch)
    require(value["host_report_sha256"] == sha(HOST_REPORT) and value["host_sources"] == host["sources"],
            "Sealed host evidence changed")
    expected = [{"profile": m["profile"], "bytes": len(b), "sha256": m["module"]["sha256"],
                 "manifest_sha256": sha(batch / m["profile"] / "bootstrap/bootstrap.json")}
                for m, b in candidates]
    require(value["modules"] == expected and value["total_source_bytes"] == sum(p.size for p in PROFILES),
            "Sealed modules/geometry changed")
    reference = ROOT / "output/backup-01/execution/run.json"
    require(sha(reference) == value["reference_body_record_sha256"], "Reference body changed")
    body = read(reference)["body"]["usb_serial_sha256"]
    require(shutil.disk_usage(ROOT / "output").free >= 2 * value["total_source_bytes"] + 67108864,
            "Insufficient host space for captures and recovery copies")
    return value, candidates, body


def save_recovery(source, destination, expected):
    source, destination = Path(source), Path(destination)
    require(sha(source) == expected, "Verified capture changed")
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if destination.exists():
        require(sha(destination) == expected and destination.stat().st_size == source.stat().st_size,
                "Recovery copy belongs to a different capture")
        return destination
    temporary = destination.with_suffix(".partial")
    with source.open("rb") as src, temporary.open("xb") as dst:
        os.chmod(temporary, 0o600)
        shutil.copyfileobj(src, dst, 65536)
        dst.flush()
        os.fsync(dst.fileno())
    require(sha(temporary) == expected and temporary.stat().st_size == source.stat().st_size,
            "Recovery copy readback mismatch")
    os.link(temporary, destination)  # No overwrite, publish only after validation.
    fd = os.open(destination.parent, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    temporary.unlink()
    return destination


def run_authorized(batch=BATCH):
    value, candidates, body = preflight(batch)
    batch = Path(batch).resolve()
    durable_new(batch / "run-attempt.json", {"batch_sha256": sha(batch / "batch.json"), "automatic_retry": False})
    restore_task_owner(batch / "run-attempt.json")
    evidence = batch / "execution"
    evidence.mkdir(mode=0o700)
    report = {"stage": "RESERVED_BEFORE_USB", "verified": [], "program_upload_limit": len(PROFILES),
              "source_passes": 2, "direct_block_node_writes": False, "kernel_code": False,
              "DMA": False, "NOR": False, "settings_or_firmware_writes": False,
              "whole_emmc_backup": False, "physical_NOR_backup": False, "restore_verified": False}
    events = []
    def event(data):
        durable_new(evidence / ("protocol-%03d.json" % len(events)), data)
        events.append(data)
    def stage(text):
        report["stage"] = text
    def work(device):
        for selected, (meta, module) in zip(PROFILES, candidates):
            stage("READING_" + selected.name)
            folder = evidence / selected.name
            folder.mkdir(mode=0o700)
            channel = RemainingChannel(device, bytes.fromhex(meta["nonce"]), selected.name)
            channel.source_is_hardware = True
            captured = execute_remaining_authenticated(channel, module, meta["module"]["sha256"], folder)
            digest = read(folder / "capture/status.json")["sha256"]
            recovery = save_recovery(captured, RECOVERY / (selected.name + ".bin"), digest)
            report["verified"].append({"partition": selected.name, "bytes": selected.size,
                                       "sha256": digest, "capture": str(captured), "recovery": str(recovery)})
            durable_new(folder / "recovery-verified.json", report["verified"][-1])
        return report["verified"]
    try:
        run_normal_session(body, work, record_event=event, set_stage=stage)
        require([(p["partition"], p["bytes"]) for p in report["verified"]]
                == [(p.name, p.size) for p in PROFILES], "Not all planned full captures were verified")
        report["stage"] = "ALL_PLANNED_BACKUPS_VERIFIED_EXIT_RESPONSE_RETURNED"
        report["camera_health_after_exit"] = "USER_CONFIRMATION_REQUIRED"
    except BaseException as error:
        report["error_type"] = type(error).__name__
        report["usb_error_chain_numeric_only"] = usb_error_diagnostic(error)
        report["no_further_application_USB_requests"] = True
        raise
    finally:
        try:
            durable_new(evidence / "run.json", report)
        finally:
            restore_task_owner(evidence, recursive=True)
            if RECOVERY.exists():
                restore_task_owner(RECOVERY, recursive=True)
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=["seal", "inspect", "run"])
    p.add_argument("--allow-planned-backup-batch", action="store_true")
    a = p.parse_args()
    try:
        if a.action == "seal":
            result = seal()
        elif a.action == "inspect":
            result = preflight()[0]
        else:
            require(a.allow_planned_backup_batch, "Separate planned-batch user authorization required")
            result = run_authorized()
        print(json.dumps({"action": a.action, "state": "PASS",
                          "profiles": [p.name for p in PROFILES],
                          "source_bytes": sum(p.size for p in PROFILES),
                          "verified_count": len(result.get("verified", [])),
                          "device_operations": "only if action=run" if a.action == "run" else 0}))
    except BaseException as error:
        print(json.dumps({"state": "STOPPED", "error_type": type(error).__name__, "automatic_retry": False}))
        raise SystemExit(1)


if __name__ == "__main__":
    main()
