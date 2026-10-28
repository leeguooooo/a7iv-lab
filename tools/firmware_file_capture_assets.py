"""Pure local firmware asset checks. No simulator, SDK or device imports."""
import json
from pathlib import Path
from camera_inventory import require, sha
from camera_firmware_capture import profile
from tools.build_firmware_file_capture_offline import derived_source, target_header

ROOT = Path(__file__).resolve().parents[1]

EARLY_CASES = ('not_root', 'bad_start', 'wrong_start_nonce', 'not_regular', 'wrong_size',
               'read_error', 'low_tmpfs', 'reopened_identity')
TINY_CASES = ('success', 'short_reads', 'changed_second_read', 'changed_identity',
              'bad_ack', 'no_ack', 'wrong_ack_nonce', 'wrong_ack_hash', 'wrong_ack_magic',
              'short_ack', 'long_ack', 'close_error', 'existing_data', 'existing_temp',
              'existing_record', 'existing_done', 'rename_unsupported') + EARLY_CASES

BLOCK_EARLY_CASES = ('not_root', 'bad_sysfs', 'bad_sysfs_size', 'bad_start', 'wrong_start_nonce',
                     'not_block', 'wrong_device', 'wrong_size', 'read_error', 'low_tmpfs')
BLOCK_TINY_CASES = tuple(c for c in TINY_CASES if c not in EARLY_CASES and c != 'changed_identity') + BLOCK_EARLY_CASES

def cases_for(meta):
    p = profile(meta['profile'])
    if p.source_kind == 'BLOCK':
        return BLOCK_TINY_CASES if meta['test_image'] else BLOCK_EARLY_CASES
    return TINY_CASES if meta['test_image'] else EARLY_CASES

def checked_manifest(job):
    job = Path(job).resolve()
    meta = json.loads((job / 'job.json').read_text())
    require(meta['schema'] == 'camera-firmware-file-offline-worker/1', 'Wrong schema')
    p = profile(meta['profile'])
    require(type(meta['test_image']) is bool, 'Missing test scope')
    require(meta['target'] == [p.name, p.minor, p.tiny_size if meta['test_image'] else p.size], 'Wrong geometry')
    require(meta.get('source_kind') == p.source_kind and meta.get('targetpath') == p.path
            and meta.get('expected_sha256') == p.sha256, 'Source kind/path/hash changed')
    require(meta['chunk_bytes'] == (4096 if meta['test_image'] else 8388608), 'Wrong chunk size')
    nonce = bytes.fromhex(meta['nonce'])
    require(len(nonce) == 16 and meta['job_dir'] == '/tmp_wbshd/m4stream_' + nonce.hex(), 'Wrong nonce')
    require((job / 'firmware_file_capture.c').read_text() == derived_source(p.name), 'Derived source changed')
    require((job / 'target.h').read_text() == target_header(p), 'Target changed')
    require(sha(job / 'worker.debug.elf') == meta['worker_sha256'], 'Worker changed')
    for name, digest in meta['sources'].items():
        path = (ROOT / name).resolve()
        require(path.is_relative_to(ROOT) and sha(path) == digest, 'Source changed')
    expected = '#define JOB_DIR "' + meta['job_dir'] + '"\n'
    expected += 'static const unsigned char job_nonce[]={' + ','.join(map(str, nonce)) + '};\n'
    require((job / 'job.h').read_text() == expected, 'Nonce header changed')
    return meta


BOOTSTRAP_SHA = "4e4dcb37eceab654a25b4a7f0d16626d1764f2a9708a48b3275da10c173b19a1"
LINUX_HELPERS_SHA = "827bfa50c9d5e2a1ee8eacc032303844cd3c0a8a9b4f5ea1bfa640a987eedd88"
COMPILER_SHA = "c65cd34917923f575448cc0603dd7c2326da0af0e5c323043d090662dcdf351c"


def checked_job(directory):
    directory = Path(directory).resolve()
    meta = checked_manifest(directory)
    report = json.loads((directory / "emulation.json").read_text())
    require(report.get("all_passed") is True and report.get("hardware_acceptance") is False
            and report.get("full_size_success_emulated") is False, "Wrong emulation evidence scope")
    require(report.get("worker_sha256") == meta["worker_sha256"]
            and report.get("job_manifest_sha256") == sha(directory / "job.json"),
            "Worker/manifest emulation binding changed")
    require(report.get("emulator_sha256") == sha(ROOT / "tools/emulate_firmware_file_capture_offline.py"),
            "Worker emulator changed since validation")
    require(report.get("target") == meta["target"]
            and report.get("chunk_bytes") == meta["chunk_bytes"]
            and report.get("sources") == meta["sources"]
            and report.get("test_image") is meta["test_image"], "Emulation metadata binding mismatch")
    tests = report.get("tests")
    expected = cases_for(meta)
    require(isinstance(tests, list) and len(tests) == len(expected)
            and {t.get("scenario") for t in tests} == set(expected)
            and all(t.get("passed") is True for t in tests), "Incomplete/failed worker tests")
    if not meta["test_image"]:
        require(all(t.get("source_bytes_read") == 0 for t in tests),
                "Production evidence must only cover zero-byte refusals")
    else:
        for test in tests:
            if test["scenario"] in ("success", "short_reads", "changed_second_read"):
                require(test["source_bytes_read"] == 2 * meta["target"][2]
                        and test["published_chunks"] ==
                        (meta["target"][2] + meta["chunk_bytes"] - 1) // meta["chunk_bytes"],
                        "Tiny evidence did not cover complete two-pass geometry")
    return meta, report

