"""Seal/inspect locally; a separate explicit flag admits one fixed P1 write.

No LUT, sound, normal AP/CP, NOR, settings, or full-firmware installation exists
here. The P1 candidate bypasses updater signature/version checks while retaining
original public-key bytes. This is a persistent receiver modification.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

from camera_stream_execution import durable_new
from camera_stream_pilot import restore_task_owner
from camera_stream_batch import save_recovery
from camera_stream_service import usb_error_diagnostic
from camera_stream_usb_session import run_normal_session
from stock_p1_writer_host import execute_writer_authenticated, GLOBAL_ATTEMPT
from stock_p1_writer_plan import ROOT, JOB, MODULE_SHA, SOURCE_SHA, TARGET_SHA, validate
from stock_p1_readback_plan import require
from stock_p1_readback import GLOBAL_ATTEMPT as READBACK_ATTEMPT

BUNDLE = ROOT / 'output/stock-p1-install-bundle-01'
HOST_REPORT = ROOT / 'output/stock-p1-host-tests-03.json'
BODY_RECORD = ROOT / 'output/backup-01/execution/run.json'
RECOVERY = ROOT / 'local/recovery/stock-p1-install-01/observed-p1.bin'
SDK_COMMIT = 'a82f5baaa8e9c3d9f28f94699e860fb2e48cc8e0'
REF_COMMIT = 'caa29145644e1d7d0a41cef1e42f0c53368bd025'
TEST_MODULES = ('tests.test_stock_p1_install', 'tests.test_stock_p1_writer_host',
                'tests.test_stock_p1_readback', 'tests.test_stock_p1_readback_plan',
                'tests.test_stock_p1_writer_boundary', 'tests.test_stock_p1_write_outcome')


def sha(path):
    with Path(path).open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def runtime_policy():
    # -B alone still permits reading old pyc files. Redirect cache lookup to an
    # absent sealed-bundle path as well, so the checked .py sources are compiled.
    prefix = BUNDLE / 'absent-bytecode-cache'
    require(sys.dont_write_bytecode and sys.flags.ignore_environment == 1
            and sys.flags.no_user_site == 1 and sys.pycache_prefix == str(prefix)
            and not prefix.exists(), 'Use reviewed -B -E -s -X pycache_prefix=<bundle>/absent-bytecode-cache startup')


def git_pins():
    for directory, commit in ((ROOT / 'Sony-PMCA-RE', SDK_COMMIT),
                              (ROOT / 'ref/sony-a7m4-custom-firmware', REF_COMMIT)):
        require(subprocess.check_output(['git', '-C', str(directory), 'rev-parse', 'HEAD'], text=True).strip() == commit,
                'Pinned SDK/reference revision changed')
        require(not subprocess.check_output(['git', '-C', str(directory), 'status', '--porcelain']),
                'Pinned SDK/reference checkout changed')


def host_evidence():
    report = json.loads(HOST_REPORT.read_text())
    require(report['all_passed'] is True and report['hardware_operations'] == 0,
            'Passing offline host evidence required')
    require(set(report['test_modules']) == set(TEST_MODULES) and report['tests'] >= 37,
            'Complete current host test scope required')
    expected = {str(p.relative_to(ROOT)) for pattern in ('stock_p1*.py', 'camera_stream*.py')
                for p in ROOT.glob(pattern)}
    require(expected <= set(report['sources']), 'Host evidence missing executable dependencies')
    for name, digest in report['sources'].items():
        require(sha(ROOT / name) == digest, 'Host evidence stale')
    return report


def seal():
    m, _ = validate()
    git_pins()
    host = host_evidence()
    BUNDLE.mkdir(mode=0o700)
    for name, digest in host['sources'].items():
        destination = BUNDLE / 'host-sources' / name
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with destination.open('xb') as f:
            os.fchmod(f.fileno(), 0o600)
            f.write((ROOT / name).read_bytes());f.flush();os.fsync(f.fileno())
        require(sha(destination) == digest, 'Frozen host snapshot differs')
    plan = {'schema': 'camera-fixed-stock-p1-install/1', 'writer_nonce': m['nonce'],
        'source_sha256': SOURCE_SHA, 'target_sha256': TARGET_SHA,
        'writer_module_sha256': MODULE_SHA, 'target': m['target'],
        'window_count': 550, 'forward_bytes': m['stage_bytes'] // 2,
        'source_passes_after_write': 2, 'independent_host_readback': True,
        'host_report_sha256': sha(HOST_REPORT), 'host_sources': host['sources'],
        'body_record_sha256': sha(BODY_RECORD), 'SDK_commit': SDK_COMMIT, 'reference_commit': REF_COMMIT,
        'requires_separate_explicit_P1_write_approval': True, 'approval_received': False,
        'automatic_retry': False, 'automatic_host_rollback': False,
        'automatic_reboot_on_unknown': False, 'no_service_exit_on_exception': True,
        'stock_public_key_bytes_preserved': True, 'SD_signature_and_version_checks_bypassed': True,
        'physical_restore_tested': False, 'physical_NOR_backup': False,
        'full_DAT_built': False, 'LUT_or_sound_features_installed': False,
        'physical_execution_performed': False}
    durable_new(BUNDLE / 'plan.json', plan)
    return plan


def preflight():
    m, _ = validate()
    git_pins()
    host = host_evidence()
    p = json.loads((BUNDLE / 'plan.json').read_text())
    require(p['schema'] == 'camera-fixed-stock-p1-install/1' and p['writer_nonce'] == m['nonce']
            and p['source_sha256'] == SOURCE_SHA and p['target_sha256'] == TARGET_SHA
            and p['writer_module_sha256'] == MODULE_SHA and p['target'] == m['target']
            and p['window_count'] == 550 and p['forward_bytes'] == 8994820
            and p['automatic_retry'] is False and p['automatic_host_rollback'] is False
            and p['no_service_exit_on_exception'] is True, 'Sealed operation changed')
    require(p['host_report_sha256'] == sha(HOST_REPORT) and p['host_sources'] == host['sources']
            and p['body_record_sha256'] == sha(BODY_RECORD), 'Sealed host/body evidence changed')
    for name, digest in p['host_sources'].items():
        require(sha(BUNDLE / 'host-sources' / name) == digest, 'Frozen host snapshot changed')
    body = json.loads(BODY_RECORD.read_text())['body']['usb_serial_sha256']
    require(isinstance(body, str) and len(body) == 64, 'Saved body fingerprint missing')
    require(shutil.disk_usage(ROOT / 'output').free >= 134217728, 'Need space for readback and recovery copy')
    return p, body


def run_authorized(*, allow_fixed_p1_write=False):
    require(allow_fixed_p1_write is True, 'Separate explicit approval for this fixed P1 write required')
    require(os.geteuid() == 0, 'Reviewed macOS USB path requires sudo')
    runtime_policy()
    p, body = preflight()
    require(not GLOBAL_ATTEMPT.exists(), 'Compiled writer nonce already attempted; do not replay')
    require(not READBACK_ATTEMPT.exists(), 'Readback nonce already attempted; do not enter USB')
    durable_new(BUNDLE / 'entry-attempt.json', {'writer_nonce': p['writer_nonce'],
        'state': 'RESERVED_BEFORE_NORMAL_USB', 'explicit_write_flag': True, 'automatic_retry': False})
    evidence = BUNDLE / 'execution'
    evidence.mkdir(mode=0o700)
    report = {'schema': 'camera-fixed-stock-p1-execution/1', 'events': [], 'stage': 'RESERVED',
              'automatic_retry': False, 'physical_restore_tested': False, 'features_installed': False}
    def event(value):
        report['events'].append(value)
    def stage(value):
        report['stage'] = value
    def work(device):
        body_verified = any(e.get('model') == 'ILCE-7M4' and e.get('body_matched') is True
                            for e in report['events'])
        require(body_verified, 'SDK body-verification event missing before writer callback')
        outcome = execute_writer_authenticated(device, evidence, write_authorized=True,
            same_body_verified=body_verified, source_is_hardware=True)
        report['outcome'] = outcome
        report['observed_state'] = outcome['independent_read_state']
        report['original_recovery_source'] = 'local/recovery/backup-01/cnflasha1.bin'
        report['stage'] = 'WRITER_OUTCOME_RECONCILED_RECOVERY_COPY_PENDING'
        observed = evidence / 'readback/capture/cnflasha1.bin'
        try:
            recovery = save_recovery(observed, RECOVERY, outcome['independent_host_sha256'])
        except BaseException:
            report['stage'] = 'WRITER_OUTCOME_RECONCILED_RECOVERY_COPY_FAILED'
            raise
        report['recovery_copy'] = str(recovery.relative_to(ROOT))
        report['recovery_copy_role'] = 'Observed post-transaction snapshot; not the factory restore source'
        return outcome
    try:
        run_normal_session(body, work, record_event=event, set_stage=stage)
        report['stage'] = 'P1_OUTCOME_RECONCILED_EXIT_RESPONSE_RETURNED'
        report['camera_health_after_exit'] = 'USER_CONFIRMATION_REQUIRED'
    except BaseException as error:
        report['error_type'] = type(error).__name__
        report['usb_error_chain_numeric_only'] = usb_error_diagnostic(error)
        report['no_further_application_USB_requests'] = True
        known = bool(report.get('outcome', {}).get('evidence_supports_session_end'))
        report['native_writer_outcome_known'] = known
        report['do_not_reset_or_reboot_while_writer_outcome_unknown'] = not known
        raise
    finally:
        try:
            durable_new(evidence / 'run.json', report)
        finally:
            restore_task_owner(BUNDLE, recursive=True)
            if GLOBAL_ATTEMPT.exists():
                restore_task_owner(GLOBAL_ATTEMPT)
            if READBACK_ATTEMPT.exists():
                restore_task_owner(READBACK_ATTEMPT)
            if RECOVERY.parent.exists():
                restore_task_owner(RECOVERY.parent, recursive=True)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('seal', 'inspect', 'run'))
    parser.add_argument('--allow-fixed-p1-write', action='store_true')
    args = parser.parse_args()
    try:
        if args.action == 'seal':
            plan = seal()
        elif args.action == 'inspect':
            plan, _ = preflight()
        else:
            result = run_authorized(allow_fixed_p1_write=args.allow_fixed_p1_write)
            print(json.dumps({'state': result['stage'], 'outcome': result['outcome']['state'],
                              'features_installed': False}))
            return
        print(json.dumps({'state': 'OFFLINE_VALIDATED_NOT_EXECUTED', 'writer_nonce': plan['writer_nonce'],
                          'target': plan['target'], 'separate_P1_write_approval_required': True,
                          'device_operations': 0}))
    except BaseException as error:
        # Never print SDK exception strings or a traceback containing identity/auth data.
        print(json.dumps({'state': 'STOPPED', 'error_type': type(error).__name__, 'automatic_retry': False}))
        raise SystemExit(1)


if __name__ == '__main__':
    main()
