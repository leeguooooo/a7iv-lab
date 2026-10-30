"""Prepare or run one explicitly authorized FL23 pre-install read-only group.

No card activation, RAM patch, firmware start or restoration command exists.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import uuid

from camera_device_lease import CameraDeviceLease
from camera_install_journal import InstallJournal
from camera_operation_guard import DEFAULT_SESSIONS
from camera_install_patch_plan import _local
from camera_install_patch_session import _json, _source_only_runtime
from camera_install_requirements import read_requirements
from camera_install_runtime_metadata import MetadataAssets
from camera_install_runtime_session import (RuntimeAssets, preflight_assets, validate_review,
                                           run_runtime_session, require, REVIEW_SCHEMA)
from camera_install_runtime_plan import seal
from camera_toolchain import PLAIN, PACKAGE_SHA, PLAIN_SHA, original_plan_body


def _sha(path):
    with _local(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def _base_plan(path, digest):
    raw, plan = _json(_local(path))
    require(hashlib.sha256(raw).hexdigest() == digest, 'Original local plan SHA differs')
    body = original_plan_body(plan)
    return plan | dict(reference_body_sha256=body)


def assets_from_reference(reference):
    metadata = reference['metadata']
    assets = MetadataAssets(Path(metadata['job_dir']), *(metadata[key] for key in
        ('manifest_sha256', 'module_sha256', 'native_model_sha256', 'bootstrap_model_sha256')))
    return RuntimeAssets(Path(reference['p1']['directory']), reference['p1']['manifest_sha256'], assets)


def _host_access():
    require(sys.platform != 'darwin' or os.geteuid() == 0,
            'macOS MSC collection requires the reviewed command to run with sudo')


def prepare_read(*, original_plan, original_plan_sha256, p1_directory, metadata_job, output):
    plan = _base_plan(original_plan, original_plan_sha256)
    p1_directory = _local(p1_directory, directory=True)
    job = _local(metadata_job, directory=True)
    assets = RuntimeAssets(p1_directory, _sha(p1_directory / 'post_p1/bootstrap/bootstrap.json'),
        MetadataAssets(job, *(_sha(job / name) for name in
            ('manifest.json', 'libJit.so', 'native-model-report.json', 'bootstrap-model-report.json'))))
    requirements = read_requirements(PLAIN)
    return seal(output, assets=assets, body_sha256=plan['reference_body_sha256'],
        plan_sha256=original_plan_sha256, required_partition_sizes=requirements['required_partition_sizes'])


def run_read(*, original_plan, original_plan_sha256, review_path, review_sha256, evidence,
             read_authorized=False, camera_ready=False):
    require(read_authorized is True and camera_ready is True,
            'Explicit read-only authorization and connected normal MSC camera required')
    _source_only_runtime()
    _host_access()
    plan = _base_plan(original_plan, original_plan_sha256)
    _, review = _json(_local(review_path))
    require(review.get('schema') == REVIEW_SCHEMA, 'Runtime-only review required')
    assets = assets_from_reference(review['asset_reference'])
    prepared = preflight_assets(assets)
    sizes = read_requirements(PLAIN)['required_partition_sizes']
    validate_review(review_path, review_sha256, prepared, plan['reference_body_sha256'], original_plan_sha256, sizes)
    folder = _local(evidence, directory=True, existing=False)
    with CameraDeviceLease('fl23-runtime-preinstall-read') as lease:
        prepared = preflight_assets(assets)
        validate_review(review_path, review_sha256, prepared, plan['reference_body_sha256'], original_plan_sha256, sizes)
        journal = InstallJournal.create(DEFAULT_SESSIONS, 'runtime-' + uuid.uuid4().hex,
            plan_sha256=original_plan_sha256, body_sha256=plan['reference_body_sha256'], model='ILCE-7M4')
        try:
            folder.mkdir(mode=0o700, parents=True)
        except BaseException:
            journal.advance('CANCELLED_BEFORE_DEVICE_WRITE', details=dict(reason='local_evidence_directory_creation_failed'))
            raise
        return run_runtime_session(plan['reference_body_sha256'], folder, plan_sha256=original_plan_sha256,
            review_path=review_path, review_sha256=review_sha256, journal=journal, lease=lease, assets=assets,
            required_partition_sizes=sizes, runtime_read_authorized=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    prepare = commands.add_parser('prepare', help='Seal a read-only review without contacting a camera')
    read = commands.add_parser('read', help='Run one explicitly authorized normal-MSC read-only group')
    for subparser in (prepare, read):
        subparser.add_argument('--original-plan', type=Path, required=True)
        subparser.add_argument('--original-plan-sha256', required=True)
    prepare.add_argument('--p1-directory', type=Path, required=True)
    prepare.add_argument('--metadata-job', type=Path, required=True)
    prepare.add_argument('--output', type=Path, required=True)
    read.add_argument('--review', type=Path, required=True)
    read.add_argument('--review-sha256', required=True)
    read.add_argument('--evidence', type=Path, required=True)
    read.add_argument('--read-authorized', action='store_true')
    read.add_argument('--camera-ready', action='store_true')
    args = parser.parse_args()
    if args.command == 'prepare':
        result = prepare_read(original_plan=args.original_plan, original_plan_sha256=args.original_plan_sha256,
            p1_directory=args.p1_directory, metadata_job=args.metadata_job, output=args.output)
    else:
        observed = run_read(original_plan=args.original_plan, original_plan_sha256=args.original_plan_sha256,
            review_path=args.review, review_sha256=args.review_sha256, evidence=args.evidence,
            read_authorized=args.read_authorized, camera_ready=args.camera_ready)
        result = dict(state=observed['state'], source_is_hardware=observed['source_is_hardware'],
            receipt_path=str(args.evidence.absolute() / 'runtime-session-exit.json'),
            installation_authorized=False, write_admission=False)
    print(json.dumps(result))


if __name__ == '__main__':main()
