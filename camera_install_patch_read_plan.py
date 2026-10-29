"""Seal a current-read-only review and source snapshots; no device entry CLI."""
import argparse
import hashlib
import json
import os
from pathlib import Path

from camera_install_patch_plan import _local, _write, _sync
from camera_install_patch_read_execution import InstallPatchReadAssets, preflight_assets
from camera_install_patch_read_session import (REVIEW_SCHEMA, SCOPE, FALSE_CLAIMS, SOURCE_ONLY_RUNTIME,
    review_source_paths, validate_review)


def _sha(path):
    with Path(path).open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def assets_from_directory(directory):
    job = _local(directory, directory=True)
    m = json.loads((job / 'manifest.json').read_text())
    return InstallPatchReadAssets(job, *[_sha(_local(job / name)) for name in
        ('manifest.json', 'libJit.so', 'native-model-report.json', 'bootstrap-model-report.json')], m['target_spec_sha256'])


def seal(output, *, assets, pending_reference, expected_body_sha256, plan_sha256):
    out = _local(output, directory=True, existing=False)
    prepared = preflight_assets(assets, pending_reference=pending_reference,
        expected_body_sha256=expected_body_sha256, plan_sha256=plan_sha256)
    from camera_install_patch_read_session import ROOT
    sources = {name: _sha(_local_source(ROOT / name)) for name in review_source_paths(prepared)}
    out.mkdir(mode=0o700, parents=True)
    snapshots = out / 'sources';snapshots.mkdir(mode=0o700)
    for name, digest in sources.items():
        raw = _local_source(ROOT / name).read_bytes()
        if hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError('Current-read source changed while sealing')
        path = snapshots / name;path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        _write(path, raw)
    review = dict(schema=REVIEW_SCHEMA, scope=SCOPE, model='ILCE-7M4', body_sha256=expected_body_sha256,
        original_plan_sha256=plan_sha256, pending_reference=dict(pending_reference), asset_reference=prepared.reference,
        target_spec_sha256=assets.target_spec_sha256, sources=sources, source_snapshot_directory=str(snapshots),
        source_only_runtime=dict(SOURCE_ONLY_RUNTIME), execution_approval_received=False, hardware_operations=0,
        **dict.fromkeys(FALSE_CLAIMS, False))
    raw = (json.dumps(review, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()
    pending = out / 'review.pending.json';_write(pending, raw);digest = hashlib.sha256(raw).hexdigest()
    current = preflight_assets(assets, pending_reference=pending_reference,
        expected_body_sha256=expected_body_sha256, plan_sha256=plan_sha256)
    if current != prepared:
        raise ValueError('Current-read assets changed while sealing')
    validate_review(pending, digest, current)
    for directory in sorted((p for p in snapshots.rglob('*') if p.is_dir()), key=lambda p: len(p.parts), reverse=True):
        _sync(directory)
    _sync(snapshots)
    final = out / 'review.json';os.link(pending, final);pending.unlink();_sync(out);_sync(out.parent)
    return dict(review_path=str(final), review_sha256=digest, original_plan_sha256=plan_sha256,
                scope=SCOPE, hardware_operations=0, **dict.fromkeys(FALSE_CLAIMS, False))


def _local_source(path):
    from camera_install_patch_session import _safe_path
    return _safe_path(path)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True);p.add_argument('--read-job', type=Path, required=True)
    p.add_argument('--pending-receipt', type=Path, required=True);p.add_argument('--pending-sha256', required=True)
    p.add_argument('--body-sha256', required=True);p.add_argument('--original-plan-sha256', required=True)
    a = p.parse_args()
    result = seal(a.output, assets=assets_from_directory(a.read_job),
        pending_reference=dict(path=str(a.pending_receipt.absolute()), sha256=a.pending_sha256),
        expected_body_sha256=a.body_sha256, plan_sha256=a.original_plan_sha256)
    print(json.dumps(result))


if __name__ == '__main__':main()
