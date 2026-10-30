"""Seal local post-completion inputs and sources; never contact a device."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets

import camera_postinstall_verify as verifier
from camera_install_patch_plan import _local, _write, _sync
from camera_install_patch_session import _safe_path, SOURCE_ONLY_RUNTIME
from camera_install_post_session import (PostAssets, PROFILES, preflight_assets, before_evidence,
    review_source_paths, validate_review, _reference, _read_reference, _canonical,
    FALSE_CLAIMS, REVIEW_SCHEMA, SCOPE, require, _completion)
from camera_install_journal import InstallJournal


def assets_from_directory(directory):
    directory = _local(directory, directory=True)
    return PostAssets(directory, *(hashlib.sha256(_safe_path(directory / name / 'bootstrap/bootstrap.json').read_bytes()).hexdigest()
                                   for name in PROFILES))


def seal(output, *, assets, before_group, original_plan_reference, completion_reference,
         body_sha256, preflight_fn=None):
    """Publish a reviewed post-capture plan without authorizing service entry."""
    output = _local(output, directory=True, existing=False)
    original_raw, original = _read_reference(original_plan_reference)
    binding = dict(body_sha256=body_sha256, plan_sha256=original_plan_reference['sha256'], model='ILCE-7M4')
    before = before_evidence(before_group, binding)
    journal = InstallJournal.open(before['descriptor']['journal_session'])
    require(journal.state == 'DEVICE_COMPLETION_REPORTED' and journal.binding == binding, 'Completed original journal required for post plan')
    completion = _completion(completion_reference, binding, journal, not before['source_is_hardware'])
    require(completion.get('runtime_reference') == before['references']['runtime-session-exit.json'],
            'Completion does not bind original runtime group')
    preflight = preflight_fn or preflight_assets
    prepared = preflight(assets)
    from camera_install_post_session import ROOT
    sources = {}
    for name in review_source_paths(prepared):
        require(not Path(name).is_absolute() and '..' not in Path(name).parts, 'Relative post source required')
        sources[name] = hashlib.sha256(_safe_path(ROOT / name).read_bytes()).hexdigest()
    output.mkdir(mode=0o700, parents=True)
    snapshots = output / 'sources';snapshots.mkdir(mode=0o700)
    for name, digest in sources.items():
        raw = (ROOT / name).read_bytes()
        require(hashlib.sha256(raw).hexdigest() == digest, 'Post source changed while sealing')
        target = snapshots / name;target.parent.mkdir(mode=0o700, parents=True, exist_ok=True);_write(target, raw)
    used = {before['descriptor']['group_nonce'], before['before']['nonce'],
            *(row['nonce'] for row in prepared.reference['profiles'].values())}
    nonce = secrets.token_hex(16)
    while nonce in used or not any(bytes.fromhex(nonce)):
        nonce = secrets.token_hex(16)
    review = dict(schema=REVIEW_SCHEMA, scope=SCOPE, **binding, before_evidence=before,
        original_plan_reference=original_plan_reference, completion_reference=completion_reference,
        package_reference=_reference(verifier.PLAIN), factory_reference=_reference(verifier.FACTORY_P1),
        asset_reference=prepared.reference, after_nonce=nonce, sources=sources,
        source_snapshot_directory=str(snapshots), source_only_runtime=dict(SOURCE_ONLY_RUNTIME),
        execution_approval_received=False, hardware_operations=0, **dict.fromkeys(FALSE_CLAIMS, False))
    raw = (json.dumps(review, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()
    pending = output / 'review.pending.json';_write(pending, raw);digest = hashlib.sha256(raw).hexdigest()
    fresh = preflight(assets);require(fresh == prepared, 'Post assets changed while sealing')
    validate_review(pending, digest, fresh, binding, before_group, completion_reference)
    for directory in sorted((p for p in snapshots.rglob('*') if p.is_dir()), key=lambda p: len(p.parts), reverse=True):
        _sync(directory)
    _sync(snapshots)
    final = output / 'review.json';os.link(pending, final);pending.unlink();_sync(output);_sync(output.parent)
    return dict(review_path=str(final), review_sha256=digest, original_plan_sha256=binding['plan_sha256'],
                scope=SCOPE, hardware_operations=0, **dict.fromkeys(FALSE_CLAIMS, False))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--assets', type=Path, required=True)
    parser.add_argument('--before-group', type=Path, required=True)
    parser.add_argument('--original-plan', type=Path, required=True)
    parser.add_argument('--original-plan-sha256', required=True)
    parser.add_argument('--completion', type=Path, required=True)
    parser.add_argument('--completion-sha256', required=True)
    parser.add_argument('--body-sha256', required=True)
    args = parser.parse_args()
    print(json.dumps(seal(args.output, assets=assets_from_directory(args.assets), before_group=args.before_group,
        original_plan_reference=dict(path=str(args.original_plan.absolute()), sha256=args.original_plan_sha256),
        completion_reference=dict(path=str(args.completion.absolute()), sha256=args.completion_sha256),
        body_sha256=args.body_sha256)))


if __name__ == '__main__':
    main()
