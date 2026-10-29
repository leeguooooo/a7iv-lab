"""Seal PRE_INSTALL runtime collection assets and sources without device I/O."""
import hashlib
import json
import os
from pathlib import Path
import secrets

from camera_install_patch_plan import _local, _write, _sync
from camera_install_runtime_session import (SCOPE, REVIEW_SCHEMA, SOURCE_ONLY_RUNTIME, FALSE_CLAIMS,
    SHA, _requirements, preflight_assets, review_source_paths, validate_review, require)


def seal(output, *, assets, body_sha256, plan_sha256, required_partition_sizes, preflight_fn=None):
    require(all(type(value) is str and SHA.fullmatch(value) for value in (body_sha256, plan_sha256)),
            'Bound body/original plan SHA required')
    out = _local(output, directory=True, existing=False)
    required = _requirements(required_partition_sizes)
    require(preflight_fn is None or callable(preflight_fn), 'Callable local runtime preflight required')
    preflight = preflight_assets if preflight_fn is None else preflight_fn
    prepared = preflight(assets)
    from camera_install_runtime_session import ROOT
    sources = {}
    for name in review_source_paths(prepared):
        relative = Path(name)
        require(not relative.is_absolute() and '..' not in relative.parts, 'Relative runtime source path required')
        from camera_install_patch_session import _safe_path
        sources[name] = hashlib.sha256(_safe_path(ROOT / name).read_bytes()).hexdigest()
    out.mkdir(mode=0o700, parents=True);snapshots = out / 'sources';snapshots.mkdir(mode=0o700)
    for name, digest in sources.items():
        raw = (ROOT / name).read_bytes()
        require(hashlib.sha256(raw).hexdigest() == digest, 'Runtime source changed while sealing')
        target = snapshots / name;target.parent.mkdir(mode=0o700, parents=True, exist_ok=True);_write(target, raw)
    used = {prepared.reference['p1']['nonce'], prepared.reference['metadata']['nonce']}
    nonces = []
    while len(nonces) < 2:
        value = secrets.token_hex(16)
        if any(bytes.fromhex(value)) and value not in used:
            used.add(value);nonces.append(value)
    review = dict(schema=REVIEW_SCHEMA, scope=SCOPE, model='ILCE-7M4', body_sha256=body_sha256,
        original_plan_sha256=plan_sha256, required_partition_sizes=required, asset_reference=prepared.reference,
        acquisition_phase='PRE_INSTALL', technical_p1_profile='post_p1', group_nonce=nonces[0], pdt_nonce=nonces[1],
        sources=sources, source_snapshot_directory=str(snapshots), source_only_runtime=dict(SOURCE_ONLY_RUNTIME),
        execution_approval_received=False, hardware_operations=0, **dict.fromkeys(FALSE_CLAIMS, False))
    raw = (json.dumps(review, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()
    pending = out / 'review.pending.json';_write(pending, raw);digest = hashlib.sha256(raw).hexdigest()
    fresh = preflight(assets);require(fresh == prepared, 'Runtime assets changed during sealing')
    validate_review(pending, digest, fresh, body_sha256, plan_sha256, required)
    for directory in sorted((p for p in snapshots.rglob('*') if p.is_dir()), key=lambda p: len(p.parts), reverse=True):
        _sync(directory)
    _sync(snapshots)
    final = out / 'review.json';os.link(pending, final);pending.unlink();_sync(out);_sync(out.parent)
    return dict(review_path=str(final), review_sha256=digest, original_plan_sha256=plan_sha256,
                scope=SCOPE, hardware_operations=0, **dict.fromkeys(FALSE_CLAIMS, False))
