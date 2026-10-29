"""Seal an offline, body-referenced volatile-preparation plan without device I/O."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re

from camera_install_patch import InstallPatchAssets, InstallCaptureAssets, preflight_assets
from camera_install_patch_session import (CONSENT_SCOPE, REVIEW_SCHEMA, SOURCE_ONLY_RUNTIME,
    review_source_paths, validate_review)

ROOT = Path(__file__).resolve().parent
SHA = re.compile(r'[0-9a-f]{64}\Z')


def require(ok, message):
    if not ok:
        raise ValueError(message)


def _local(value, *, directory=False, existing=True):
    path = Path(value).absolute()
    require(path.is_relative_to(ROOT / 'output') and '..' not in path.parts
            and all(not p.is_symlink() for p in (path, *path.parents)),
            'Nonsymlink workspace output path required')
    if existing:
        require(path.is_dir() if directory else path.is_file(), 'Regular local input required')
    else:
        require(not path.exists(), 'Choose a fresh plan directory')
    return path


def _sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def _object(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'Duplicate JSON field')
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=pairs)
    require(isinstance(value, dict), 'JSON object required')
    return value


def _write(path, raw):
    with path.open('xb') as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def _sync(path):
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def assets_from_directories(patch_job, capture_directory):
    """Read exact local digests; this supplies no execution approval."""
    job = _local(patch_job, directory=True)
    capture = _local(capture_directory, directory=True)
    names = ('manifest.json', 'libJit.so', 'native-model-report.json', 'bootstrap-model-report.json')
    hashes = [_sha(_local(job / name)) for name in names]
    patch = InstallPatchAssets(job, *hashes)
    captures = InstallCaptureAssets(capture, *[_sha(_local(capture / name / 'bootstrap/bootstrap.json'))
                                               for name in ('pre_app', 'pre_ufp')])
    return patch, captures


def seal(output, *, assets, capture_assets, body_reference):
    """Snapshot reviewed sources and publish a fresh plan, never a device intent."""
    output = _local(output, directory=True, existing=False)
    reference = _local(body_reference)
    reference_raw = reference.read_bytes()
    reference_hash = hashlib.sha256(reference_raw).hexdigest()
    body = _object(reference_raw).get('body', {})
    require(isinstance(body, dict) and body.get('model') == 'ILCE-7M4'
            and isinstance(body.get('usb_serial_sha256'), str)
            and SHA.fullmatch(body['usb_serial_sha256']), 'Bound historical body reference required')
    prepared = preflight_assets(assets, capture_assets)
    names = set(review_source_paths()) | set(prepared.manifest['sources'])
    sources = {}
    for name in sorted(names):
        relative = Path(name)
        require(not relative.is_absolute() and '..' not in relative.parts, 'Relative source path required')
        source = ROOT / relative
        require(source.is_file() and all(not p.is_symlink() for p in (source, *source.parents)),
                'Regular nonsymlink source required')
        sources[name] = _sha(source)
    output.mkdir(mode=0o700, parents=True)
    snapshots = output / 'sources'
    snapshots.mkdir(mode=0o700)
    for name, digest in sources.items():
        raw = (ROOT / name).read_bytes()
        require(hashlib.sha256(raw).hexdigest() == digest, 'Source changed while sealing')
        target = snapshots / name
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        _write(target, raw)
    payload = dict(schema=REVIEW_SCHEMA, scope=CONSENT_SCOPE, model='ILCE-7M4',
        body_sha256=body['usb_serial_sha256'], asset_reference=prepared.reference,
        sources=sources, source_snapshot_directory=str(snapshots),
        body_reference=dict(path=str(reference), sha256=reference_hash, historical_only=True),
        source_only_runtime=dict(SOURCE_ONLY_RUNTIME), installation_authorized=False,
        hardware_admission_proven=False, flash_authorized=False,
        execution_approval_received=False, hardware_operations=0)
    pending = output / 'plan.pending.json'
    raw = (json.dumps(payload, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()
    _write(pending, raw)
    plan_sha256 = hashlib.sha256(raw).hexdigest()
    require(_sha(reference) == reference_hash, 'Historical body reference changed while sealing')
    current = preflight_assets(assets, capture_assets)
    require(current.reference == prepared.reference, 'Prepared asset binding changed while sealing')
    validate_review(pending, plan_sha256, body['usb_serial_sha256'], current)
    for name, digest in sources.items():
        require(_sha(snapshots / name) == digest, 'Source snapshot changed while sealing')
    for directory in sorted((p for p in snapshots.rglob('*') if p.is_dir()),
                            key=lambda p: len(p.parts), reverse=True):
        _sync(directory)
    _sync(snapshots)
    plan = output / 'plan.json'
    os.link(pending, plan)
    pending.unlink()
    _sync(output)
    _sync(output.parent)
    return dict(plan=str(plan), plan_sha256=plan_sha256, body_sha256=body['usb_serial_sha256'],
                source_files=len(sources), installation_authorized=False,
                flash_authorized=False, hardware_admission_proven=False, hardware_operations=0)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--patch-job', type=Path, required=True)
    parser.add_argument('--capture-assets', type=Path, required=True)
    parser.add_argument('--body-reference', type=Path, required=True)
    args = parser.parse_args()
    assets, captures = assets_from_directories(args.patch_job, args.capture_assets)
    print(json.dumps(seal(args.output, assets=assets, capture_assets=captures,
                          body_reference=args.body_reference)))


if __name__ == '__main__':
    main()
