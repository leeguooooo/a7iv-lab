"""Seal a pending AP-epoch read from immutable prior receipts; no device entry."""
import hashlib
import json
import os
from pathlib import Path

from camera_install_patch_plan import _local,_write,_sync
from camera_install_journal import InstallJournal
from camera_install_patch_session import _safe_path,SOURCE_ONLY_RUNTIME,canonical_sha256
from camera_install_epoch_session import (ROOT,SCOPE,REVIEW_SCHEMA,FALSE_CLAIMS,require,
    source_summary,review_source_paths,validate_review)
import camera_install_runtime_metadata as metadata


def seal(output,*,assets,body_sha256,plan_sha256,pending_reference,initial_runtime_reference,
        withdrawal_reference,journal,preflight_fn=None):
    out=_local(output,directory=True,existing=False)
    binding=dict(body_sha256=body_sha256,plan_sha256=plan_sha256,model='ILCE-7M4')
    require(journal.binding==binding,'Original epoch journal binding required')
    history=journal.events
    require(InstallJournal.open(journal.session_dir).events==history,'Stale epoch journal before sealing')
    summary=source_summary(pending_reference,initial_runtime_reference,withdrawal_reference,binding,history,journal.session_dir)
    require(preflight_fn is None or callable(preflight_fn),'Callable local epoch preflight required')
    preflight=metadata.preflight_assets if preflight_fn is None else preflight_fn
    prepared=preflight(assets)
    sources={name:hashlib.sha256(_safe_path(ROOT/name).read_bytes()).hexdigest() for name in review_source_paths(prepared)}
    out.mkdir(parents=True,mode=0o700);snapshots=out/'sources';snapshots.mkdir(mode=0o700)
    for name,digest in sources.items():
        relative=Path(name);require(not relative.is_absolute() and '..' not in relative.parts,'Relative epoch source required')
        raw=(ROOT/name).read_bytes();require(hashlib.sha256(raw).hexdigest()==digest,'Epoch source changed while sealing')
        path=snapshots/name;path.parent.mkdir(parents=True,exist_ok=True,mode=0o700);_write(path,raw)
    review=dict(schema=REVIEW_SCHEMA,scope=SCOPE,**binding,session_id=journal.session_dir.name,
        pending_reference=pending_reference,initial_runtime_reference=initial_runtime_reference,
        withdrawal_reference=withdrawal_reference,asset_reference=prepared.reference,source_summary=summary,
        history_sha256=canonical_sha256(history),source_only_runtime=dict(SOURCE_ONLY_RUNTIME),sources=sources,
        source_snapshot_directory=str(snapshots),execution_approval_received=False,hardware_operations=0,
        **dict.fromkeys(FALSE_CLAIMS,False))
    raw=(json.dumps(review,sort_keys=True,indent=2,allow_nan=False)+'\n').encode();pending=out/'review.pending.json'
    _write(pending,raw);digest=hashlib.sha256(raw).hexdigest()
    require(preflight(assets)==prepared,'Epoch assets changed while sealing')
    require(source_summary(pending_reference,initial_runtime_reference,withdrawal_reference,binding,history,journal.session_dir)==summary,
            'Original epoch sources changed while sealing')
    require(InstallJournal.open(journal.session_dir).events==history,'Epoch journal changed while sealing')
    validate_review(pending,digest,prepared,binding=binding,pending_reference=pending_reference,
        initial_runtime_reference=initial_runtime_reference,withdrawal_reference=withdrawal_reference,
        summary=summary,history=history,session_dir=journal.session_dir)
    for directory in sorted((p for p in snapshots.rglob('*') if p.is_dir()),key=lambda p:len(p.parts),reverse=True):_sync(directory)
    _sync(snapshots);final=out/'review.json';os.link(pending,final);pending.unlink();_sync(out);_sync(out.parent)
    return dict(review_path=str(final),review_sha256=digest,scope=SCOPE,hardware_operations=0,**dict.fromkeys(FALSE_CLAIMS,False))
