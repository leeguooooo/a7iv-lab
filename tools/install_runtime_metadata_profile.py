"""Fixed metadata-only native inputs; no device imports."""
import hashlib
from pathlib import Path
from menu_window_profile import ROOT, APP, COMPILER, COMPILER_SHA, require, read_regular, sha, mapped
SCHEMA='camera-install-runtime-metadata-offline/2'
PROFILE='fixed_partition_alias_metadata_v2_boot_epoch'
HEADER=APP/'native/linux_a64.h'
BOOTSTRAP=APP/'native/bootstrap.c'
SHA_HEADER=APP/'writer/sha256.h'
SOURCE_PATHS=('camera_device_lease.py','camera_install_journal.py','camera_operation_guard.py','camera_install_patch_session.py','camera_stream_execution.py','camera_stream_channel.py','camera_install_runtime.py',
 'camera_install_receipts.py','camera_install_card_withdraw.py','camera_install_cancel.py','camera_install_cancel_session.py',
 'camera_install_epoch_session.py','camera_install_epoch_plan.py','camera_install_io.py','native/install_runtime_metadata.c','camera_install_runtime_metadata.py',
 'tools/install_runtime_metadata_profile.py','tools/build_install_runtime_metadata_offline.py',
 'tools/verify_install_runtime_metadata_offline.py','tools/emulate_install_runtime_metadata_offline.py')
PINS={str(HEADER.relative_to(ROOT)):'827bfa50c9d5e2a1ee8eacc032303844cd3c0a8a9b4f5ea1bfa640a987eedd88',
 str(BOOTSTRAP.relative_to(ROOT)):'4e4dcb37eceab654a25b4a7f0d16626d1764f2a9708a48b3275da10c173b19a1'}
def input_evidence():
 for name,pin in PINS.items():require(sha(ROOT/name)==pin,'Pinned helper changed: '+name)
 require(sha(COMPILER)==COMPILER_SHA,'Compiler changed')
 paths=(*SOURCE_PATHS,*PINS,str(SHA_HEADER.relative_to(ROOT)),
 'tools/emulate_install_patch_read_offline.py','tools/verify_menu_window_offline.py','tools/emulate_stream_bootstrap.py','tools/model_toolchain_bootstraps_offline.py',
 'local/zig-aarch64-macos-0.15.2/lib/libc/include/any-linux-any/asm-generic/stat.h',
 'local/zig-aarch64-macos-0.15.2/lib/libc/include/any-linux-any/asm-generic/unistd.h')
 return {p:hashlib.sha256(read_regular(ROOT/p)).hexdigest() for p in paths}
def header(nonce):
 return (f'#define JOB_DIR "/tmp_wbshd/m4irm_{nonce.hex()}"\nstatic const unsigned char job_nonce[]={{'+','.join(map(str,nonce))+'};\n').encode()
def jobpath(path,fresh=False):
 p=Path(path).absolute();require('..' not in p.parts and p.is_relative_to(ROOT/'output') and all(not q.is_symlink() for q in (p,*p.parents)),'Canonical private output required')
 if fresh:require(not p.exists(),'Fresh output required')
 return p
