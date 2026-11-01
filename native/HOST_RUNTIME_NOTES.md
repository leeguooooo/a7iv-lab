# 主机集成设计笔记

从 README 移出的实现细节，上手步骤见 [README](../README.md)。

## 专用模块

`camera_native_library_read.py`在调用方已认证并持有设备操作权时，只通过既有Adjust1001选择文件/GET协议读取两份固定OSAL库，每份最多64KiB。它没有设备发现、模式切换、上传、执行或通用文件路径入口；调用方仍须完成租约、历史状态检查和退出处理。不要把SDK通用FileControl与该协议混用。库文件读取和离线原始指令检查均不构成自定义声音的实机验收。

`camera_candidate_profiles.py`与`camera_profile_audit.py`提供显式候选的离线身份及CRC审核。注册表只接受源码列出的最终签名包SHA，旧三字段绑定始终表示旧FL23包；新包不能复用旧绑定。现有安装journal和设备actor尚未开放新候选，注册及审核通过均不代表安装授权。观察固件的角色明确为消息采集，不是自定义声音成品。

### RO runtime identity host integration (review only)

`camera_readonly_identity.py` adds a bounded, injected `capture_authenticated`
path for the separately frozen `output/readonly-runtime-identity-20261031` kit.
It supplies no discovery, authentication, service entry, STOP, reset, automatic
retry, RAM patch or firmware install command. An isolated Git worktree is
explicitly rejected for hardware capture; integration and source review must
precede any separately authorized physical attempt.

The caller first verifies `Assets(kit_dir, source_root)` with `preflight_assets`.
This hashes the frozen kit, its sources, native inputs and compiler without
running them. A fresh `PLANNED` journal, exact target and stable reviewed
`approval_payload` are required. No approval is generated: the caller must
provide a separate explicit operator approval. That approval binds the target,
plan/body/history, scope, artifact and decoder hashes, nonce, declared filesystem
writes and one attempt. The ephemeral lease instance is bound later in the
reservation and receipt, so approval need not be requested while a lock is held.

`reserve_assets` permanently consumes the nonce across kit/rebuild copies.
It seals a snapshot of the reviewed freeze/manifest, decoder and host sources
into the reservation. Historical journal replay verifies those captured bytes,
not the current host source or current nonce/profile constants. A legitimate
source/profile update therefore preserves older OBSERVED terminals and older
UNKNOWN barriers. Historical schema 1 uses a stable lifecycle parser and explicit
decoder ABI/SHA allowlist; unknown ABIs fail closed. Stored host modules are never
executed, and a decoder's self-declared hash grants no execution authority. The
hashes and hash chain detect changes relative to captured references; they do
not authenticate an operator, a physical camera, or a rewritten entire ledger.
Current execution still requires the strict current-profile preflight.
`capture_authenticated` requires that exact reservation, current held lease and
an explicitly supplied channel on the already authenticated device. Hardware
calls require the canonical global lease/sessions, exact `IdentityChannel`, and
a trusted caller callback binding the physical target and exclusive device
operation ownership. A JSON `source_is_hardware` field cannot establish this
context; the cooperative host lock alone cannot establish device exclusivity.
That callback must be a pure cached authority check: it runs before MAY and may
perform no device I/O, authentication, discovery or SDK calls. The host's
MAY-before-I/O guarantee covers its own `IdentityChannel` calls, not arbitrary
caller code. `SIMULATED` requires a separate model double and rejects every known
`StreamFileChannel`/`BootstrapChannel`/`IdentityChannel` transport before MAY.

Before the first device read, the shared `InstallJournal` durably records
`RO_METADATA_MAY_BE_ACTIVE`. The host checks nonce-job absence, both original
loader library pins, and fixed upload-slot absence before uploading the exact
bootstrap once. The held lease, absent slot and exact upload bind ownership of
its fixed-path cleanup. Every packet rechecks lease/history ownership. Ready is
exactly 128 bytes/version 1, START uses `ROSTART1`, and result is at most 200000
bytes. Returned lifecycle bytes are persisted before parsing. Only known missing
publications are polled; failed/unknown reads, writes or persistence are never
retried.

A validated raw receipt closes only this observation as `RO_METADATA_OBSERVED`.
Any uncertain outcome remains `RO_METADATA_UNKNOWN` (or durable MAY if recording
UNKNOWN fails), blocking later operations through the existing global guard
after lease release. RO history cannot use install cancellation/reconciliation
or transition to RAM/flash authorization. A separately approved
`observe_existing_terminal_authenticated` attempt can read an UNKNOWN job's
original launch/ready/result and fixed slot, using a fresh guarded channel and
current lease. `TerminalObservationChannel` has no upload, START, re-execution,
STOP, reset, delete or cleanup API. Its raw publications and slot observation
are saved before validation with the sealed historical decoder. Only complete
same-operation success can transition UNKNOWN to OBSERVED; missing, malformed,
uncertain, wrong-target or wrong-source observations retain UNKNOWN. Approval
binds the exact UNKNOWN event, target/source, current source closure, evidence
path and a separate attempt nonce. The intent consumes that nonce before I/O;
replaying an attempt is forbidden. A later read requires a new explicit approval
and attempt nonce. Old capture consent is never reused. The observer requires a
currently held valid lease: it may continue under the same still-held lease or
acquire a new one after release; an expired lease is never accepted.
The successful observer receipt seals its current source bytes and records its
current lease separately, preserving historical replay after future updates. The receipt proves neither firmware,
device identity nor image admission. Missing optional sources, including the
frozen worker's `/proc/sys/kernel/module_sig_enforce` path, remain unknown and
are never positive module-load admission. The separate native probe's sysfs
signature-enforcement path is unchanged.

Offline regression checks use Python 3.11+ and temporary simulated fixtures:

```sh
python -m unittest discover -s tests -p test_camera_readonly_identity.py
python -m unittest discover -s tests -p test_camera_install_journal.py
python -m unittest discover -s tests -p test_camera_install_runtime_metadata.py
python -m unittest discover -s tests -p test_camera_operation_guard.py
python -m unittest discover -s tests -p test_camera_stream_execution.py
python -m unittest discover -s tests -p test_camera_device_lease.py
```

### Historical formal-flow evidence

`camera_install_flow_history.py` validates known version-1 producer history as
data. It verifies the sealed config/header/event and journal prefixes, original
and continuation source snapshots, the known controller/emulator/helper profile,
and existing historical pending/runtime receipt validators. It never executes
archive code or compares historical hashes with current checkout files. Producer
queries read the bound journal ancestor, so admission/card validation cannot
recurse into a future journal event.

Current `validate_config`, `init`, `step` and ordinary `status` keep their current
source checks. For a closed flow, `camera_install_flow.py status --flow ...
--historical` is an explicit read-only query: it requires CONTENT_VERIFIED and
recomputes the existing raw capture-run verification before returning. It cannot
operate devices, continue a flow, authorize firmware, or reconcile UNKNOWN.
Unsupported historical ABIs/profiles, modified snapshots, mismatched capsule
references and damaged receipts remain blocking. Hashes preserve integrity
relative to recorded references; they do not authenticate a rewritten ledger or
turn a JSON source declaration into physical attestation. New controller ABIs
must preserve or explicitly extend the historical profile registry.

The post-install proof chain currently repeats substantial local hashing:
admission/card/probe validation can revisit the same pending/runtime captures
and source snapshots, and historical closed status recomputes content captures.
This change adds no cache and makes no performance claim. A later, separate
performance design should first measure repeated bytes/call paths, then consider
bounded per-query reuse tied to immutable artifact references and pinned file
identity. Such reuse must invalidate on drift and must never cache hardware
liveness, operation authorization, UNKNOWN clearance, or evidence admission.
