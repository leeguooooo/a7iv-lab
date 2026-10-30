# 安装并验收 FL2、FL3

本操作单供相机到场后逐步执行。相机不在场时，只做离线校验和封存。
使用 `camera_install_flow.py`。旧 `camera-workflow` 的临时演练不能代替正式安装。

## 选定准备包

读取最新的 `output/fl23-complete-prepared-*/bundle.json` 和对应复核报告。
使用报告明确选定、源码校验仍通过的配置。目录编号较大不代表已获安装许可。
保留旧包作为历史记录，不复用旧现场提案或已消费的任务。

准备包包括候选文件、源码快照、八个静态原生任务、完整写入范围、备份复核结果和空白观察模板。
恢复风险批准、完整安装批准和拍摄验收均在现场另行记录。

先运行只读配置校验。将下列两个值替换为选定包的真实路径和 SHA256：

```sh
.venv-offline/bin/python -B -E -s -X pycache_prefix="$PWD"/output/workflow-absent-bytecode-cache -c 'from camera_install_flow import validate_config; validate_config({"path":"CONFIG_PATH","sha256":"CONFIG_SHA256"}); print("CONFIG_VALID")'
```

必须看到 `CONFIG_VALID`。源码变化或任务已使用时，停止并重新准备对应任务。

## 选择卡文件发布协议

准备包的 `card_activation_protocol` 明确选择发布协议。未指定时沿用 `EXCLUSIVE_RENAME`，不会在不支持时自动降级。该协议在写入激活意图之前检查系统声明的 `RENAME_EXCL` 能力；未知或不支持即停止。能力位不是实机操作证明。

macOS 某些 exFAT 驱动不支持排他改名或原子交换。`BACKUP_COPY_ATOMIC_REPLACE` 是另一份合同，需重新审查与封存，并取得明确的单写者授权。整个过程中不得用 Finder、其它程序或机身操作写这张卡，不得启动更新。主机锁只约束合作工具，无法阻止其它写者在最后检查与替换之间改动文件。这种模式不提供任意并发下的 no-clobber 保证。

该模式先独占创建完整旧包备份，文件和目录同步并完整读回，再原子替换 `BODYDATA.DAT`。不先删除或移走根目录文件，不在活动文件名下复制半个候选包。撤回使用对应的逆协议，先完整保留候选包，再将旧备份原子替换回根目录。任何同步、改名或读回结果不确定都保留现场，不自动回滚或重试。

业务文件改动前必须另行授权小文件兼容性探测。`tools.card_protocol_probe.probe` 仅在新建的 `.camera-use-probes/pair-*` 目录内执行同一发布与撤回引擎，记录目录同步和改名后文件身份检查。它不触碰根目录更新文件，也不证明掉电恢复。该函数要求调用者持有主机 lease、绑定当前相机卡发现器，并显式传入 `scratch_authorized=True` 与 `single_writer_acknowledged=True`。不得把它当自动健康检查。

选择新协议时，在 runtime 完成后运行独立的 `probe` 流程步骤。操作者记录需明确 `scratch_authorized=True`、`single_writer_acknowledged=True`、`slot1_confirmed=True`。流程仅在探测函数正常返回后记录该步 COMPLETED；发布和撤回只使用同一受审流程的已完成探测引用，不接受操作者直接提交孤立 completed 文件。它们同时验证完整探测和内层证据；缺少外层完成记录、出现 UNKNOWN、证据变化、相机或卡身份不符均拒绝。USB 重连只允许同一机身、卷 UUID、文件系统和容量的稳定身份，探测过程内部仍固定全部句柄身份。更换主机系统版本或引擎源码后须重新探测。

旧失败尝试的 UNKNOWN 不得改写为成功。先按独立、已审查的只读对账终止旧尝试，保留其全部记录；之后使用新源码封存、新任务 nonce 和新流程。不要在旧流程里直接切换协议重试。

## 接入相机并准备更新

1. 确认机身为 ILCE-7M4，版本为 6.02，拍摄和回放正常。
2. 开机，接 USB，选择 MSC。记录实际电量、卡槽和相机提示。
3. 取得本次读取、卡文件操作及临时内存修改的具体授权。完整固件更新另行批准。
4. 创建新的正式流程目录。`init` 创建本机 journal 和全局操作屏障，不发送相机命令。

```sh
sudo .venv-offline/bin/python -B -E -s -X pycache_prefix="$PWD"/output/workflow-absent-bytecode-cache camera_install_flow.py init --config CONFIG_PATH --config-sha256 CONFIG_SHA256 --output output/fl23-onsite-UNIQUE
```

每次只执行一个已获授权的步骤。操作者 JSON 由实际观察生成，引用路径和哈希必须一致。
不要把空模板中的 `null` 批量替换成 `true`。

```sh
sudo .venv-offline/bin/python -B -E -s -X pycache_prefix="$PWD"/output/workflow-absent-bytecode-cache camera_install_flow.py step --flow output/fl23-onsite-UNIQUE STEP --step-authorized --camera-ready --operator-artifact OPERATOR_PATH --operator-sha256 OPERATOR_SHA256
```

没有操作者输入的步骤，省略两个 `--operator-*` 参数。仅对当前已确认可用的相机传入 `--camera-ready`。

依次执行以下步骤。每步核对保存的结果，再执行下一步：

1. `runtime`：采集本次机身、P1、分区容量、电源 IC 和 AP 启动标识。历史备份不能代替本次读取。采用新备份替换协议时，随后执行单独授权的 `probe` 步骤；通过后才允许 stage。
2. `stage`：校验卡和候选包后暂存文件。
3. `activate`：确认卡槽 1 后激活更新文件名。此步骤不按相机上的最终更新确认。
4. `patch`：取得明确的临时内存修改许可后执行一次准备任务。成功后保留待重连状态。
5. 按本次结果要求恢复 MSC 连接。不要自行重启或点击更新。
6. `prepare-read`：按本次真实 PID 和待确认记录自动生成只读任务，运行离线模型并封存。现场不修改代码。
7. `read`：重新读取当前两个目标字。只有两个均为预期修改值，且原生任务已明确结束，才继续。
8. `observe-card`：完整读取当前卡上的活动文件，核对候选包和原文件。

## 批准并手动开始更新

先向用户展示本次完整写入范围和恢复缺口。现有备份不是当前一致快照，独立物理介质未证明，CP NOR 完整恢复和无法启动时的恢复入口尚未验证。
默认策略拒绝放行。若用户选择继续，必须明确接受报告列出的每一项恢复风险，并另行批准这一个候选包的完整更新。

1. 用 `camera_install_operator.py` 的记录函数保存实际菜单、卡槽、电源、健康状态和证据引用。
2. 保存本次明确的恢复风险决定。仅在用户明确接受时生成例外记录，再绑定完整安装批准。
3. `admit`：校验运行时、内存重读、卡文件、候选包、写入范围、恢复决定和批准记录。
4. `start`：先持久记录 `FLASH_MAY_HAVE_STARTED`。只有该步骤成功返回手动指令，才按相机上的最终更新确认。
5. 按相机屏幕要求等待和操作。电脑不会自动点击更新、重启或断电。

## 读取更新结果并验收

1. 相机明确报告更新完成后，记录真实提示以及按屏幕要求完成的操作。
2. `complete`：保存操作者完成报告。报告本身不证明固件内容正确。
3. `prepare-post`：封存更新后的读取计划。
4. `post`：取得本次读取授权后采集 AP、CP、P1 和 PDT。
5. `content`：重新计算并核对实际内容，再记录内容校验通过。
6. 分别使用 FL2、FL3 拍摄照片和视频，共四份不同媒体。确认保存和机内回放，保留原始文件及实际参数。
7. 按验收要求记录断电重启后的表现。普通开关机只能形成部分验收，不能冒充完整断电验收。
8. `features`：核对四份真实媒体和明确的操作者报告，保存功能验收结果。

## 遇到异常时停止

状态为 `UNKNOWN`、原生结束不明确、STOP 失败、lease 变化或 journal 追加不确定时，保留全部现场文件并停止。
不要自动重试、重复上传、再次 START、重置 USB、断电或回滚。

尚未开始更新时，按当前 journal 状态选择取消路径：

- `PLANNED`：直接执行已获授权的 `cancel`，不撤回文件。
- `SD_STAGED` 且未执行 `activate`：执行 `cancel`，由工具确认卡上没有活动候选。不执行 `withdraw`。
- 已执行 `activate`：先取得文件名撤回许可，执行 `withdraw`，确认活动候选已撤回。若仍为 `SD_STAGED`，再执行 `cancel`。
- `INSTALL_PATCH_AWAITING_OPERATOR_RECONNECT`：完成上述撤回后，选择当前原值读取策略执行 `cancel`；或另获人工 AP 重启许可后，按实际顺序执行 `prepare-epoch` 和 AP 启动标识策略的 `cancel`。

仅在取消记录明确完成后，才把流程视为已解除。`BLOCKED_READ_ONLY` 表示本次已知读取不满足取消条件，journal 仍保留屏障。
记录过 `FLASH_MAY_HAVE_STARTED` 后，不使用这些更新前取消路径。

查看已有状态不触碰相机：

```sh
.venv-offline/bin/python -B -E -s -X pycache_prefix="$PWD"/output/workflow-absent-bytecode-cache camera_install_flow.py status --flow output/fl23-onsite-UNIQUE
```
