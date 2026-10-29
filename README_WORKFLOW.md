# 相机分步工具

在项目目录运行。四个阶段展开成 17 个子步骤，完整列表以工具显示为准。

```sh
./camera-workflow steps
./camera-workflow simulate --interactive
./camera-workflow simulate --scenario usb-lost --interactive
./camera-workflow simulate --scenario write-interrupted
```

模拟不连接相机、不写存储卡，不创建真实操作记录。按回车逐步查看，输入 `q` 退出。可选场景还有 `bad-package`、`wrong-body`、`ram-unknown`、`verify-mismatch`。模拟中的“通过”仅代表合成流程；它不能成为实机验收或写入许可。

离线准备新计划会运行本地测试并保存源码快照。输出路径必须是新的文件名，旧记录不会覆盖：

```sh
./camera-workflow prepare --report output/offline-toolchain/my-reviewed-plan.json
```

实操控制器目前只接通临时演练的 `settings → stage → window → restore`，一次命令只做一个动作。`init` 仅创建本地计划和机身绑定记录；`status` 只读已有记录。正式安装和更新文件名激活没有实操入口。它们在模拟中展示，但仍需完成实机演练及单独安装审查。

初始化写盘失败时，`status` 可以显示缺失记录及已有 ledger。`cancel-init --confirm-local-cancel` 只允许取消尚无任何设备动作意图的本地初始化，保留全部记录；开始过设备动作后不能用它清除未知状态。

执行临时演练时，需使用已审核的计划文件及其完整 SHA。每个设备动作都要求独立的 `--authorize-step`、`--camera-ready`、`--firmware-never-started`，暂存还要求 `--slot1-confirmed`。这些参数是操作者确认，不是软件自行获得的授权或现场检测。

临时演练会加载用户态程序并写临时文件，只改两处 RAM 指令；不启动固件更新。已知服务退出不等于恢复成功，倒计时结束也不能代替原窗口的恢复记录。遇到未知结果会保留意图和部分证据，阻断后续步骤，不自动重试、回滚、STOP 或重启。完整更新涉及非原子写入，工具无法保证断电后恢复。

`window` 核实两处修改并确认服务退出后，保存待重连记录，状态为 `RAM_AWAITING_OPERATOR_RECONNECT`。工具在此停止，等待操作者保持相机开机、重新连接 USB 并选择 MSC。没有要求人工在 30 秒内完成操作的倒计时。记录中的剩余秒数只作历史观察，不能作为继续操作的许可。

待连接状态不会放行正式安装、新窗口、其他工作流或取消。操作者重新连接并选择 MSC 后，可单独授权既有 `restore` 动作。它只在一次重新核实机身的会话中读取原窗口的 ready、patched 和终态记录，核对原 nonce、原程序及原生恢复证明；即使已超过 600 秒也必须取得证明。成功后才记录专用的 `RAM_RESTORATION_VERIFIED`，不上传或 START 新程序。USB、认证、终态或 STOP 未知仍保留为 `STOPPED_UNKNOWN`，不自动重试、复位或重启。

待重连记录位于 `menu/session-awaiting-reconnect.json`，与 `window-result.json` 相同。原补丁观察和完整待重连记录的哈希都绑定到审计事件。新的分步交接流程已通过离线验证，尚未重新进行真机验收。已使用的一次性原生任务不能重用；下一轮实机实验需另行准备新任务和新计划。

## 一次性安装补丁的离线开发

独立的 `INSTALL_VOLATILE_PATCH` 模块已接入离线构建和校验，尚无设备执行器。以下命令只读取本地原件、交叉编译，并在 Unicorn 的合成环境中验证目标指令，不连接相机。构建目录必须不存在，报告不会覆盖。

```sh
.venv-offline/bin/python -B -E -s tools/build_install_volatile_offline.py --output output/install-volatile-review-01
.venv-offline/bin/python -B -E -s tools/verify_install_volatile_offline.py --output output/install-volatile-review-01
.venv-offline/bin/python -B -E -s tools/emulate_install_volatile_offline.py --job output/install-volatile-review-01 --bootstrap-report output/install-volatile-review-01/bootstrap-model-report.json
.venv-offline/bin/python -B -E -s camera_toolchain.py check --tests --install-volatile-job output/install-volatile-review-01 --report output/install-volatile-review-01/toolchain-check.json
```

新模块使用 `M4IVP001/version2` 和独立 START 协议。成功时两处补丁有意保留，关闭两个内存句柄后发布终态并退出，不再计时恢复。提交边界前的失败保留原目标身份检查和反向恢复；提交后的关闭或发布异常仍可能留下补丁，不能重试或声称已恢复。最终记录先写入并关闭临时文件，再以 `RENAME_NOREPLACE` 发布，关闭或重命名失败不能产生新的成功终态。

主机验证器只核对三份回执的字节、身份和状态一致性，不证明它们来自真实设备。`VOLATILE_PATCH_APPLIED_NOT_RESTORED` 不等于 RAM 恢复、菜单接纳或安装成功。工具链检查同时核对完整 worker 与 bootstrap 模型及其源码、产物、nonce 绑定，仍保持 `installation_authorized=false`。真实 Linux 调用、缓存一致性、进程切换、正式安装交接和取消流程尚待验证，现有演练入口继续使用原协议。

## 主机准备会话与计划封存

`run_install_patch_session` 提供独立的准备会话接口，没有接入设备 CLI。它只接受易失补丁准备许可，并要求明确知晓补丁不会计时恢复；这不是固件安装许可。真实入口要求全局 journal、规范设备 lease，以及 `-B -E -s -X pycache_prefix="$PWD/output/workflow-absent-bytecode-cache"` 启动参数，该缓存目录必须不存在。

认证前先校验计划、源码快照、原生模块和全部 nonce，再记录 `INSTALL_PATCH_MAY_BE_ACTIVE` 并预留一次性任务。完整回执先落盘，成功路径才允许原正常会话辅助函数执行 STOP。已知退出后只记录 `INSTALL_PATCH_AWAITING_OPERATOR_RECONNECT`。该状态仍阻断协作工具的其他操作，不通往 READY、FLASH、旧演练恢复或取消。未知认证、START、回执或 STOP 结果都不会自动重试、恢复或重启。

封存新计划前，需要两份未使用的原库采集任务。以下命令均为离线构建和本地封存，不会预占硬件 nonce，也不会连接设备：

```sh
.venv-offline/bin/python -B -E -s tools/build_firmware_file_capture_offline.py --target pre_app --output output/install-patch-captures-01/pre_app --bundle
.venv-offline/bin/python -B -E -s tools/build_firmware_file_capture_offline.py --target pre_ufp --output output/install-patch-captures-01/pre_ufp --bundle
.venv-offline/bin/python -B -E -s camera_install_patch_plan.py --output output/install-patch-plan-01 --patch-job output/install-volatile-review-01 --capture-assets output/install-patch-captures-01 --body-reference output/backup-01/execution/run.json
```

计划绑定本地源码、SDK Python 文件、快照、模块与采集任务哈希，以及历史机身参考记录。它不证明相机当前在线或满足现场条件，也不授予执行许可。源文件、快照或参考记录变化后，入口会在认证前拒绝旧计划。计划目录必须是新目录，旧文件不会覆盖。

重连后仍需新的当前状态证据或明确的刷写前菜单验收。保存的补丁终态和同机 MSC 重现，不能证明补丁此刻仍有效。补丁后的安全取消与正式更新入口尚未实现，不能靠时间、PID 消失或一次电源拨动清除审计记录。

## 当前 RAM 只读观察与取消证据

`camera_install_patch_read.py` 与独立原生读取程序提供当前字节观察契约，尚未接入真实 SDK 会话。目标只能从完整的原准备回执派生，构建接口不接受单独 PID 或地址。新回执绑定读取 nonce、原补丁 nonce 和完整目标规格 SHA；原生程序只读固定 PID 的 maps、stat 和 mem，两遍比较映射、启动计数、锚点、版本及目标字，关闭内存句柄后才发布终态。

结果区分 `ORIGINAL`、`PATCHED`、`MIXED`、`OTHER`。PID 消失或上下文、字节发生变化会保留未知，不能解释成补丁已经清除。当前字节观察不证明与原 worker 已关闭的 mm 连续，也不等于恢复、取消或安装准入。

构建参数和离线检查入口如下。读取任务必须使用新的目录；MODEL 回执仅用于合成验证，不能当作机身观察。该组件只能走离线 `check`，不能混入旧 `prepare` 会话计划：

```sh
.venv-offline/bin/python -B -E -s tools/build_install_patch_read_offline.py --help
.venv-offline/bin/python -B -E -s camera_toolchain.py check --tests --install-patch-read-job output/current-read-reviewed-01
```

`camera_install_cancel.py` 只评估证据。它要求明确注入文件系统观察器，固定卡身份和打开的目录/文件句柄，完整核对未激活候选及原根文件。活动候选不会被自动撤下，普通读取也不承诺文件系统访问时间元数据不变。

仅当所给观察为两处原字节、没有 FLASH 历史、操作者确认未启动更新与健康状态、卡证据完整时，才标记可交给独立取消审查。该标记不会清除 journal、恢复 RAM 或开放 READY。补丁仍在、混合、未知或缺少证据时继续阻塞；实际 SDK 复查、主动撤销及正式更新控制仍待接入。
