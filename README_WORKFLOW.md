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
