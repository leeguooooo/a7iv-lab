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

未来执行临时演练时，需使用已审核的计划文件及其完整 SHA。每个设备动作都要求独立的 `--authorize-step`、`--camera-ready`、`--firmware-never-started`，暂存还要求 `--slot1-confirmed`。这些参数是操作者确认，不是软件自行获得的授权或现场检测。当前无需运行设备命令。

临时演练会加载用户态程序并写临时文件，只改两处 RAM 指令；不启动固件更新。已知服务退出不等于恢复成功，倒计时结束也不能代替原窗口的恢复记录。遇到未知结果会保留意图和部分证据，阻断后续步骤，不自动重试、回滚、STOP 或重启。完整更新涉及非原子写入，工具无法保证断电后恢复。
