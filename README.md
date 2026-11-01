# a7iv-lab

Sony A7 IV（ILCE-7M4）固件研究项目，包含离线校验工具、安装流程控制器和一个纯模拟的分步演练。

> **干净克隆不能刷机。** 仓库不含固件、密钥、相机备份和已审核的安装包，克隆后可以运行模拟和便携测试。真实固件写入跨多个分区且不是原子操作，中断后可能无法恢复，工具也不保证能回退。

## 先确认你要做什么

| 目标 | 需要什么 | 看哪里 |
|---|---|---|
| 了解安装流程和故障处理 | Python 3.11+ | [第 1 步](#第-1-步运行模拟) |
| 验证或修改代码 | Python 3.11+、`pyelftools` | [第 2 步](#第-2-步运行便携测试) |
| 准备新的候选固件 | 研究机本地资产 | [第 3 步](#第-3-步准备本地资产仅研究者) |
| 在真机上做临时演练 | 已审核计划、相机、逐步授权 | [README_WORKFLOW.md](README_WORKFLOW.md) |
| 在真机上安装 FL2、FL3 | 已封存准备包、相机、逐步批准 | [FL23_INSTALL.md](FL23_INSTALL.md) |

## 第 1 步：运行模拟

模拟不连接相机，不写存储卡，只需要标准库。

```sh
git clone https://github.com/leeguooooo/a7iv-lab.git
cd a7iv-lab
./camera-workflow steps
./camera-workflow simulate --interactive
```

`steps` 列出四个阶段的 17 个子步骤。`--interactive` 按回车逐步前进，输入 `q` 退出。

查看故障时的停止行为：

```sh
./camera-workflow simulate --scenario usb-lost
```

场景有 `normal`、`bad-package`、`wrong-body`、`usb-lost`、`ram-unknown`、`write-interrupted`、`verify-mismatch`。

正确结果：输出末尾显示模拟结果（`usb-lost` 为 `STOPPED_UNKNOWN`）和“此结果不证明实机安装成功”。退出码 0 只代表模拟运行完成。

## 第 2 步：运行便携测试

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements-analysis.txt
.venv/bin/python -m unittest discover -s tests -p 'test_camera_workflow_simulator.py'
.venv/bin/python -m unittest discover -s tests -p 'test_camera_install_journal.py'
```

不依赖本地资产的完整测试清单在 [`.github/workflows/source-checks.yml`](.github/workflows/source-checks.yml)，提交前运行这份清单。

不要在干净克隆里用 `unittest discover -s tests` 跑全部测试：很多测试需要 `output/`、`local/`、`ref/` 下的私有输入，缺失时大量报错属于预期现象。

## 第 3 步：准备本地资产（仅研究者）

以下目录被 Git 忽略，需要自行准备：

| 目录 | 内容 |
|---|---|
| `local/` | 固件和工具链，例如 Zig |
| `ref/`、`Sony-PMCA-RE/` | 第三方源码，版本见 [UPSTREAMS.md](UPSTREAMS.md) |
| `output/` | 本机备份、原生任务、安装包和操作记录 |
| `.venv-offline/` | 离线研究环境 |

只使用合法取得的输入，并核对代码中固定的哈希。缺失或不匹配时工具会拒绝执行，不要改哈希绕过。准备好后封存新计划：

```sh
./camera-workflow prepare --report output/offline-toolchain/my-reviewed-plan.json
```

`prepare` 在干净克隆里会报 `FileNotFoundError`，因为它需要上述本地资产。报告路径必须是新文件。

## 第 4 步：实机操作前检查

全部满足才继续：

- 机身是 ILCE-7M4，固件 6.02，取景、菜单、拍摄和回放正常。
- 电量充足，Slot 1 有卡，只有一个工具在操作相机。
- 已完成并核对本机备份。其他相机的备份不能替代。
- 已读完对应操作单，清楚哪些步骤不可重试。

然后选择一条路径，两者的记录不能互相代替：

- **临时演练：** 使用 `camera-workflow`，流程是 `settings → stage → window → restore`，详见 [README_WORKFLOW.md](README_WORKFLOW.md)。
- **正式安装：** 使用 `camera_install_flow.py`，详见 [FL23_INSTALL.md](FL23_INSTALL.md)。`camera-workflow` 的正式安装入口是锁定的。

一条命令只执行一个已授权的动作，核对保存的结果后再做下一步。

## 出现异常时

1. 停止，不要重试、重启或回滚。
2. 保持相机和卡的现状，不要用 Finder 或其他工具写卡。
3. 保留全部记录。`UNKNOWN` 不能改写成成功，也不能手动清除。
4. 按 [FL23_INSTALL.md 的异常章节](FL23_INSTALL.md#遇到异常时停止)处理。

## 给 AI 代理的规则

如果你是操作这个仓库的 AI，按以下规则执行：

- 默认只运行第 1、2 步。这些命令不接触设备。
- 用户说“装一下”“继续”不算授权。每个设备动作都要先说明具体动作和风险，得到用户针对该动作的明确确认。
- `--step-authorized`、`--camera-ready`、`--firmware-never-started` 等参数是操作者对现场事实的确认，你不能代为填写。不要把模板里的 `null` 批量改成 `true`。
- 遇到 `UNKNOWN`、哈希不匹配或记录缺失时停止并报告，不要重试、改哈希、改源码绕过或删除记录。
- 模拟或测试通过，都不能表述为“可以安装”或“安装成功”。
- 不要提交固件、备份、密钥、设备序列号和含绝对路径的日志。
- 操作前先读对应的操作单，以其内容和工具的实际输出为准。

## 项目现状

| 能力 | 状态 |
|---|---|
| 分步模拟、候选包哈希和 CRC 校验 | 可用 |
| 操作日志、设备租约、未知状态阻断 | 可用，有离线测试 |
| 临时 RAM 演练 | 需要本地资产；新的交接流程尚未重新做真机验收 |
| FL2、FL3 正式安装 | 独立控制器，需要已封存准备包和逐步批准 |
| LUT | 有解析和打包研究代码，尚无可安装的后端 |
| 自定义声音 | 未完成 |

## 文档索引

- [README_WORKFLOW.md](README_WORKFLOW.md)：模拟、临时演练、离线开发
- [FL23_INSTALL.md](FL23_INSTALL.md)：FL2、FL3 现场操作单
- [UPSTREAMS.md](UPSTREAMS.md)：第三方来源和版本
- [native/HOST_RUNTIME_NOTES.md](native/HOST_RUNTIME_NOTES.md)：主机集成的设计细节
- [native/M4_QEMU_NOTES.md](native/M4_QEMU_NOTES.md)：A7 IV QEMU 研究笔记

解密能力、研究密钥签名或模拟成功，都不代表 Sony 认证、设备接纳或恢复能力。
