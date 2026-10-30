# 第三方参考

这些项目由原维护者持有，本仓库不复制其固件、密钥或完整源码。使用第三方代码时须遵守其许可证。以下 SHA 是本地研究使用的版本，不表示上游最新版本。

| 项目 | 用途 | 本地固定版本 |
|---|---|---|
| [ma1co/Sony-PMCA-RE](https://github.com/ma1co/Sony-PMCA-RE) | 普通 USB / 服务协议参考 | `a82f5baaa8e9c3d9f28f94699e860fb2e48cc8e0` |
| [DavidBuchanan314/fwtool.py](https://github.com/DavidBuchanan314/fwtool.py/tree/a7iv) | CXD90057 固件解包参考 | `3955d7890fc38daf942bb52827599bfe35de4a14` |
| [Erlla/sony-a7m4-custom-firmware](https://github.com/Erlla/sony-a7m4-custom-firmware) | A7 IV 补丁、封装及临时菜单窗口研究 | `caa29145644e1d7d0a41cef1e42f0c53368bd025` |

本地布局包括 `Sony-PMCA-RE/`、`ref/`、`local/`、`output/`。它们被 Git 忽略，不会随克隆获得。设备执行需要另行准备合法取得的输入、核对固定哈希并完成相应实机验证；仓库不自动下载或替用户准备固件、密钥和设备备份。

## 新增观察项目

| 项目 | 观察范围 | 最近核查的远端版本 |
|---|---|---|
| [16480000/sony-a7iv-qemu](https://github.com/16480000/sony-a7iv-qemu) | A7M4 6.02 原厂 AP、菜单、显示、输入、虚拟 CP 与声音模拟；跟踪代码、Issue、PR、标签和发行 | `main` · `3637f15da850bea406bacd755381020b511b3867`，2026-10-30 |

后续仓库更新核查包括此项目。该记录是观察基线，不表示已将上游代码接入本项目，也没有创建自动订阅任务。本次远端 Issue、PR 与 GitHub Releases 列表为空。

深入研究时分别核对原厂 AP 执行、虚拟 CP 替身、浏览器声音和网页拍照。网页生成 JPEG、虚拟卡写入或界面显示不能证明真实 ISP、CP、LUT 色彩、快门声音和真机安装通过。

源码路径、已核对的同版菜单锚和复现限制见 [A7 IV QEMU 研究笔记](native/M4_QEMU_NOTES.md)。
