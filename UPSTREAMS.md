# 第三方参考

这些项目由原维护者持有，本仓库不复制其固件、密钥或完整源码。使用第三方代码时须遵守其许可证。以下 SHA 是本地研究使用的版本，不表示上游最新版本。

| 项目 | 用途 | 本地固定版本 |
|---|---|---|
| [ma1co/Sony-PMCA-RE](https://github.com/ma1co/Sony-PMCA-RE) | 普通 USB / 服务协议参考 | `a82f5baaa8e9c3d9f28f94699e860fb2e48cc8e0` |
| [DavidBuchanan314/fwtool.py](https://github.com/DavidBuchanan314/fwtool.py/tree/a7iv) | CXD90057 固件解包参考 | `3955d7890fc38daf942bb52827599bfe35de4a14` |
| [Erlla/sony-a7m4-custom-firmware](https://github.com/Erlla/sony-a7m4-custom-firmware) | A7 IV 补丁、封装及临时菜单窗口研究 | `caa29145644e1d7d0a41cef1e42f0c53368bd025` |

本地布局包括 `Sony-PMCA-RE/`、`ref/`、`local/`、`output/`。它们被 Git 忽略，不会随克隆获得。设备执行需要另行准备合法取得的输入、核对固定哈希并完成相应实机验证；仓库不自动下载或替用户准备固件、密钥和设备备份。
