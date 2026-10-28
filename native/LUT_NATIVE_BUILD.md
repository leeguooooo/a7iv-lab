数据、保存、媒体、本地请求捕获和选择失败防护模块已经交叉编译为 Linux/AArch64 共享库，适配基线为 glibc 2.25。产物只在电脑上；未上传、加载或合入相机固件。当前版本提供 14 个 `camera_*` 接口，没有 AP 启动绑定、菜单注册、CP 发布适配器或自定义声音功能。

当前离线组件为 `output/lut-data-aarch64-05/libcamera_lut_data.so`，99,952 字节，SHA-256 为 `8f47baf9688e473d466a4697356df3df1a062af33ff8b3389ed931c000885d3b`。十份 C 源/头文件、编译器和参数已绑定在同目录 manifest.json。01/02/03 作为较早离线记录保留；03 的不透明媒体块复制已由 04 的归一化捕获取代。复现必须选择新的输出目录：

```sh
python3 tools/build_lut_data_native.py \
  --zig local/zig-aarch64-macos-0.15.2/zig \
  --output output/lut-data-aarch64-new --with-ap-request --with-select-guard
```

| 已核对 | 证据与范围 |
|---|---|
| 正常系统来源 | 官方 nfa3 镜像的 FAT → INITRD.IMG 内 ext2 → libc-2.25.so/libpthread-2.25.so；未用更新器运行库替代 |
| 依赖 | 21 个实际导入的名字、提供库和 GLIBC_2.17 版本均在上述正常系统库中匹配 |
| ELF | AArch64 ET_DYN、入口为 0、没有同时可写可执行的 LOAD、栈不允许执行；无测试故障注入导出 |
| 结构 | 编译目标的 stat 为 128 字节，st_mode/st_size 偏移为 16/48，与缓存 Sony AArch64 内核 UAPI 一致；公开数据接口结构与主机测试类型一致 |
| stat 适配 | 组件自带的本地 fstat 包装以版本 0 尾调用 __fxstat；正常 libc 的该入口接受版本 0 并直达 syscall 80 |
| 目标代码重放 | 在 Unicorn 中实际运行新编译的数据接口；公开 33 点 CUBE 的 payload 与原厂读取器重放一致，记录与主机独立进程恢复结果一致；坏 CRC 拒绝 |

CPU 重放把内存/字符串 libc 调用替换为模型；文件、锁、分配和设备接口调用会直接拒绝，未执行目标保存函数。没有在主机 OS 加载相机运行库，也没有真实 syscall 或设备操作。

静态依赖、结构和 CPU 重放通过，仍不等于 AP 能加载或机内操作可用。真实加载、线程上下文、目录权限、VFAT 同步/锁及空间、菜单/SD 入口、CP 资源生存期与画面输出还要逐项完成。此库不是可安装固件，不能用原厂 `.LUT` 入口直接消费保存记录。

证据保存在该产物目录的 normal-runtime-symbol-audit.json、structure-abi-audit.json、data-api-replay.json、media-api-replay.json、ap-request-replay.json 、select-guard-api-replay.json 和 admission.json。源码接口见 [CUBE_INPUT.md](CUBE_INPUT.md)、[LUT_STORE.md](LUT_STORE.md)、[LUT_MEDIA.md](LUT_MEDIA.md)、[LUT_AP_REQUEST.md](LUT_AP_REQUEST.md)。

05 的选择失败防护调用原厂 send_lut 指令的12组目标重放通过，加载、传送和配置出口是替身。选择函数表为16字节、结果为24字节，字段偏移与主机类型一致。CONFIG_REQUESTED 只表示配置辅助函数返回1，不是CP确认或画面验收。04保留比较，二者都不可安装。源码接口另见 [LUT_SELECT_GUARD.md](LUT_SELECT_GUARD.md)。

当前后端限制：原厂参考配置路径 `3503b44 → 35a338c/35999dc → 35e7a78/35bf0e4` 在 stock 和离线 FL23 AP 中均为空实现，原指令重放确认它们只清零状态并返回。禁止把此路径当作可激活用户LUT的后端；05只提供控制防护。详见 `output/a7m4-lut-config-noop-review.json`。这不排除其他ISP LUT路径；仍须建立真实兼容配置接口、生命周期和回执，不能因helper返回1或菜单可见便宣称机内生效。
