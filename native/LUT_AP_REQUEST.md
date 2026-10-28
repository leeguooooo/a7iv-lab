`lut_ap_request.c` 把已核对的本地导入序列对象转换为调用者拥有的 320 字节请求。没有注册、改写或调用真实 AP 菜单回调，也不读取文件、保存或发布到 CP。

适用对象仅为 `model::sequence_cube_file_copy`，原虚拟入口 `0x31a1270`，复制主体 `0x31a0998`。源指令核对的对象尺寸为 `0x2c0`，字段为：卡号 `+0x18`、两卡数据 `+0x1c`、64 字节文件名 `+0x16c`、目标 LUT 枚举 `+0x1ac`。原入口只检查 signed enum > 2；本模块只接受 User1–User16（3–18）。远程复制与嵌入 LUT 对象不使用这个布局。

调用者必须持有存活、不可变的对象，并事先完成 AP 身份、装载偏移和映射指令核验。参数中的 expected vtable 只用于类型一致性比较，不是来源证明。当前还没有实现真实 AP 发现和启动绑定。

请求包含独立文件名、卡号、目标槽、前端请求 ID 和归一化媒体快照。仅复制媒体路径选择需要的盘符与类型；其余未解析字节清零，不把原生媒体块里的未知内容留到工作线程。捕获成功后，原对象的字节被改写也不会改变请求。

选择时与当前的媒体代次必须由实际 AP 前端事件生命周期提供，且非零、相等；本模块不从未知字段推测代次，也不以请求 ID 冒充媒体代次。排队、取消和发布前的再检查仍需接入。失败时结果保持不变；输出与原对象重叠会拒绝。

7 项主机 C 测试通过。AArch64 联合重放把原虚拟入口的重路径拦截，再运行新捕获、媒体读取和数据模块；原对象覆盖、未解析字段清零、过期捕获及原厂 payload 摘要均已检查。媒体事件和 raw Fsys 仍是替身，未执行原复制主体、C++ 析构或实际 GUI/读卡。

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p test_lut_ap_request.py -v
python3 tools/build_lut_data_native.py \
  --zig local/zig-aarch64-macos-0.15.2/zig \
  --output output/lut-data-aarch64-new --with-ap-request
```

当前组件为 `output/lut-data-aarch64-04/`，状态仍是 `OFFLINE_COMPONENT_NOT_INSTALLABLE`。前一版 03 保留用于离线比较，因会复制原始媒体块的未知字段而被 04 取代。组件没有启动钩子或实际任务调度，不可据这些测试宣称机内导入已经可用。
