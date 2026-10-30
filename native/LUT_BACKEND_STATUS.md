当前没有可安装的 LUT 激活后端。05 组件提供解析、打包、保存、媒体读取、请求捕获和同步错误防护；尚未接入设备。

`output/lut-genuine-entry-design-20261031/` 新增了预留内核端点的内部C数据持有原型。10项编译A64检查及2项原始内核检查通过，两次构建一致。测试生成非identity的17点CUBE，经原C解析和打包得到48000字节，再经过新组件、原厂API和队列，进入48个描述符。该结果是CPU模型中的CUBE字节流，不是实际SD读卡、内核模块接入或照片/视频色彩验收。

原型在首次调用前锁定数据；返回、超时及晚回调均不释放、覆盖或再次提交。这个单次保留边界不等于正常重复导入已完成。正式配置在申请backing和调用native之前拒绝；实际UAPI、模块装载、连续direct-map分配、回调代码及上下文引用尚未实现。原始内核`module_alloc`走vmalloc的调用边已核对，不能把普通模块BSS当作连续DMA缓冲。共享L3D写者、请求归属及硬件完成合同仍须闭合。

`output/l3d-native-irq-binding-20261031/run.py` 的14项原始指令检查恢复了channel5的IRQ183注册、LIRO trampoline及Linux IRQ flow。在明确的描述符和CPU上下文替身下，回调沿硬IRQ路径执行；不能在其中等待自身IRQ或使用睡眠锁。初始化返回0的反例只绑定57项，而非58项，因此还须核对实际绑定。

原始`dis_int/ena_int/clr_pic`只操作GIC，不等待回调结束；`synchronize_irq(183)`的原始软件等待链已重放，但它不排空72字节任务队列、worker超时/错误回调或DMA。原诊断代码还会忽略channel5申请失败后继续启动该通道，分配标志不能作为独占能力。正常重复导入需要同时协调native worker、所有已准入写者、IRQ和硬件最后读取，不能只加一个IRQ同步调用。

`output/l3d-output-domain-20261031/run.py` 的17项原始A64模型及1项静态关联检查进一步区分数据加载与激活：所查48000字节CPU加载路径没有显式编程独立的flow/on-off控制。原厂另有控制API写入`F3019010`、`F3019400/9410/9414`。StillCapture与VDT周边确实共用VFX传输原语，但具体MLUT实例、effect/flow及输出buffer到JPEG和录像编码器的链路仍未闭合。既不能据此证明照片/录像生效，也不能只凭MLUT名字判为仅监看。

`output/feature-acceptance-assets-20261031/` 已准备identity、红蓝互换及反色CUBE和静态光学测试靶，供后端就绪后的相机原始JPEG及离机解码录像A–B–A比较。素材经现有C解析/打包检查，但没有复制到SD或进行相机采集；这些输入素材不是效果或安装证据。

`output/l3d-capture-buffer-lineage-20261031/run.py` 的5项原始指令边界检查又确认：给定全部空闲的fixture时，StillCapture的VFX自动选择先用`F3000000`、再用`F3100000`、最后才用`F3010000`。这不是当前相机资源分配的观测。另一路实际DMM解析、JPEG参数和地址映射将独立源地址传到合成JPEG输入寄存器，但没有执行完整编码器。VFX的Capture字段`+334`与JPEG的`+41C/+344/+348`是否指向同一帧仍未知，不能把两个分别成功的边界拼成完整LUT照片路径；录像链也未闭合。

`output/readonly-runtime-identity-20261031/` 已准备固定proc/sysfs采集worker、原样bootstrap和纯解码器；独立重建二进制一致，22个worker、15个损坏记录拒绝及18个bootstrap模型场景通过。启动方案仅数据、审批模板为空，尚无SDK执行器。它不加载模块、不操作MMIO/DMA或相机设置；临时job写入及固定SDK上传文件清理仍需独占租约和归属证据。当前没有实机身份、IRQ、地址或路由观测，不能由nonce或采集文件本身推导物理来源与准入。

| 已核对的路径 | 当前证据 | 仍缺的部分 |
|---|---|---|
| A7 IV AP 原选择配置 | `3503b44` 的两个实现为空，仅清零状态返回 | 不能当作激活后端 |
| FX2 新请求 | 存在真实实现；A7 IV 所查接收表的同编号含义/负载不同 | 完整命名空间、目标协议与接收能力 |
| A7 IV CP `SendVDF_SetMonitorLut` | 内部12字节请求/回复与错误映射已重放 | AP入口、任意3D数据支持；原无限等待不能照用 |
| AP侧 AV-CAM L3D接口 | 实际校验IP0、48000字节，构造带指针/回调的72字节任务 | 格式兼容、异步消费者、资源所有权、用户态桥接与画面验收 |

AV-CAM 由 LIRO 加载，使用 LIRO 复制的 OSAL 接口表。已核对 Linux 内核线程直接调用映像入口的静态链；当前启动的实际映射和初始化结果尚未观察。高链接地址不能直接作为05组件的用户态函数指针；内核调用也须先验证实际映射、初始化及缓冲所有权。纯数据解析仍留在用户态，不直接传递用户指针。

`2ac4a8` 只校验目标类型及长度。`2b5090` 复制72字节任务描述符，其中 `+0x10` 是回调、`+0x20` 是数据指针，随后经 `osal_snd_msg` 提交。在其分配失败路径中，函数也返回0而没有提交；提交失败则返回-20。因此返回0不证明入队、消费或写入。缓冲区释放、超时与重试必须等待消费者及回调合同闭合，不能据返回码自动推断。

源码中可见24段各2000字节的测试复制，与48000字节长度相符；测试源以 `3d003000/3d003004` 等图样开始。它不是identity色彩金样，不能仅据分bank形状认定当前AP Q13打包已与该驱动兼容。当前只找到调试包装的一个直接调用，没有证明普通用户态或GUI可达。

可复跑证据：

- `output/replay-a7m4-lut-config-noop.py`
- `output/compare-a7m4-fx2-lut-config.py`
- `output/replay-a7m4-cp-monitor-lut.py`
- `output/replay-a7m4-avcam-l3d-api.py`
- `output/replay-a7m4-avcam-l3d-queue.py`

这些程序只读取本地固件，在模拟器中执行所查原指令；所有硬件/消息出口均未执行。它们不连接相机，不是设备诊断执行器或安装工具。完整目标仍是 FL2/FL3、SD卡自定义CUBE导入及自定义快门声音，不能用内置Gamma Assist或离线转换替代。

消费者现已定位：`2b485c` 收取队列消息，`2b4918` 按任务类型分发，type1到`2b4b04`，经`2b51cc`构造bank源段、`2b4b5c`准备后续描述符，最后由`2b4d88`启动边界并等待。原指令核对确认三个序号各8个bank，每个2000字节，合计覆盖48000字节一次。每个bank另有选择记录，共48个源记录；下游描述符及完成路径见后文。

当前 C 打包器与原 AP `313936c` 在 identity 和非对称两组17点预量化数据上逐字节一致，随后交给原 `2b51cc` 源段构造器验证。脚本 `output/l3d-bridge-expansion-20261030/replay_ap_to_l3d_segments.py` 与 `byte_contract.json` 保存完整输入哈希、结果和替身范围。这闭合的是 CPU 字节布局与源段寻址，尚未证明硬件对 Q13、节点或色彩通道的解释，也没有证明照片、视频生效。

已另外定位原厂用户态 `libosal_uipc.so::u_osal_snd_msg` 的 `/dev/uipc` ioctl 边界，以及 LIRO 所复制的内核 `osal_snd_msg` 回调。对应审计在 `output/liro-userspace-route-20261030/`。具体 selector、消息与 L3D 分发链仍未恢复，不能将 LIRO 的高地址入口作为普通用户态函数指针调用。

2026-10-31 的只读审计补齐了64位 `unlocked_ioctl → UDIF → UIPC` 回调边。恢复符号的内核 ELF 唯一非空 PT_LOAD 全部6,610,952字节与原始 normal-vmlinux.bin 一致；实际函数指针、调用指令及 UIPC 模块重定位共同约束这条链。对应的 compat_ioctl 槽为 NULL，本证据不外推全部32位行为。可复跑脚本和11项输入哈希保存在 `output/m4-udif-l3d-edge-20261031/audit.py` 与 `audit.json`。

同次审计核对 LIRO 接口对象的 `+0x48` 偏置，定位 DebugMonitor 动态队列注册和 `mlut` 调试命令。`0xbe` 是动态分配标签，不是可直接发送的目的地。原 `mlut` 包装器只解析 IP 和 size，再复制24段内置数据到固定48KB缓冲；它不读取任意 CUBE 指针或文件。内核接口连通证据、原厂内置调试命令与可用的 SD CUBE 激活后端仍是不同的完成条件。

`output/liro-execution-mapping-20261031/audit.py` 另固定13项输入，核对四个文件与自有原厂 ext2 映像逐字一致。原 im.elf 从 `Backup_read(00fa007c)` 构造模块 `adr` 参数；LIRO 以 `(adr-memstart_addr)|0xffffffc000000000` 转换地址，并在 Linux kthread 中直接调用 ORIL 头内的入口。所查加载路径不重基址这些已链接指针。原内核文件中 memstart_addr 的初值是 UINT64_MAX，不能拿它当当前内存起点。

既有本机设置捕获的容器0给出 `adr=0x401000000`，容器1为 UINT64_MAX；原 getter 的活动容器和当前启动 memstart 未观察。`/sys/module/liro/parameters/adr` 的0444权限已由模块参数记录核对，但路径存在与当前初始化成功仍待只读现场检查。同映像 UIPC 的真实导出表包含三个对应 OSAL API，尚未观察运行时提供者绑定或 DebugMonitor 实际目的地。

`output/debugmonitor-sender-20261031/audit.py` 核对了目的地发布与原厂发送者：DebugMonitor把动态分配得到的完整ID放在command6的`+4`，label放`+2`，发布给ULOG `0x008f0139`。原厂ulogio从选中终端记录取完整ID、复制输入文本后发送。106条原指令断言及12个原厂ext2文件回查通过。`0x800e`只查询当前共享选择，`0x800d`会改选择；尚无任意label的无副作用查询证明。这恢复了真实控制路径，不是任意CUBE数据接收端，也没有观察当前选择或注册状态。

错误回调不能当作可释放证明。`2b4d88` 的超时分支会调用client(-7)，所查函数内没有停止/取消/等待硬件静止；完成入口`2b4fd8`使用同一全局回调槽，模拟的晚完成能再次通知或命中新替换回调。此为源码控制模型，未证明真实设备上的时间竞态，也未排除底层额外保证。释放必须有实际完成/静止及归属证据；超时须保留资源，不自动重试。

`output/l3d-native-lifetime-followup-20261031/audit.py` 新增7项原始A64检查，恢复48个16字节下游描述符。每对描述符分别向`F3019408`传1个选择字、向`F301C000`传500个数据字，最后一个设置bit31。实际channel5启动路径向`F10581A0`起的寄存器写描述符并启用通道；地址转换与缓存操作仍是明确替身。

原始IRQ路径`2e4bb0→2e3cdc/2e3fb8/2e3d44→2b4fd8`先清channel5 enable bit0，再写两个ack寄存器，最后读取当前全局client并回调。完整type1超时模型中，超时返回后合成enable位仍置位；替换client后到达的旧IRQ会调用新client。该证据把剩余问题缩小到pending/error位、disable及ack的硬件最后读取合同与可见性，尚不能把这些寄存器操作当作释放屏障。只增加一个回调thunk不足以解决重新启动后的旧IRQ归属。

`output/l3d-dmac-contract-20261031/audit.py` 的37项原指令检查将寄存器和描述符布局与[Linux的PL080定义](https://github.com/torvalds/linux/blob/v6.18/include/linux/amba/pl080.h)对照。原始状态函数`2e4020`检查bit18和bit0，不检查PL080所定义的Active bit17；状态0不能直接解释为FIFO已空。[ARM DDI0196G手册](https://documentation-service.arm.com/static/5e8e3c6488295d1e18d3a8c3)区分Enable、Halt与Active，并给出有条件的停止和传输结束合同。尚未读取此Sony控制器的身份信息，且原厂还写入标准配置字段外的bit24，因此这里只建立结构匹配假设，不能直接套用通用PL080停机或释放流程。

`output/avcam-l3d-queue-error-01/` 是单独离线指令修复候选，只把分配失败时的清零返回改为原错误返回。实际改1字节，5组原API+候选队列控制用例和独立指令复核通过；成功/提交失败路径不变。它不修复超时、硬件停机、颜色格式或用户态桥接，没有完成容器校验/签名/启动验证，不能安装。
