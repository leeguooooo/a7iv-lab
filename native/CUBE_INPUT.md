`cube_input.c` 提供机内导入所需的纯数据处理。当前在电脑上编译验证，还没有合入 AP/CP，也没有连接相机。它不会打开文件、挂载介质、发布当前 LUT 或修改固件。

| 接口 | 作用 |
|---|---|
| `camera_cube_parse` | 严格读取整数尺寸的 3D CUBE，保留 DOMAIN，拒绝缺行、多行、重复/未知指令及非有限数值；输入上限 65 点、32 MiB |
| `camera_cube_sample` | 按指定 DOMAIN 做三线性插值；不推断 gamma、色域或输入颜色空间 |
| `camera_cube_resample` | 在独立临时区生成输入域为 0–1 的 17/33 点表；越界默认拒绝，显式夹取时统计节点数 |
| `camera_cube_pack_ap_integer` | 生成已审原厂整数路径的 48,000 字节数据；量化为 uint16 Q13，三通道/八 bank/每 bank 10×10×10；输出超范围默认拒绝，显式饱和时统计有效组件数 |

行顺序为 R 最快、G 次之、B 最慢。原厂整数路径每轴只有 17 个有效节点，33 点输入只取偶数节点；本模块没有把这一路径改成真正的 33 点硬件网格。65 点是输入数据的处理上限，需要先重采样。1D/1D+3D 组合 LUT 当前会明确拒绝。

推荐的数据调用顺序是：读取候选字节到自有缓冲 → parse 到临时浮点表 → 确认输入颜色空间合同 → resample 到独立临时区 → pack 到独立字节缓冲 → 由尚未接入的事务层保存并发布。成功前不得替换活动 LUT。源缓冲在调用过程中必须保持不变。

parse/resample 失败时临时区可能改变，结果元数据不会提交。sample 失败不改变输出。pack 会在写入前检查完整源数据、容量、DOMAIN、策略和缓冲重叠。临时区不能与活动表复用；C 接口无法验证调用者是否真正拥有传入的内存。

DOMAIN 重采样只处理坐标范围，不会把 S-Log3、S-Gamut3.Cine、sRGB 等输入互相转换。将视频 Log LUT 直接套到未知照片管线会改变颜色语义；输入颜色空间与真实消费者的合同尚未建立。重采样和量化也不保证任意 LUT 的逐像素等价。

测试命令：

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p test_cube_input.py -v
```

测试使用主机 C 编译器，在临时目录构建库并清理。原厂数据格式参考来自 `output/a7m4-cube-integer-packing-review.json` 中绑定的原指令重放；当前测试对其中 identity 和非对称表的摘要做独立比较。原文件读取及存储模型分别见 `output/a7m4-cube-file-reader-review.json`、`output/a7m4-lut-store-control-review.json`。

仍需完成：AP 菜单和 SD 文件入口、颜色空间合同、保存/发布与回滚、CP/ISP 消费者接线、预览和照片对比、原有外观回归、重启恢复、完整固件构建及真实机身验收。不得据本模块的主机测试宣称相机已支持自定义 LUT。
