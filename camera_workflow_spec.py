"""Shared walkthrough text. These are checkpoints, not device permissions."""


def action(id, title, description):
    return dict(id=id, title=title, description=description)


STEPS = (
    dict(number=1, id='prepare', title='准备与检查', description='离线材料先核对，连接后再核实现场条件。', actions=(
        action('package', '校验候选包', '核对来源、完整哈希及实际包内 CRC；校验通过不等于可安装。'),
        action('backups', '核对已有备份', '核对备份及恢复副本；物理 NOR 和实际恢复能力仍单列。'),
        action('power', '确认供电与卡槽', '操作者确认取景、菜单、供电及 Slot 1；软件不代填。'),
        action('identity', '核实机身与单一操作方', 'MSC 机身须匹配本计划，其他工具不得同时操作。'))),
    dict(number=2, id='rehearse', title='暂存与临时 RAM 演练', description='这一阶段不执行固件更新。', actions=(
        action('settings', '获取本轮设置备份', '只读采集当前设置，记录机身及计划绑定。'),
        action('stage', '暂存非更新文件', '复制候选并完整校验，保留已有 BODYDATA.DAT。'),
        action('libraries', '核对实际完整库文件', '双遍只读采集两个原库，须匹配精确基线。'),
        action('window', '执行一次临时 RAM 窗口', '独立授权后加载临时程序；只改两处 RAM 指令。'),
        action('handoff', '等待操作者重新连接', '已知服务退出后保留待连接记录；操作者重新连接并选择 MSC，再单独授权收集。'),
        action('restore', '收集 RAM 恢复证明', '读取原窗口终态，计时结束不能代替恢复证明。'))),
    dict(number=3, id='install', title='正式安装', description='当前实操入口锁定；模拟只展示流程和风险。', actions=(
        action('consent', '重新核对并确认安装范围', '正式安装需新鲜现场条件及明确授权；演练许可不外推。'),
        action('activation', '校验并激活卡内候选', '仅在正式安装条件满足后修改更新文件名；保护原包。'),
        action('new-window', '建立新的菜单窗口', '原演练窗口已结束，不能重用；实际先后衔接待实机验证。'),
        action('menu-update', '由操作者启动更新', '跨分区写入非原子；中断可能部分写入，不能自动重试。'))),
    dict(number=4, id='verify', title='回读与实际验收', description='设备提示完成不能代替内容与拍摄验收。', actions=(
        action('readback', '完整双遍回读', '重新采集 AP、CP、P1 和设置，绑定此次安装。'),
        action('content', '核验内容与设置', '核对目标内容和关键设置；不把模型资料当硬件结果。'),
        action('shooting', '照片与视频验收', '确认取景、菜单、照片及视频；LUT 与声音另行验收。'))),
)

SCENARIOS = {
    'normal': '正常模拟流程（不代表工具已获实机验证）',
    'bad-package': '候选包校验失败',
    'wrong-body': '连接了另一台相机',
    'usb-lost': '请求发出后 USB 中断',
    'ram-unknown': '缺少 RAM 恢复终态',
    'write-interrupted': '安装中断，可能部分写入',
    'verify-mismatch': '回读内容不匹配',
}
