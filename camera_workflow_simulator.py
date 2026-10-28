"""Synthetic four-step rehearsal. No device, filesystem, journal or SDK access."""
from camera_workflow_spec import STEPS, SCENARIOS

# Tuples contain only immutable scalar text. Each call creates its own containers.
_NORMAL_EVENTS = {
    'prepare': (
        '模拟：检查方案、候选包、机身绑定和操作许可。',
        '模拟：准备检查通过；未执行任何硬件操作。',
    ),
    'rehearse': (
        '模拟请求：将候选文件暂存为相机不识别的名称，保留原 BODYDATA。',
        '模拟请求：开启临时 RAM 窗口；收到补丁观察记录。',
        '模拟请求：已知成功退出后，确认同一机身回到正常模式。',
        '模拟请求：读取原窗口的完整恢复记录，两处 RAM 恢复检查通过。',
        '模拟：演练结束；倒计时和重启均不构成恢复证据。',
    ),
    'install': (
        '模拟：本步骤仅为模型时间线，model_only=True；没有真实安装许可。',
        '模拟请求：确认 Slot 1 后排他备份原 BODYDATA，再激活候选文件名。',
        '模拟请求：记录可能开始写入，再执行正式安装流程。',
        '模拟：收到设备完成报告；完成报告尚不能证明内容正确。',
    ),
    'verify': (
        '模拟请求：回读安装后的目标内容，并核对预期摘要。',
        '模拟：内容比对通过；这不是实机安装或摄影功能证明。',
    ),
}

# stage id, terminal state, replacement events. Later steps are locally blocked.
_FAILURES = {
    'bad-package': ('prepare', 'LOCAL_PACKAGE_REJECTED', (
        '模拟：候选包摘要与固定方案不符。',
        '模拟：本地拒绝，硬件请求为零。',
    )),
    'wrong-body': ('rehearse', 'LOCAL_BODY_REJECTED_NO_DEVICE_OPERATION', (
        '模拟：只比较合成机身身份，发现与方案绑定不符。',
        '模拟：在操作前拒绝，硬件请求为零。',
    )),
    'usb-lost': ('rehearse', 'STOPPED_UNKNOWN', (
        '模拟请求：开始临时 RAM 窗口操作。',
        '模拟：USB 在请求后断开，无法确认结果。',
        '模拟：STOPPED_UNKNOWN；从此不发送后续请求，不自动重试或回滚。',
    )),
    'ram-unknown': ('rehearse', 'STOPPED_UNKNOWN', (
        '模拟请求：开启临时 RAM 窗口，随后读取原窗口恢复记录。',
        '模拟：恢复记录缺失或不能证明两处 RAM 安全。',
        '模拟：STOPPED_UNKNOWN；不能用等待或重启推断恢复。',
        '模拟：从此不发送后续请求，不自动重试或回滚。',
    )),
    'write-interrupted': ('install', 'STOPPED_UNKNOWN', (
        '模拟：本步骤仅为模型时间线，model_only=True；没有真实安装许可。',
        '模拟请求：记录可能开始写入，然后开始正式安装。',
        '模拟：写入期间连接中断，可能只写入了一部分。',
        '模拟：STOPPED_UNKNOWN；从此不发送后续请求，不自动重试或回滚。',
    )),
    'verify-mismatch': ('verify', 'STOPPED_UNKNOWN', (
        '模拟请求：回读安装后的内容并比较摘要。',
        '模拟：回读内容与预期不符，验收未通过。',
        '模拟：STOPPED_UNKNOWN；从此不发送后续请求，不自动重试或回滚。',
    )),
}


_FAILURE_ACTION = {
    'bad-package': 'package', 'wrong-body': None, 'usb-lost': 'window',
    'ram-unknown': 'restore', 'write-interrupted': 'menu-update', 'verify-mismatch': 'content',
}


def _actions(reference, scenario, phase_status):
    values = []
    failed_at = _FAILURE_ACTION.get(scenario)
    reached_failure = False
    for source in reference['actions']:
        row = dict(id=source['id'], title=source['title'], description=source['description'])
        if phase_status == 'blocked' or (phase_status == 'failed' and (failed_at is None or reached_failure)):
            row['status'] = 'not_simulated'
        elif phase_status == 'failed' and row['id'] == failed_at:
            row['status'] = 'failed'
            reached_failure = True
        else:
            row['status'] = 'passed'
        if reference['id'] == 'install':
            row['model_only'] = True
        values.append(row)
    return values


def simulate(scenario='normal'):
    """Return independent JSON-compatible containers, never hardware evidence."""
    if not isinstance(scenario, str) or scenario not in SCENARIOS:
        raise ValueError('未知模拟场景')
    if scenario != 'normal' and scenario not in _FAILURES:
        raise ValueError('模拟场景尚未实现')
    failure = _FAILURES.get(scenario)
    stopped = False
    steps = []
    terminal = 'SIMULATED_CONTENT_VERIFIED'
    for reference in STEPS:
        identifier = reference['id']
        row = dict(id=identifier, number=reference['number'], title=reference['title'],
                   status='passed', events=[])
        if identifier == 'install':
            row['model_only'] = True
        if stopped:
            row['status'] = 'blocked'
            row['events'] = ['模拟：前一步未通过，本步骤保持阻断。']
        elif failure is not None and identifier == failure[0]:
            row['status'] = 'failed'
            row['events'] = list(failure[2])
            terminal = failure[1]
            stopped = True
        else:
            row['events'] = list(_NORMAL_EVENTS[identifier])
        row['actions'] = _actions(reference, scenario, row['status'])
        steps.append(row)
    return dict(schema='camera-workflow-simulation/1', scenario=scenario,
                simulated=True, model_only=True, hardware_operations=0,
                installation_authorized=False, firmware_installation_proven=False,
                automatic_retry=False, automatic_rollback=False,
                steps=steps, terminal_state=terminal)


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description='四阶段、17个子步骤模拟；不连接相机，不执行安装。')
    parser.add_argument('--interactive', action='store_true', help='每个子步骤等待回车；输入q退出模拟')
    parser.add_argument('--scenario', choices=tuple(SCENARIOS), default='normal',
                        help='模拟场景：' + '；'.join(str(key)+'='+str(value) for key, value in SCENARIOS.items()))
    args = parser.parse_args(argv)
    result = simulate(args.scenario)
    labels = {'passed': '模拟通过', 'failed': '模拟失败', 'blocked': '已阻断', 'not_simulated': '未模拟'}
    print('仅模拟：硬件操作 0 次，安装许可关闭。')
    action_number = 0
    for row in result['steps']:
        print('阶段 ' + str(row['number']) + '：' + row['title'] + '（' + labels[row['status']] + '）')
        for action in row['actions']:
            action_number += 1
            if args.interactive:
                answer = input(f'回车查看第{action_number}步，q退出模拟：').strip().lower()
                if answer == 'q':
                    result['terminal_state'] = 'SIMULATION_ABORTED'
                    result['interactive_walkthrough_completed'] = False
                    print('已退出模拟。没有连接设备或执行安装。')
                    return result
            print(str(action_number) + '. ' + action['title'] + '：' + labels[action['status']])
            print('   ' + action['description'])
        for event in row['events']:
            print('   ' + event)
    print('模拟结果：' + result['terminal_state'])
    print('此结果不证明实机安装成功。')
    result['interactive_walkthrough_completed'] = True
    return result


if __name__ == '__main__':
    main()
