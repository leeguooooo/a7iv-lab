"""Pure synthetic timelines; no SDK, subprocess, filesystem or device operations."""
import builtins
import contextlib
import copy
import importlib
import io
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

import camera_workflow_simulator as simulator


class SimulationTests(unittest.TestCase):
    def test_normal_four_steps_are_explicitly_only_models(self):
        result = simulator.simulate()
        self.assertEqual(result['schema'], 'camera-workflow-simulation/1')
        self.assertEqual([row['id'] for row in result['steps']], ['prepare', 'rehearse', 'install', 'verify'])
        self.assertEqual([row['number'] for row in result['steps']], [1, 2, 3, 4])
        self.assertEqual([row['status'] for row in result['steps']], ['passed'] * 4)
        self.assertEqual(result['terminal_state'], 'SIMULATED_CONTENT_VERIFIED')
        self.assertTrue(result['simulated'])
        self.assertEqual(result['hardware_operations'], 0)
        self.assertFalse(result['installation_authorized'])
        self.assertFalse(result['firmware_installation_proven'])
        self.assertTrue(result['steps'][2]['model_only'])
        self.assertEqual([len(row['actions']) for row in result['steps']], [4, 6, 4, 3])
        self.assertTrue(all(action['status'] == 'passed' for row in result['steps'] for action in row['actions']))
        self.assertTrue(all('模拟' in event for row in result['steps'] for event in row['events']))

    def test_each_fault_stops_at_the_expected_step_without_later_requests(self):
        expected = {'bad-package': 1, 'wrong-body': 2, 'usb-lost': 2, 'ram-unknown': 2,
                    'write-interrupted': 3, 'verify-mismatch': 4}
        for scenario, number in expected.items():
            with self.subTest(scenario=scenario):
                result = simulator.simulate(scenario)
                rows = result['steps']
                self.assertEqual(rows[number-1]['status'], 'failed')
                self.assertTrue(all(row['status'] == 'passed' for row in rows[:number-1]))
                self.assertTrue(all(row['status'] == 'blocked' for row in rows[number:]))
                self.assertTrue(all('模拟请求' not in event for row in rows[number:] for event in row['events']))
                self.assertFalse(result['automatic_retry'])
                self.assertFalse(result['automatic_rollback'])
                self.assertEqual(result['hardware_operations'], 0)
                self.assertFalse(result['installation_authorized'])
                self.assertFalse(result['firmware_installation_proven'])
                self.assertTrue(rows[2]['model_only'])

    def test_unknown_outcomes_have_no_requests_after_unknown_marker(self):
        for scenario in ('usb-lost', 'ram-unknown', 'write-interrupted', 'verify-mismatch'):
            with self.subTest(scenario=scenario):
                result = simulator.simulate(scenario)
                self.assertEqual(result['terminal_state'], 'STOPPED_UNKNOWN')
                events = [event for row in result['steps'] for event in row['events']]
                unknown = next(index for index, event in enumerate(events) if 'STOPPED_UNKNOWN' in event)
                self.assertTrue(all('模拟请求' not in event for event in events[unknown+1:]))

    def test_wrong_body_has_no_request_in_rejected_step(self):
        result = simulator.simulate('wrong-body')
        self.assertIn('NO_DEVICE_OPERATION', result['terminal_state'])
        self.assertTrue(all('模拟请求' not in event for event in result['steps'][1]['events']))

    def test_results_do_not_share_mutable_objects_or_change_spec(self):
        before = copy.deepcopy(simulator.STEPS)
        first, second = simulator.simulate(), simulator.simulate()
        first['steps'][0]['events'].append('changed')
        first['steps'][0]['title'] = 'changed'
        first['steps'][0]['actions'][0]['description'] = 'changed'
        first['steps'][0]['actions'].clear()
        first['steps'].pop()
        self.assertEqual(second, simulator.simulate())
        self.assertEqual(before, simulator.STEPS)
        failed = simulator.simulate('usb-lost')
        failed['steps'][1]['events'].clear()
        self.assertTrue(simulator.simulate('usb-lost')['steps'][1]['events'])

    def test_faults_do_not_mark_unreached_actions_completed(self):
        for scenario, phase, action in (
            ('bad-package', 0, 'package'), ('usb-lost', 1, 'window'),
            ('ram-unknown', 1, 'restore'), ('write-interrupted', 2, 'menu-update'),
            ('verify-mismatch', 3, 'content')):
            with self.subTest(scenario=scenario):
                result = simulator.simulate(scenario)
                actions = result['steps'][phase]['actions']
                failure = next(index for index, row in enumerate(actions) if row['id'] == action)
                self.assertEqual(actions[failure]['status'], 'failed')
                self.assertTrue(all(row['status'] == 'passed' for row in actions[:failure]))
                self.assertTrue(all(row['status'] == 'not_simulated' for row in actions[failure+1:]))
                self.assertTrue(all(row['status'] == 'not_simulated'
                    for step in result['steps'][phase+1:] for row in step['actions']))
        wrong = simulator.simulate('wrong-body')
        self.assertTrue(all(action['status'] == 'not_simulated'
                           for step in wrong['steps'][1:] for action in step['actions']))

    def test_unknown_or_unhashable_scenario_is_rejected(self):
        for value in ('unknown', '', None, [], {}):
            with self.subTest(value=value):
                with self.assertRaises(ValueError): simulator.simulate(value)

    def test_import_and_all_scenarios_never_import_hardware_or_call_io(self):
        original_import = builtins.__import__
        def guarded_import(name, *args, **kwargs):
            if name.startswith(('pmca', 'usb', 'camera_')) and name != 'camera_workflow_spec':
                raise AssertionError('Hardware dependency imported: ' + name)
            return original_import(name, *args, **kwargs)
        with patch('builtins.__import__', side_effect=guarded_import), \
                patch.object(subprocess, 'run', side_effect=AssertionError('subprocess')), \
                patch.object(subprocess, 'Popen', side_effect=AssertionError('subprocess')), \
                patch.object(subprocess, 'check_output', side_effect=AssertionError('subprocess')):
            importlib.reload(simulator)
            with patch('builtins.open', side_effect=AssertionError('filesystem')), \
                    patch.object(os, 'open', side_effect=AssertionError('filesystem')), \
                    patch.object(Path, 'read_text', side_effect=AssertionError('filesystem')), \
                    patch.object(Path, 'write_text', side_effect=AssertionError('filesystem')):
                for scenario in simulator.SCENARIOS:
                    self.assertEqual(simulator.simulate(scenario)['hardware_operations'], 0)

    def test_cli_prints_chinese_simulation_steps_without_saving(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), \
                patch('builtins.open', side_effect=AssertionError('filesystem')):
            result = simulator.main(['--scenario', 'usb-lost'])
        text = output.getvalue()
        self.assertIn('硬件操作 0 次', text)
        self.assertIn('1. ', text)
        self.assertIn('17. ', text)
        self.assertIn('未模拟', text)
        self.assertIn('STOPPED_UNKNOWN', text)
        self.assertFalse(result['installation_authorized'])
