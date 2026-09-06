"""Regression checks for idle qualification and owned descendant identity accounting."""
import copy
import unittest
from unittest.mock import patch

from run_idle_cleanup import assess, owned_processes
from assess_performance import RESOURCES


class IdleCleanupTests(unittest.TestCase):
    def test_detached_reparented_descendant_remains_owned_but_reused_pid_does_not(self):
        table = {
            10: dict(pid=10, ppid=1, group=10, started='a'),
            11: dict(pid=11, ppid=10, group=11, started='b'),
            12: dict(pid=12, ppid=11, group=12, started='c'),
            13: dict(pid=13, ppid=1, group=13, started='d'),
            14: dict(pid=14, ppid=1, group=14, started='new'),
        }
        observed = {'13': dict(started='d'), '14': dict(started='old')}
        with patch('run_idle_cleanup.processes', return_value=table):
            self.assertEqual(set(owned_processes(10, observed)), {10, 11, 12, 13})

    def fixture(self):
        limits = dict(warmup_cycles=5, window_samples=3, dropped_events=0)
        limits.update({budget: 10 for budget in RESOURCES.values()})
        idle = [dict(phase='paused_idle', seconds=i * 5, capture=9, snapshot=7, ticks=33,
                     trace_bytes=100, dropped=0, **{field: 100 for field in RESOURCES})
                for i in range(25)]
        closed = [dict(phase='post_close', seconds=150 + i * 5, agent_alive=False,
                       ghidra_rss_kib=100, ghidra_threads=10, ghidra_handles=10)
                  for i in range(5)]
        report = dict(status='COMPLETED_MEASUREMENTS', samples=idle + closed,
                      surviving_owned_descendants=[])
        return report, limits

    def test_complete_fixed_idle_series_uses_declared_comparators(self):
        report, limits = self.fixture()
        result = assess(report, limits)
        self.assertTrue(all(c['within_comparator'] for c in result['comparators'].values()))
        self.assertEqual(len(result['comparators']['agent_rss_kib']['trend']['rolling_windows']), 18)

    def test_workload_changes_and_surviving_agents_or_descendants_are_rejected(self):
        report, limits = self.fixture()
        variants = []
        changed = copy.deepcopy(report)
        changed['samples'][10]['ticks'] += 1
        variants.append(changed)
        alive = copy.deepcopy(report)
        alive['samples'][-1]['agent_alive'] = True
        variants.append(alive)
        descendant = copy.deepcopy(report)
        descendant['surviving_owned_descendants'] = [99]
        variants.append(descendant)
        for invalid in variants:
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                assess(invalid, limits)

    def test_growth_is_reported_without_inventing_a_plateau_threshold(self):
        report, limits = self.fixture()
        for sample in report['samples'][22:25]:
            sample['agent_rss_kib'] = 111
        comparator = assess(report, limits)['comparators']['agent_rss_kib']
        self.assertFalse(comparator['within_comparator'])
        self.assertEqual(comparator['declared_soak_allowance'], 10)
        self.assertEqual(comparator['growth'], 11)


if __name__ == '__main__':
    unittest.main()
