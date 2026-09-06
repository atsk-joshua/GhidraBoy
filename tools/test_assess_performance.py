"""Regression tests for evidence that could otherwise produce a false budget PASS."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import assess_performance as assess


LIMITS = assess.load(Path(__file__).with_name('performance_limits.json'))


def performance(value=10):
    report = dict(schema=1, **{key: 'fixture' for key in LIMITS['comparison']['matched_fields']})
    report['rom_sha256'] = 'a' * 64
    report.update({key: dict(count=20, samples_ms=[value] * 20) for key in assess.METRICS})
    return report


def soak():
    return dict(schema=1, status='COMPLETED_MEASUREMENTS', cycles=100, requested_seconds=1800,
                samples=[dict(cycle=i, seconds=i * 18, capture=i * 8, snapshot=i * 7,
                              trace_bytes=i * 8192, dropped=0, pause_ms=10,
                              **{field: 10 for field in assess.RESOURCES}) for i in range(1, 101)])


class ComparisonTest(unittest.TestCase):
    def compare(self, before=None, after=None):
        return assess.compare([copy.deepcopy(before or performance()) for _ in range(3)],
                              [copy.deepcopy(after or performance()) for _ in range(3)], LIMITS['comparison'])

    def test_absolute_and_relative_budgets_and_run_median(self):
        self.assertEqual(self.compare(after=performance(20))['status'], 'PASS')
        self.assertEqual(self.compare(after=performance(20.001))['status'], 'FAIL')
        self.assertEqual(self.compare(performance(100), performance(120))['status'], 'PASS')
        self.assertEqual(self.compare(performance(100), performance(120.001))['status'], 'FAIL')
        result = assess.compare([performance(10), performance(10), performance(500)],
                                [performance(20)] * 3, LIMITS['comparison'])
        self.assertEqual(result['metrics']['step_reply']['baseline_median_p95_ms'], 10)

    def test_missing_identity_on_both_sides_is_invalid(self):
        for key in LIMITS['comparison']['matched_fields']:
            for value in (None, '', ' ', 5):
                with self.subTest(key=key, value=value):
                    report = performance()
                    report[key] = value
                    with self.assertRaises(ValueError):
                        self.compare(report, report)
            report = performance()
            del report[key]
            with self.assertRaises(ValueError):
                self.compare(report, report)

    def test_different_identity_and_incomplete_runs(self):
        report = performance()
        report['host'] = 'other'
        with self.assertRaises(ValueError):
            self.compare(after=report)
        with self.assertRaises(ValueError):
            assess.compare([performance()] * 2, [performance()] * 3, LIMITS['comparison'])

    def test_p95_is_nearest_rank_and_recomputed(self):
        report = performance()
        for key in assess.METRICS:
            report[key]['samples_ms'] = list(range(1, 21))
        result = self.compare(report, report)
        self.assertEqual(result['metrics']['step_reply']['candidate_median_p95_ms'], 19)
        report['step_reply']['p95_ms'] = 1
        with self.assertRaisesRegex(ValueError, 'disagrees'):
            self.compare(after=report)

    def test_invalid_raw_samples_and_summaries(self):
        for field in ('samples_ms', 'p95_ms', 'median_ms'):
            for value in (float('nan'), float('inf'), -1, True, '10', None):
                with self.subTest(field=field, value=value):
                    report = performance()
                    if field == 'samples_ms':
                        report['step_reply'][field][0] = value
                    else:
                        report['step_reply'][field] = value
                    with self.assertRaises(ValueError):
                        self.compare(after=report)
        for count in (19, 21, 20.0, True):
            report = performance()
            report['step_reply']['count'] = count
            with self.assertRaises(ValueError):
                self.compare(after=report)


class SoakTest(unittest.TestCase):
    def assess(self, report):
        return assess.assess_soak(report, LIMITS['soak'])

    def test_valid_soak_has_complete_trends_and_requires_review(self):
        result = self.assess(soak())
        self.assertEqual(result['status'], 'PASS')
        self.assertTrue(result['review_required'])
        self.assertEqual(len(result['trends']['agent_rss_kib']['rolling_windows']), 93)
        self.assertEqual(len(result['trends']['trace_storage']['intervals']), 94)
        self.assertEqual(result['checks']['trace_bytes_per_capture']['value'], 1024)

    def test_middle_spike_is_visible_even_with_passing_endpoint_budget(self):
        report = soak()
        for sample in report['samples'][45:50]:
            sample['agent_rss_kib'] = 1_000_000
        result = self.assess(report)
        self.assertEqual(result['status'], 'PASS')
        self.assertEqual(result['trends']['agent_rss_kib']['maximum'], 1_000_000)
        self.assertEqual(max(w['median'] for w in result['trends']['agent_rss_kib']['rolling_windows']), 1_000_000)
        self.assertTrue(result['review_required'])

    def test_full_growth_trend_and_declared_failures(self):
        report = soak()
        for sample in report['samples']:
            sample['agent_rss_kib'] = sample['cycle'] * 1000
        result = self.assess(report)
        self.assertEqual(result['status'], 'FAIL')
        self.assertAlmostEqual(result['trends']['agent_rss_kib']['slope_per_minute'], 1000 / 18 * 60)
        for key, value in (('pause_ms', 2000), ('dropped', 1), ('trace_bytes', 100_000_000)):
            with self.subTest(key=key):
                report = soak()
                report['samples'][-1][key] = value
                self.assertEqual(self.assess(report)['status'], 'FAIL')

    def test_nonfinite_negative_boolean_and_missing_fields(self):
        for key in ('seconds', 'pause_ms', 'capture', 'snapshot', 'trace_bytes', 'dropped', *assess.RESOURCES):
            for value in (float('nan'), float('inf'), -1, True, None):
                with self.subTest(key=key, value=value):
                    report = soak()
                    report['samples'][50][key] = value
                    with self.assertRaises(ValueError):
                        self.assess(report)
            report = soak()
            del report['samples'][50][key]
            with self.assertRaises(ValueError):
                self.assess(report)

    def test_incomplete_or_reset_counters_are_not_false_passes(self):
        for key in ('seconds', 'capture', 'snapshot', 'trace_bytes', 'cycle'):
            report = soak()
            report['samples'][50][key] = 0
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.assess(report)
        for field, value in (('status', 'RUNNING'), ('cycles', 101), ('schema', True),
                             ('requested_seconds', 1801), ('samples', [])):
            report = soak()
            report[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.assess(report)


class CommandTest(unittest.TestCase):
    def test_exit_codes_and_stale_pass_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            source, output = Path(directory) / 'soak.json', Path(directory) / 'assessment.json'
            for state, code in (('PASS', 0), ('FAIL', 1), ('INVALID', 2)):
                report = soak()
                if state == 'FAIL':
                    report['samples'][-1]['pause_ms'] = 2000
                elif state == 'INVALID':
                    report['samples'][-1]['pause_ms'] = float('nan')
                source.write_text(json.dumps(report))
                result = subprocess.run([sys.executable, str(Path(assess.__file__)), '--soak', str(source),
                                         '--output', str(output)], capture_output=True, text=True)
                self.assertEqual(result.returncode, code, result.stderr)
                self.assertEqual(json.loads(output.read_text())['status'], state)
                self.assertEqual(len(json.loads(output.read_text())['inputs'][0]['sha256']), 64)

    def test_duplicate_run_paths_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            source, output = Path(directory) / 'run.json', Path(directory) / 'assessment.json'
            source.write_text(json.dumps(performance()))
            args = [sys.executable, str(Path(assess.__file__)), '--output', str(output)]
            for flag in ('--baseline', '--candidate'):
                for _ in range(3):
                    args += [flag, str(source)]
            result = subprocess.run(args, capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(json.loads(output.read_text())['status'], 'INVALID')


if __name__ == '__main__':
    unittest.main()
