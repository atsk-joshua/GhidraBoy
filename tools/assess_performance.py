#!/usr/bin/env python3
"""Assess recorded real-RMI measurements against predeclared, scoped budgets."""
import argparse
import hashlib
import json
import math
from pathlib import Path
import statistics


METRICS = ('step_reply', 'step_capture_ready', 'pause_reply', 'pause_capture_ready')
RESOURCES = {
    'agent_rss_kib': 'agent_rss_growth_kib',
    'ghidra_rss_kib': 'ghidra_rss_growth_kib',
    'agent_threads': 'agent_thread_growth',
    'ghidra_threads': 'ghidra_thread_growth',
    'agent_handles': 'agent_handle_growth',
    'ghidra_handles': 'ghidra_handle_growth',
}


def load(path):
    return json.loads(path.read_text())


def number(value, name, integer=False):
    if (isinstance(value, bool) or not isinstance(value, (int, float))
            or not math.isfinite(value) or value < 0
            or (integer and not isinstance(value, int))):
        raise ValueError(f'{name} must be a finite nonnegative {"integer" if integer else "number"}')
    return value


def schema(report):
    if not isinstance(report, dict) or type(report.get('schema')) is not int or report['schema'] != 1:
        raise ValueError('Expected a schema-1 measurement report')


def distribution(report, key):
    metric = report.get(key)
    if not isinstance(metric, dict):
        raise ValueError(f'Missing distribution: {key}')
    count = number(metric.get('count'), f'{key}.count', integer=True)
    samples = metric.get('samples_ms')
    if not isinstance(samples, list) or count < 20 or len(samples) != count:
        raise ValueError(f'Incomplete performance samples: {key}')
    for value in samples:
        number(value, f'{key}.samples_ms')
    # Match the harness's nearest-rank estimator; supplied summaries never decide PASS.
    p95 = sorted(samples)[math.ceil(count * .95) - 1]
    median = statistics.median(samples)
    for field, computed in (('p95_ms', p95), ('median_ms', median)):
        if field in metric:
            reported = number(metric[field], f'{key}.{field}')
            if not math.isclose(reported, computed, rel_tol=1e-9, abs_tol=1e-9):
                raise ValueError(f'{key}.{field} disagrees with raw samples')
    return p95


def compare(baseline, candidate, limits):
    minimum = limits['minimum_runs']
    if len(baseline) < minimum or len(candidate) < minimum:
        raise ValueError(f'{minimum} or more matched runs are required on each side')
    reference = baseline[0]
    runs = [*baseline, *candidate]
    for item in runs:
        schema(item)
        for key in limits['matched_fields']:
            value = item.get(key)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f'Missing or invalid performance identity: {key}')
            if value != reference.get(key):
                raise ValueError(f'Performance inputs differ in environment/fixture: {key}')
        rom_hash = item['rom_sha256']
        if len(rom_hash) != 64 or any(char not in '0123456789abcdef' for char in rom_hash):
            raise ValueError('rom_sha256 must be a lowercase SHA256 digest')
    metrics = {}
    for key in METRICS:
        before = statistics.median(distribution(item, key) for item in baseline)
        after = statistics.median(distribution(item, key) for item in candidate)
        allowed = before + max(before * limits['relative_p95_regression'], limits['absolute_p95_allowance_ms'])
        metrics[key] = dict(baseline_median_p95_ms=before, candidate_median_p95_ms=after,
                            limit_ms=allowed, passed=after <= allowed)
    return dict(status='PASS' if all(m['passed'] for m in metrics.values()) else 'FAIL',
                identity={key: reference[key] for key in limits['matched_fields']},
                baseline_runs=len(baseline), candidate_runs=len(candidate), metrics=metrics)


def soak_samples(report, limits):
    schema(report)
    cycles = number(report.get('cycles'), 'cycles', integer=True)
    requested = number(report.get('requested_seconds'), 'requested_seconds')
    samples = report.get('samples')
    if (report.get('status') != 'COMPLETED_MEASUREMENTS' or cycles < limits['minimum_cycles']
            or requested < limits['minimum_seconds'] or not isinstance(samples, list) or not samples):
        raise ValueError('Extended soak has not completed')
    if len(samples) != cycles:
        raise ValueError('Soak requires one sample per completed cycle')
    previous = None
    for cycle, sample in enumerate(samples, 1):
        if not isinstance(sample, dict):
            raise ValueError('Invalid soak sample')
        for field in ('cycle', 'capture', 'snapshot', 'trace_bytes', 'dropped', *RESOURCES):
            number(sample.get(field), field, integer=True)
        for field in ('seconds', 'pause_ms'):
            number(sample.get(field), field)
        if sample['cycle'] != cycle or sample['seconds'] <= 0:
            raise ValueError('Soak cycles must be contiguous and elapsed time positive')
        if previous:
            for field in ('seconds', 'capture', 'snapshot'):
                if sample[field] <= previous[field]:
                    raise ValueError(f'Soak {field} must strictly increase; segment replacement targets separately')
            if sample['trace_bytes'] < previous['trace_bytes']:
                raise ValueError('Trace storage decreased; cumulative storage needs separate accounting')
        previous = sample
    if samples[-1]['seconds'] < max(requested, limits['minimum_seconds']):
        raise ValueError('Extended soak has not completed')
    return samples


def trend(samples, field, count):
    """Describe every post-warmup sample without inventing a post-hoc trend budget."""
    values = [sample[field] for sample in samples]
    elapsed = [sample['seconds'] for sample in samples]
    xmean, ymean = statistics.mean(elapsed), statistics.mean(values)
    slope = sum((x - xmean) * (y - ymean) for x, y in zip(elapsed, values)) / sum(
        (x - xmean) ** 2 for x in elapsed)
    windows = [dict(first_cycle=samples[i]['cycle'], last_cycle=samples[i + count - 1]['cycle'],
                    median=statistics.median(values[i:i + count]))
               for i in range(len(samples) - count + 1)]
    return dict(minimum=min(values), maximum=max(values), slope_per_minute=slope * 60,
                rolling_windows=windows)


def assess_soak(report, limits):
    samples = soak_samples(report, limits)
    stable = [sample for sample in samples if sample['cycle'] > limits['warmup_cycles']]
    count = limits['window_samples']
    if len(stable) < count * 2:
        raise ValueError('Insufficient post-warmup samples')
    checks = {}
    trends = {}
    for field, budget in RESOURCES.items():
        before = statistics.median(s[field] for s in stable[:count])
        after = statistics.median(s[field] for s in stable[-count:])
        checks[field] = dict(initial_window=before, final_window=after, growth=after - before,
                             limit=limits[budget], passed=after - before <= limits[budget])
        trends[field] = trend(stable, field, count)
    captures = stable[-1]['capture'] - stable[0]['capture']
    storage = (stable[-1]['trace_bytes'] - stable[0]['trace_bytes']) / captures
    checks['trace_bytes_per_capture'] = dict(value=storage, limit=limits['trace_bytes_per_capture'],
                                             passed=storage <= limits['trace_bytes_per_capture'])
    trends['trace_storage'] = dict(intervals=[
        dict(cycle=after['cycle'], captures=after['capture'] - before['capture'],
             bytes_per_capture=(after['trace_bytes'] - before['trace_bytes']) /
                               (after['capture'] - before['capture']))
        for before, after in zip(stable, stable[1:])])
    checks['pause'] = dict(maximum_ms=max(s['pause_ms'] for s in samples), limit_ms=limits['maximum_pause_ms'],
                          passed=all(s['pause_ms'] < limits['maximum_pause_ms'] for s in samples))
    checks['events'] = dict(maximum_reported_dropped=max(s['dropped'] for s in samples),
                           passed=all(s['dropped'] == limits['dropped_events'] for s in samples))
    return dict(status='PASS' if all(c['passed'] for c in checks.values()) else 'FAIL', checks=checks,
                trends=trends, review_required=['Full resource trends and idle behavior',
                    'Post-close descendant and resource cleanup', 'Separate lifecycle target storage/resources',
                    'External host, harness and artifact identity binding (not embedded in schema-1 soak reports)'],
                scope='Predeclared bounded budgets only; trend diagnostics have no newly invented thresholds. '
                      'A budget PASS does not establish release qualification or absence of leaks.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--limits', type=Path, default=Path(__file__).with_name('performance_limits.json'))
    parser.add_argument('--baseline', type=Path, action='append', default=[])
    parser.add_argument('--candidate', type=Path, action='append', default=[])
    parser.add_argument('--soak', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    limits = load(args.limits)
    result = {'schema': 1, 'limits_sha256': hashlib.sha256(args.limits.read_bytes()).hexdigest()}
    try:
        # Reusing a path is not an independent run. Distinct files still require provenance review.
        paths = [*args.baseline, *args.candidate]
        if len({p.resolve() for p in paths}) != len(paths):
            raise ValueError('Comparison inputs must be distinct run files')
        if args.baseline or args.candidate:
            result['comparison'] = compare([load(p) for p in args.baseline],
                                           [load(p) for p in args.candidate], limits['comparison'])
        if args.soak:
            result['soak'] = assess_soak(load(args.soak), limits['soak'])
        if not ('comparison' in result or 'soak' in result):
            parser.error('Provide comparison inputs or a soak report')
    except (ValueError, KeyError, TypeError, OSError) as error:
        result['status'] = 'INVALID'
        result['error'] = str(error)
    else:
        result['status'] = 'PASS' if all(result[k]['status'] == 'PASS'
                                       for k in ('comparison', 'soak') if k in result) else 'FAIL'
    result['inputs'] = [dict(path=str(p.resolve()), sha256=hashlib.sha256(p.read_bytes()).hexdigest())
                        for p in [*args.baseline, *args.candidate, *([args.soak] if args.soak else [])]
                        if p.is_file()]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, allow_nan=False) + '\n')
    print(json.dumps(result, indent=2, allow_nan=False))
    if result['status'] != 'PASS':
        raise SystemExit(2 if result['status'] == 'INVALID' else 1)


if __name__ == '__main__':
    main()
