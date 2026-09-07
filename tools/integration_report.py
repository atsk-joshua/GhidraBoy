#!/usr/bin/env python3
"""Render the original integration gates and exact receipts without promoting results."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--status', type=Path, default=Path('docs/integration/status.json'))
    parser.add_argument('--receipt', type=Path, action='append', default=[])
    parser.add_argument('--packages', type=Path, action='append', default=[])
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--require-qualified', action='store_true')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    status = json.loads(args.status.read_text())
    gates = status['gates']
    names = [g['id'] for g in gates]
    if len(names) != len(set(names)) or len(names) != 58:
        raise ValueError('Expected the original 58 distinct integration gates')
    plan = (root / status['plan']).read_text()
    if any('`' + name + '`' not in plan for name in names):
        raise ValueError('Gate register differs from the original plan')
    def evidence(path):
        path = path.resolve()
        return dict(path=str(path.relative_to(root)),
                    sha256=hashlib.sha256(path.read_bytes()).hexdigest())
    receipts = [evidence(p) for p in args.receipt]
    packages = []
    for index in args.packages:
        data = json.loads(index.read_text())
        for package in data['packages']:
            actual = evidence(Path(package['archive']))
            if actual['sha256'] != package['sha256'] or not package['byte_reproducible']:
                raise ValueError('Package hash/reproducibility mismatch: ' + actual['path'])
            packages.append(dict(actual, backend=package['backend'],
                                 source_head=data['source_head'], index=evidence(index)))
    remaining = [g for g in gates if g['id'] != 'DEVICE-01' and g['status'] != 'PASS']
    result = dict(schema=1, source_commit=subprocess.check_output(
        ['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(),
        status='NON_DECK_QUALIFIED' if not remaining else 'INCOMPLETE',
        device_status=next(g['status'] for g in gates if g['id'] == 'DEVICE-01'),
        scope='Local qualification only. Physical Steam Deck deferred. No publication or archival.',
        gate_register=evidence(args.status), packages=packages, receipts=receipts,
        gates=gates, remaining_non_deck=[g['id'] for g in remaining])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    lines = ['# Generated integration qualification report', '',
             '**' + result['status'] + '** — ' + result['scope'], '',
             'Source commit: `' + result['source_commit'] + '`. Receipt and archive hashes are in the adjacent JSON.', '',
             '| Original gate | Status | Requirement |', '| --- | --- | --- |']
    for gate in gates:
        lines.append('| ' + gate['id'] + ' | ' + gate['status'] + ' | ' +
                     gate['requirement'].replace('|', '\\|').replace('\n', ' ') + ' |')
    args.output.with_suffix('.md').write_text('\n'.join(lines) + '\n')
    print(json.dumps(dict(status=result['status'], remaining_non_deck=result['remaining_non_deck'])))
    if args.require_qualified and remaining:
        raise SystemExit(2)


if __name__ == '__main__':
    main()
