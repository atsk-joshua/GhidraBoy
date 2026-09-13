#!/usr/bin/env python3
"""Semantic sensitivity controls on copied generic native captures, not hardware execution."""
import argparse
import copy
import json
import shutil
from pathlib import Path
import check_conditional_calls as checker


def run(capture, output):
    output.mkdir(parents=True, exist_ok=False)
    baseline = checker.check(capture, exhaust=False)
    results = {'baseline': baseline, 'mutants': {}}
    original = json.loads((capture / 'original-root-high.json').read_text())
    mapper = lambda op: op['mnemonic'] == 'CALLOTHER' and op.get('userop_name') == 'gb_cartridge_write8'
    def fresh_const(op, index, value, identity):
        op['inputs'][index] = dict(op['inputs'][index], constant=True, space='const', offset=value, id=identity, address=False, register=False)
    for name in ['wrong-register', 'missing-restoration', 'extra-latch', 'reordered-before-use', 'wrong-physical-bytes']:
        blocks = copy.deepcopy(original)
        matches = [(block, index, op) for block in blocks for index, op in enumerate(block['ops']) if mapper(op)]
        if len(matches) != 2:
            raise RuntimeError('Control needs the generic two-write native mapper fixture')
        identities = [v['id'] for block in blocks for op in block['ops'] for v in [op.get('output'), *op['inputs']] if v is not None]
        fresh = max(identities) + 100
        block, index, op = matches[0]
        last_block, last_index, last = matches[1]
        if name == 'wrong-register':
            fresh_const(op, 1, 0x3000, fresh);fresh_const(op, 2, 1, fresh + 1)
        elif name == 'missing-restoration':
            fresh_const(last, 2, 2, fresh)
        elif name == 'extra-latch':
            extra = copy.deepcopy(last);fresh_const(extra, 1, 0x3000, fresh);fresh_const(extra, 2, 0, fresh + 1)
            last_block['ops'].insert(last_index, extra)
        elif name == 'reordered-before-use':
            # Move restoration before the callee's visible data effect. Final
            # latches and all write values stay identical; epoch must reject it.
            if block is not last_block:raise RuntimeError('Expected one generic straight-line mapper region')
            block['ops'].pop(last_index);block['ops'].insert(index + 1, last)
        else:
            # Consume a physical byte from the wrong bank in the selected epoch.
            # The output is unused so convenient return values cannot expose it.
            operand = dict(id=fresh, size=1, constant=False, address=True, offset=0x4000, space='rom1', register=False)
            out = dict(id=fresh+1, size=1, constant=False, address=False, offset=0x70000000, space='unique', register=False)
            block['ops'].insert(index+1, dict(mnemonic='COPY',opcode=1,inputs=[operand],output=out))
        dest = output / name
        shutil.copytree(capture, dest)
        (dest / 'original-root-high.json').write_text(json.dumps(blocks) + '\n')
        try:
            checker.check(dest, exhaust=False)
            results['mutants'][name] = {'status':'INCORRECTLY_ACCEPTED'}
        except checker.core.Refusal as error:
            results['mutants'][name] = {'status':'REJECTED', 'reason':str(error)}
        except Exception as error:
            results['mutants'][name] = {'status':'INCONCLUSIVE', 'type':type(error).__name__, 'reason':str(error)}
    (output / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
    if any(row['status'] != 'REJECTED' for row in results['mutants'].values()):raise RuntimeError('Semantic sensitivity incomplete')
    return results

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    print(json.dumps(run(args.capture, args.output), indent=2))
