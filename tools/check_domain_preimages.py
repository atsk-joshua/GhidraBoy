#!/usr/bin/env python3
"""Verify exact production capture bytes, preserving every field and multiplicity."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path


def category(field):
    prefix = field.split(':', 1)[0]
    if prefix == 'symbol':
        identity = field.split(':', 2)[1]
        dynamic = identity == 'dynamic' or (identity.isdigit() and int(identity) >> 56 == 0x40)
        return 'dynamicSymbols' if dynamic else 'storedSymbols'
    return {
        'reference': 'referencesAndBindings', 'function': 'functionsAndIds',
        'functionAnnotations': 'functionAnnotationsAndThunkIds', 'parameter': 'parametersAndFunctionIds',
        'context': 'contexts', 'defaultContext': 'defaultContexts',
        'defaultDisassemblyContext': 'defaultDisassemblyContext', 'dataClass': 'dataDefinitions',
        'dataSetting': 'dataSettings', 'dataComment': 'dataComments',
        'analysis.ownership.v1': 'ownership', 'farCallConvention': 'convention',
        'permissions': 'blockPermissions',
    }.get(prefix, 'programFingerprint' if len(field) == 64 else 'algorithm')


CATEGORIES = ['dynamicSymbols', 'storedSymbols', 'referencesAndBindings', 'functionsAndIds',
              'functionAnnotationsAndThunkIds', 'parametersAndFunctionIds', 'contexts',
              'defaultContexts', 'defaultDisassemblyContext', 'dataDefinitions', 'dataSettings',
              'dataComments', 'ownership', 'convention', 'blockPermissions', 'programFingerprint', 'algorithm']


def read_capture(path):
    value = json.loads(path.read_text())
    raw = path.with_suffix('.preimage').read_bytes()
    assert hashlib.sha256(raw).hexdigest() == value['digest'], str(path)
    assert json.loads(raw) == value['fields'], str(path)
    assert value['fields'] == sorted(value['fields']), str(path)
    value['path'] = str(path)
    value['preimageBytes'] = len(raw)
    return value


def diff(left, right):
    result = {}
    for name in CATEGORIES:
        a = Counter(f for f in left['fields'] if category(f) == name)
        b = Counter(f for f in right['fields'] if category(f) == name)
        removed, added = list((a-b).elements()), list((b-a).elements())
        result[name] = {'beforeCount': sum(a.values()), 'afterCount': sum(b.values()),
                        'removed': removed, 'added': added}
        if name == 'dynamicSymbols':
            # Key by the complete descriptor after ID; preserve duplicate occurrences.
            def keyed(fields):
                output = {}
                for f in fields:
                    _, identity, descriptor = f.split(':', 2)
                    output.setdefault(descriptor, []).append(identity)
                return output
            x, y = keyed(removed), keyed(added)
            result[name]['keyedIdentityChanges'] = [
                {'descriptor': key, 'beforeIds': x.get(key, []), 'afterIds': y.get(key, [])}
                for key in sorted(x.keys() | y.keys())]
    return result


def verify(root, expected):
    fresh_dir = next(root.glob('captures-persist-*'))
    fresh = [read_capture(p) for p in sorted(fresh_dir.glob('*.json'))]
    reopened = [read_capture(p) for p in sorted((root/'captures-reopen').glob('*.json'))]
    registration = json.loads((root/'persisted-registration.json').read_text())
    stored = [c for c in fresh if c['digest'] == registration['dependencies']
              and any('SoftwareCallDomains.install(' in s for s in c['stack'])]
    assert len(stored) == 1, 'Must identify the actual stored production traversal'
    stored = stored[0]
    saved = [c for c in fresh if c['phase'] == 'immediately-before-save'][-1]
    first = reopened[0]
    assert first['sequence'] == 1 and any('SoftwareCallDomains.currentRecord(' in s for s in first['stack'])
    assert stored['programId'] == saved['programId'] == first['programId'] == registration['programId']
    assert stored['javaPid'] == saved['javaPid'] != first['javaPid']
    assert stored['fields'] == saved['fields'], 'Registration-to-save preimages differ'
    differences = diff(saved, first)
    changed = [name for name, item in differences.items() if item['removed'] or item['added']]
    assert stored['components'] == saved['components'] == first['components']
    if expected == 'unchanged':
        assert not changed and saved['fields'] == first['fields'], changed
        assert Path(saved['path']).with_suffix('.preimage').read_bytes() == Path(first['path']).with_suffix('.preimage').read_bytes()
    else:
        assert changed == ['dynamicSymbols'], changed
        assert all(c['beforeIds'] and len(c['beforeIds']) == len(c['afterIds']) for c in differences['dynamicSymbols']['keyedIdentityChanges'])
    guards = []
    if expected == 'unchanged':
        for capture in reopened:
            stack = capture['stack']
            caller = next((stack[i+1] for i, entry in enumerate(stack[:-1])
                           if 'SoftwareCallDomains.fingerprint(' in entry), '')
            if 'SoftwareCallDomains.currentRecord(' in caller or 'SoftwareCallDomains.emit(' in caller:
                assert capture['fields'] == saved['fields'], 'Callback dependency preimage changed'
                assert Path(capture['path']).with_suffix('.preimage').read_bytes() == Path(saved['path']).with_suffix('.preimage').read_bytes()
                guards.append(capture['sequence'])
        assert guards and guards[0] == 1
    summary_keys = ['path', 'sequence', 'phase', 'programId', 'javaPid', 'modification', 'digest', 'preimageBytes', 'components', 'stack']
    return {'status': 'PASS', 'expected': expected, 'verifiedCaptures': len(fresh)+len(reopened),
            'registration': {k: stored[k] for k in summary_keys},
            'beforeSave': {k: saved[k] for k in summary_keys},
            'firstReopenedCheck': {k: first[k] for k in summary_keys},
            'allCategories': differences, 'changedCategories': changed,
            'zeroUnexplainedDifferences': not changed, 'reopenedGuardSequencesVerified': guards,
            'classification': 'Captured fields only; old dynamic IDs identified by pinned standalone map ID 0x40; no live Program enumeration'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('--expect', choices=['dynamic-id-mismatch', 'unchanged'], required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = verify(args.root, args.expect)
    args.output.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({k: result[k] for k in ['status', 'expected', 'verifiedCaptures', 'changedCategories']}))
