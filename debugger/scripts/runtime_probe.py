#!/usr/bin/env python3
"""Load and capture every selected backend without importing optional adapters."""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'python'))
from ghigbc.backend import create_backend
from ghigbc.profile import installed_providers


def selected_backends(root=ROOT):
    path = root / 'runtime-backends.json'
    if not path.exists():
        return ['sameboy']  # Compatibility with packages predating backend selection.
    data = json.loads(path.read_text())
    names = data.get('backends')
    if (type(data.get('schema')) is not int or data['schema'] != 1 or not isinstance(names, list) or not names or
            len(set(names)) != len(names) or set(names) - {'sameboy', 'mgba'}):
        raise ValueError('Invalid selected runtime backends')
    return names


def probe(names, display=False):
    results = {}
    for name in names:
        machine = create_backend(name, ROOT / 'build/teaching.gbc')
        try:
            capture = machine.capture()
            if capture.state['abi'] != 1:
                raise ValueError('Unsupported native ABI')
            results[name] = {'status': 'READY', 'descriptor': machine.descriptor.id}
        finally:
            machine.close()
    if installed_providers(ROOT)[1]:
        raise ValueError('Invalid installed profile providers')
    if display:
        from ghigbc.display import load_sdl
        load_sdl()
    return results


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--backend', action='append', choices=['sameboy', 'mgba'])
    parser.add_argument('--display', action='store_true')
    args = parser.parse_args()
    print(json.dumps(probe(args.backend or selected_backends(), args.display), sort_keys=True))
