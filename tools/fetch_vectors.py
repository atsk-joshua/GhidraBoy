#!/usr/bin/env python3
"""Explicit network maintenance command. Ordinary tests use committed samples only."""
import argparse, hashlib, json, pathlib, urllib.request
REV = 'f9c30210245dd691661db39f5ace022c465ecc2f'
ROOT = f'https://raw.githubusercontent.com/SingleStepTests/sm83/{REV}/'
parser = argparse.ArgumentParser()
parser.add_argument('--output', type=pathlib.Path, default=pathlib.Path('src/test/resources/vectors'))
parser.add_argument('--count', type=int, default=8)
args = parser.parse_args()
args.output.mkdir(parents=True, exist_ok=True)
manifest = {'revision': REV, 'selection': f'first {args.count} vectors per listed file', 'files': {}}
for opcode in ['27', '88', '8e', '8f', '98', '9e', '9f', 'f1', '09', '29', 'e8', 'f8', '22', '2a', '32', '3a', 'cb 00', 'cb 11', 'cb 46', 'cb 86', 'cb fe']:
    name = opcode + '.json'
    raw = urllib.request.urlopen(ROOT + 'v1/' + urllib.parse.quote(name)).read()
    vectors = json.loads(raw)[:args.count]
    sample = (json.dumps(vectors, indent=2) + '\n').encode()
    (args.output / name).write_bytes(sample)
    manifest['files'][name] = {'upstreamSha256': hashlib.sha256(raw).hexdigest(), 'sampleSha256': hashlib.sha256(sample).hexdigest(), 'count':len(vectors)}
    print(name, len(vectors), flush=True)
(args.output / 'LICENSE').write_bytes(urllib.request.urlopen(ROOT + 'LICENSE').read())
(args.output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
