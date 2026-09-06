#!/usr/bin/env python3
"""Build the experimental pinned GB-only mGBA adapter from an isolated archive."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys

SOURCE_ARCHIVE_SHA256 = 'a59017f0dee15f8f9067c5f0638707f81487de595274f6b9e5a3e88f2bb517e9'
REVISION = '685023e05d90d87050fb357f46f7bd2d907083f5'
ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--output', type=Path, default=ROOT / 'build')
    args = parser.parse_args()
    source, work, output = args.source.resolve(), args.work.resolve(), args.output.resolve()
    revision = REVISION
    if source.is_file():
        if sha(source) != SOURCE_ARCHIVE_SHA256:
            parser.error('Requires the locked pristine mGBA source archive')
    elif (subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip() != REVISION or
          subprocess.check_output(['git', '-C', str(source), 'status', '--porcelain'])):
        parser.error('Requires clean mGBA source at ' + REVISION)
    work.mkdir(parents=True, exist_ok=False)
    native = ROOT / 'backends/mgba/native'
    patch = native / 'patches/0001-sm83-no-idle.patch'
    receipt = dict(schema=1, status='BUILDING', backend='mgba', sourceRevision=revision,
                   host=platform.platform(), patchSha256=sha(patch), commands=[],
                   sources={str(p.relative_to(native)): sha(p) for p in sorted(native.rglob('*')) if p.is_file()})
    receipt['builderSha256'] = sha(Path(__file__))

    def run(command, timeout=120):
        receipt['commands'].append([str(arg) for arg in command])
        subprocess.run(receipt['commands'][-1], check=True, timeout=timeout)

    try:
        archive = work / 'source.tar'
        if source.is_file():
            shutil.copyfile(source, archive)
        else:
            run(['git', '-C', source, 'archive', '--format=tar', '--output=' + str(archive), revision])
        if sha(archive) != SOURCE_ARCHIVE_SHA256:
            raise ValueError('Pristine mGBA source archive mismatch')
        receipt['sourceArchiveSha256'] = sha(archive)
        copied = work / 'source'
        copied.mkdir()
        run(['tar', '-xf', archive, '-C', copied])
        run(['git', '-C', copied, 'apply', '--check', patch])
        run(['git', '-C', copied, 'apply', patch])
        run(['cmake', '-S', native, '-B', work / 'build', '-DMGBA_SOURCE=' + str(copied), '-DCMAKE_BUILD_TYPE=Release'])
        run(['cmake', '--build', work / 'build', '--parallel', str(min(4, os.cpu_count() or 1))], timeout=300)
        name = 'libghigbc_mgba' + ('.dylib' if sys.platform == 'darwin' else '.so')
        binary = work / 'build' / name
        receipt['binarySha256'] = sha(binary)
        receipt['abiBuildFiles'] = {}
        for name_ in ('flags.make', 'link.txt'):
            path = work / 'build/CMakeFiles/ghigbc_mgba.dir' / name_
            if path.exists():
                receipt['abiBuildFiles'][name_] = dict(sha256=sha(path), content=path.read_text())
        receipt['status'] = 'BUILT'
        output.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(binary, output / name)
        shutil.copyfile(archive, output / 'mgba-source.tar')
        (output / (name + '.json')).write_text(json.dumps(receipt, indent=2) + '\n')
    except Exception as error:
        receipt.update(status='FAILED', error=str(error))
        raise
    finally:
        (work / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')


if __name__ == '__main__':
    main()
