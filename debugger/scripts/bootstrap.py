#!/usr/bin/env python3
"""Prepare pinned native sources/tools and an isolated Python runtime for this checkout."""
import argparse
import inspect
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile

if __package__:
    from .build_inputs import runtime_dependencies, sha
    from .runtime_python import prepare_environment
else:
    from build_inputs import runtime_dependencies, sha
    from runtime_python import prepare_environment

ROOT = Path(__file__).resolve().parents[1]


def run(*args, **kwargs):
    return subprocess.run([str(arg) for arg in args], check=True, **kwargs)


def prepare_source(root, spec):
    destination = root / '.deps/SameBoy'
    if (root / '.deps').is_symlink() or destination.is_symlink():
        raise ValueError('Dependency source directory must not be a symlink')
    patch = root / spec['patch']
    if sha(patch) != spec['patch_sha256']:
        raise ValueError('SameBoy instrumentation patch does not match the canonical lock')
    destination.mkdir(parents=True, exist_ok=True)
    if not (destination / '.git').exists():
        run('git', 'init', destination)
        run('git', '-C', destination, 'remote', 'add', 'origin', spec['repository'])
        run('git', '-C', destination, 'fetch', '--depth', '1', 'origin', spec['commit'])
        run('git', '-C', destination, 'checkout', '--detach', spec['commit'])
    head = subprocess.check_output(['git', '-C', str(destination), 'rev-parse', 'HEAD'], text=True).strip()
    if head != spec['commit']:
        raise ValueError('Existing SameBoy source has a different revision; preserve it before replacing the dependency')
    actual = subprocess.check_output(['git', '-C', str(destination), 'diff', '--no-ext-diff', '--binary', 'HEAD'])
    if not actual:
        run('git', '-C', destination, 'apply', patch)
        actual = subprocess.check_output(['git', '-C', str(destination), 'diff', '--no-ext-diff', '--binary', 'HEAD'])
    # Compare the whole change, not just whether our patch can be reversed. This
    # rejects additional modifications even inside a file the patch also edits.
    with tempfile.TemporaryDirectory(prefix='ghidraboy-source-index-') as temporary:
        env = dict(os.environ, GIT_INDEX_FILE=str(Path(temporary) / 'index'))
        run('git', '-C', destination, 'read-tree', 'HEAD', env=env)
        run('git', '-C', destination, 'apply', '--cached', patch, env=env)
        expected = subprocess.check_output(['git', '-C', str(destination), 'diff', '--no-ext-diff', '--binary', '--cached', 'HEAD'], env=env)
    untracked = subprocess.check_output(['git', '-C', str(destination), 'ls-files', '--others', '--exclude-standard'])
    if actual != expected or untracked:
        raise ValueError('SameBoy contains changes beyond the pinned patch; preserving source for review')


def prepare_archive(root, name, spec, cache=None):
    archive = root / '.deps' / name
    if (root / '.deps').is_symlink() or archive.is_symlink():
        raise ValueError('Dependency cache must not be a symlink')
    if not archive.exists():
        temporary = archive.with_suffix(archive.suffix + '.partial')
        if cache and (cache / name).is_file():
            shutil.copy2(cache / name, temporary)
        else:
            urllib.request.urlretrieve(spec['url'], temporary)
        if sha(temporary) != spec['sha256']:
            raise ValueError('Dependency digest mismatch: ' + name)
        temporary.replace(archive)
    if sha(archive) != spec['sha256']:
        raise ValueError('Dependency digest mismatch: ' + name)
    destination = root / '.deps/rgbds-bin'
    if destination.is_symlink():
        raise ValueError('Unsafe tool destination')
    destination.mkdir(parents=True, exist_ok=True)

    def validate_destination(name):
        target = destination / name
        if target.is_symlink() or not target.resolve().is_relative_to(destination.resolve()):
            raise ValueError('Unsafe tool destination: ' + name)

    if archive.suffix == '.zip':
        with zipfile.ZipFile(archive) as zipped:
            for member in zipped.infolist():
                path = Path(member.filename)
                if path.is_absolute() or '..' in path.parts or (member.external_attr >> 16) & 0o170000 == 0o120000:
                    raise ValueError('Unsafe tool archive member')
                validate_destination(member.filename)
            for member in zipped.infolist():
                zipped.extract(member, destination)
                target = destination / member.filename
                if target.is_file() and member.external_attr >> 16:
                    target.chmod((member.external_attr >> 16) & 0o777)
    else:
        with tarfile.open(archive) as compressed:
            for member in compressed.getmembers():
                path = Path(member.name)
                if path.is_absolute() or '..' in path.parts or not (member.isfile() or member.isdir()):
                    raise ValueError('Unsafe tool archive member')
                validate_destination(member.name)
            options = {'filter': 'data'} if 'filter' in inspect.signature(compressed.extractall).parameters else {}
            compressed.extractall(destination, **options)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--download-cache', type=Path, help='Optional archive cache; all bytes are verified against the lock')
    parser.add_argument('--ghidra', type=Path, default=os.environ.get('GHIDRA_INSTALL_DIR'))
    args = parser.parse_args()
    if not args.ghidra:
        parser.error('Select --ghidra or GHIDRA_INSTALL_DIR')
    lock = runtime_dependencies(ROOT)
    props = dict(line.split('=', 1) for line in (args.ghidra / 'Ghidra/application.properties').read_text().splitlines()
                 if '=' in line and not line.startswith('#'))
    if props['application.version'] != lock['ghidra']['version']:
        raise ValueError('Selected Ghidra does not match the canonical dependency lock')
    lane = (platform.system(), platform.machine())
    archives = {('Darwin', 'arm64'): 'rgbds-macos.zip', ('Linux', 'x86_64'): 'rgbds-linux-x86_64.tar.xz'}
    if lane not in archives:
        raise ValueError('Supported native build lanes: macOS arm64 and Linux x86-64')
    prepare_source(ROOT, lock['sameboy'])
    name = archives[lane]
    prepare_archive(ROOT, name, lock['downloads'][name], args.download_cache)
    python = prepare_environment(sys.executable, ROOT / '.venv12', args.ghidra.resolve() / 'Ghidra/Debug/Debugger-rmi-trace/pypkg/dist')
    print('Verified native sources and tools; isolated Python:', python)
    print('Next: bash debugger/scripts/build_native.sh; bash debugger/scripts/build_extension.sh')


if __name__ == '__main__':
    main()
