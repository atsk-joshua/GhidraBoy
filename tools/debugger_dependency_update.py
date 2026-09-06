#!/usr/bin/env python3
"""Build offline and install/verify/rollback the pinned Java patch into NEW copies only.

Build: --ghidra BASE --jdk JDK21 --patch PATCH --output NEW_BUNDLE
Install/rollback: --ghidra SOURCE --package ZIP --sha256 TRUSTED_HASH --output NEW_BUNDLE
The new runnable distribution is NEW_BUNDLE/distribution. Source is never edited.
Use canonical paths (e.g. /private/tmp on macOS); this copy tool refuses symlinks.
"""
import argparse
import ctypes
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile

BASE = '12.1.3'
VERSION = '12.1.3+ghidraboy.register-lifetime.1'
JAR = 'Ghidra/Debug/Debugger/lib/Debugger.jar'
SOURCE_ZIP = 'Ghidra/Debug/Debugger/lib/Debugger-src.zip'
SOURCE = 'ghidra/app/plugin/core/debug/gui/register/DebuggerRegistersProvider.java'
CLASS = SOURCE.removesuffix('.java') + '.class'
MARKER = 'Ghidra/Debug/Debugger/ghidraboy-java-dependency.json'
PATCH_NAME = 'ghidra-12.1.3-debugger-register-lifetime.patch'
BASE_SHA = '7f72777cda59badf9f0b8e878f7a9d52040c39593a1e05251285ccafae6baecc'
JAR_SHA = '3b75891c6734b23f03c0313cb5fc582a9410676b799c8c1af3e30e3696b10bbf'
PATCH_SHA = '84a7da39520e7e2eaf12ebc49aa2f7c78f9e7e5fd19be3bda4e1ac55eb227df7'
SOURCE_SHA = 'e93c32916d81a274678dfb133ee54a2913186b26bc36c08a7a519424a6d64c71'
PATCHED_SOURCE_SHA = '4b561f12b9dccc2312aea7e7238de8991133dac6a5c5544c942ddb9c1cab5bb3'
SOURCE_ZIP_SHA = 'd42d79db2de15b28f1803e936eab4ac4db724ca5a1e373e8a59cdbb104b6d107'
IDENTITY = dict(schema='ghidraboy-debugger-java-dependency-v1', baseGhidraVersion=BASE,
                dependencyVersion=VERSION, jarSha256=JAR_SHA, baselineJarSha256=BASE_SHA,
                patchSha256=PATCH_SHA, sourceSha256=SOURCE_SHA,
                patchedSourceSha256=PATCHED_SOURCE_SHA, officialJava=False)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


def no_links(path):
    path = Path(path).absolute()
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError('Symlink paths are not accepted; select canonical absolute paths: ' + str(path))
    return path


def ordinary(path):
    no_links(path)
    if not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError('Expected an ordinary file: ' + str(path))
    return path.read_bytes()


def checked(path, expected):
    data = ordinary(path)
    if digest(data) != expected:
        raise ValueError('Pinned hash mismatch: ' + str(path))
    return data


def snapshot(root):
    result = {}
    for p in sorted(root.rglob('*')):
        mode = p.lstat().st_mode
        if stat.S_ISDIR(mode):
            continue
        if not stat.S_ISREG(mode):
            raise ValueError('Distribution contains links or special files: ' + str(p))
        result[p.relative_to(root).as_posix()] = (digest(p.read_bytes()), stat.S_IMODE(mode))
    return result


def base(root):
    root = no_links(root).resolve()
    if not root.is_dir():
        raise ValueError('Select an ordinary Ghidra directory')
    props = ordinary(root / 'Ghidra/application.properties').decode()
    if 'application.version=' + BASE not in props.splitlines():
        raise ValueError('Expected Ghidra ' + BASE)
    return root


def output_path(source, output):
    output = no_links(output).resolve()
    if (output.exists() or output.is_relative_to(source) or source.is_relative_to(output)
            or not output.parent.is_dir()):
        raise ValueError('Output must be a new independent path with an existing parent; never overwrite source or output')
    return output


def publish(stage, output):
    # Exclusive atomic rename prevents an existing or concurrently created output being overwritten.
    libc = ctypes.CDLL(None, use_errno=True)
    if platform.system() == 'Darwin':
        fn = libc.renamex_np
        fn.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        result = fn(os.fsencode(stage), os.fsencode(output), 4)
    elif platform.system() == 'Linux':
        fn = libc.renameat2
        fn.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        result = fn(-100, os.fsencode(stage), -100, os.fsencode(output), 1)
    else:
        raise ValueError('Exclusive publication requires macOS or Linux')
    if result:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code), str(output))


def jar_changes(before, after):
    with zipfile.ZipFile(io.BytesIO(before)) as src, zipfile.ZipFile(io.BytesIO(after)) as dst:
        if src.namelist() != dst.namelist() or len(set(src.namelist())) != len(src.namelist()):
            raise ValueError('JAR entry topology changed')
        changed = [n for n in src.namelist() if src.read(n) != dst.read(n)]
    if changed != [CLASS]:
        raise ValueError('Unexpected changed JAR members: ' + repr(changed))
    return changed


def read_package(path, expected_sha256):
    data = ordinary(path)
    if len(data) > 64 * 1024 * 1024 or digest(data) != expected_sha256:
        raise ValueError('Package differs from trusted SHA256 or exceeds size bound')
    expected = {'dependency.json', 'build.json', 'rollback.json', 'Debugger.jar',
                'rollback/Debugger.jar', PATCH_NAME, 'source/original.java', 'source/patched.java'}
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        infos = z.infolist()
        if (len(infos) != len(expected) or set(z.namelist()) != expected
                or sum(i.file_size for i in infos) > 64 * 1024 * 1024
                or any(i.flag_bits & 1 or stat.S_IFMT(i.external_attr >> 16) not in (0, stat.S_IFREG) for i in infos)):
            raise ValueError('Unexpected, duplicate, encrypted or unsafe package entries')
        files = {n: z.read(n) for n in expected}
    if json.loads(files['dependency.json']) != IDENTITY:
        raise ValueError('Unrecognized debugger Java dependency identity')
    for name, sha in [('Debugger.jar', JAR_SHA), ('rollback/Debugger.jar', BASE_SHA),
                      (PATCH_NAME, PATCH_SHA), ('source/original.java', SOURCE_SHA),
                      ('source/patched.java', PATCHED_SOURCE_SHA)]:
        if digest(files[name]) != sha:
            raise ValueError('Pinned package member hash mismatch: ' + name)
    if json.loads(files['rollback.json']) != rollback_identity():
        raise ValueError('Unexpected rollback recipe')
    if json.loads(files['build.json']) != build_identity():
        raise ValueError('Unexpected build recipe')
    jar_changes(files['rollback/Debugger.jar'], files['Debugger.jar'])
    return files


def rollback_identity():
    return dict(path=JAR, originalSha256=BASE_SHA, installedSha256=JAR_SHA,
                identityMarker=MARKER, originalMarkerExisted=False)


def build_identity():
    return dict(schema=1, dependencyVersion=VERSION, status='PASS_PINNED_REBUILD',
                baselineSourceArchiveSha256=SOURCE_ZIP_SHA,
                changedMembers=[CLASS], compiler='javac 21; -proc:none -g',
                patchStrip=1, network=False)


def build(ghidra, jdk, patch, output):
    ghidra = base(ghidra)
    output = output_path(ghidra, output)
    original = checked(ghidra / JAR, BASE_SHA)
    source_zip = checked(ghidra / SOURCE_ZIP, SOURCE_ZIP_SHA)
    patch_data = checked(patch, PATCH_SHA)
    with zipfile.ZipFile(io.BytesIO(source_zip)) as z:
        source_data = z.read(SOURCE)
    if digest(source_data) != SOURCE_SHA:
        raise ValueError('Unmatched original source')
    javac = jdk / 'bin/javac'
    version = subprocess.run([str(javac), '-version'], capture_output=True, text=True, check=True)
    if not (version.stdout + version.stderr).strip().startswith('javac 21.'):
        raise ValueError('Build requires JDK 21; output is also pinned byte-for-byte')
    stage = Path(tempfile.mkdtemp(prefix='.debugger-java-build-', dir=output.parent))
    try:
        source = stage / 'Ghidra/Debug/Debugger/src/main/java' / SOURCE
        source.parent.mkdir(parents=True)
        source.write_bytes(source_data)
        local_patch = stage / PATCH_NAME
        local_patch.write_bytes(patch_data)
        log = stage / 'commands.jsonl'
        def run(command):
            with (stage / 'build.log').open('ab') as out:
                process = subprocess.Popen(command, cwd=stage, stdout=out, stderr=subprocess.STDOUT)
                code = process.wait()
            with log.open('a') as out:
                out.write(json.dumps(dict(command=command, pid=process.pid, exit_code=code)) + '\n')
            if code:
                raise ValueError('Build command failed: ' + repr(command))
        run(['patch', '--batch', '-p1', '--input', str(local_patch)])
        patched_source = checked(source, PATCHED_SOURCE_SHA)
        classes = stage / 'classes'
        classes.mkdir()
        jars = sorted(p for p in ghidra.rglob('*.jar') if 'yajsw' not in str(p))
        for jar in jars:
            no_links(jar)
        run([str(javac), '-proc:none', '-g', '-cp', os.pathsep.join(map(str, jars)),
             '-d', str(classes), str(source)])
        replacements = {p.relative_to(classes).as_posix(): p.read_bytes() for p in classes.rglob('*.class')}
        target = io.BytesIO()
        with zipfile.ZipFile(io.BytesIO(original)) as src, zipfile.ZipFile(target, 'w') as dst:
            for info in src.infolist():
                dst.writestr(info, replacements.pop(info.filename, src.read(info)))
        if replacements or digest(target.getvalue()) != JAR_SHA:
            raise ValueError('Compiler output differs from pinned reviewed JAR')
        jar_changes(original, target.getvalue())
        files = {'dependency.json': encoded(IDENTITY), 'build.json': encoded(build_identity()),
                 'rollback.json': encoded(rollback_identity()), 'Debugger.jar': target.getvalue(),
                 'rollback/Debugger.jar': original, PATCH_NAME: patch_data,
                 'source/original.java': source_data, 'source/patched.java': patched_source}
        package = stage / 'debugger-java-dependency.zip'
        with zipfile.ZipFile(package, 'w') as z:
            for name, data in sorted(files.items()):
                info = zipfile.ZipInfo(name, (2026, 9, 6, 0, 0, 0))
                info.external_attr = (stat.S_IFREG | 0o644) << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                z.writestr(info, data)
        package_sha = digest(package.read_bytes())
        read_package(package, package_sha)
        receipt = dict(status='BUILT', dependencyVersion=VERSION, package='debugger-java-dependency.zip',
                       packageSha256=package_sha, identity=IDENTITY, compiler=(version.stdout + version.stderr).strip())
        (stage / 'receipt.json').write_bytes(encoded(receipt))
        publish(stage, output)
        return receipt
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def require_state(root, installed):
    checked(root / JAR, JAR_SHA if installed else BASE_SHA)
    if installed:
        if ordinary(root / MARKER) != encoded(IDENTITY):
            raise ValueError('Debugger Java identity marker mismatch')
    elif (root / MARKER).exists() or (root / MARKER).is_symlink():
        raise ValueError('Original distribution must not contain a Java dependency marker')


def update(mode, ghidra, output, files):
    ghidra = base(ghidra)
    output = output_path(ghidra, output)
    installing = mode == 'install'
    require_state(ghidra, not installing)
    before = snapshot(ghidra)
    stage = Path(tempfile.mkdtemp(prefix='.debugger-java-copy-', dir=output.parent))
    try:
        copied = stage / 'distribution'
        shutil.copytree(ghidra, copied)
        if snapshot(copied) != before:
            raise ValueError('Source changed during copy')
        (copied / JAR).write_bytes(files['Debugger.jar' if installing else 'rollback/Debugger.jar'])
        if installing:
            (copied / MARKER).write_bytes(encoded(IDENTITY))
            (copied / MARKER).chmod(0o644)
        else:
            (copied / MARKER).unlink()
        require_state(copied, installing)
        wanted = dict(before)
        wanted[JAR] = (JAR_SHA if installing else BASE_SHA, before[JAR][1])
        if installing:
            wanted[MARKER] = (digest(encoded(IDENTITY)), 0o644)
        else:
            wanted.pop(MARKER)
        if snapshot(copied) != wanted or snapshot(ghidra) != before:
            raise ValueError('Source or output changed; nothing published')
        receipt = dict(status='COPIED', action=mode, source=str(ghidra),
                       distribution=str(output / 'distribution'), dependencyVersion=VERSION,
                       sourceUnchanged=True, jarSha256=wanted[JAR][0])
        (stage / 'receipt.json').write_bytes(encoded(receipt))
        publish(stage, output)
        return receipt
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('mode', choices=['build', 'install', 'verify', 'rollback'])
    p.add_argument('--ghidra', required=True, type=Path)
    p.add_argument('--output', type=Path)
    p.add_argument('--package', type=Path)
    p.add_argument('--sha256')
    p.add_argument('--jdk', type=Path)
    p.add_argument('--patch', type=Path)
    a = p.parse_args()
    if a.mode == 'build':
        if not all((a.jdk, a.patch, a.output)):
            p.error('build requires --jdk --patch --output; no automatic downloads')
        result = build(a.ghidra, a.jdk, a.patch, a.output)
    elif a.mode == 'verify':
        require_state(base(a.ghidra), True)
        result = dict(status='MATCHED', identity=IDENTITY)
    else:
        if not all((a.package, a.sha256, a.output)):
            p.error('install/rollback requires --package --sha256 --output')
        files = read_package(a.package, a.sha256)
        result = update(a.mode, a.ghidra, a.output, files)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, zipfile.BadZipFile, subprocess.SubprocessError) as error:
        print(json.dumps(dict(status='REFUSED_OR_FAILED', reason=str(error))), file=sys.stderr)
        raise SystemExit(2)
