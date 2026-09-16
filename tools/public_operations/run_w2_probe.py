#!/usr/bin/env python3
"""Compile a passive normal-provider W2 probe and optionally run on a new project copy.

Desktop capture is opt-in. No installed payload change, private controller intervention
or pre-witness proof refresh occurs. Published DecompileData observations do not
establish full request coverage.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import time
import zipfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('runtime', 'jdk', 'candidate', 'project-dir', 'out'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--project-name', required=True)
    parser.add_argument('--program', required=True)
    parser.add_argument('--run', action='store_true', help='Run the real normal UI')
    parser.add_argument('--desktop-capture', action='store_true', help='Capture actual visible desktop window images for aggregate visual review')
    parser.add_argument('--observe-native', action='store_true', help='Pinned 12.1.3 public API breakpoints via loopback JDI; changes request timing')
    parser.add_argument('--comparison', action='store_true', help='Explicit refresh and reversal only after retaining pre-rescue display')
    parser.add_argument('--physical-diagnostic', action='store_true', help='Run only the bounded stock-carrier/physical-destination discriminator')
    parser.add_argument('--w2-r3', action='store_true', help='Run the bounded AUTH-R3 pollution/physical/topology/save qualification')
    parser.add_argument('--immutable-reopen', action='store_true', help='Open the copied saved Program immutably for the first-use witness')
    parser.add_argument('--baseline', type=Path, help='Saved authority receipt required by --immutable-reopen')
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    write = lambda name, value: (out / name).write_text(json.dumps(value, indent=2) + '\n')
    archive_hash = sha(args.candidate)
    with zipfile.ZipFile(args.candidate) as archive:
        for member in archive.infolist():
            if not member.is_dir() and archive.read(member) != (args.runtime / 'Ghidra/Extensions' / member.filename).read_bytes():
                raise RuntimeError('Installed candidate mismatch: ' + member.filename)
    write('candidate.json', {'archive': str(args.candidate), 'sha256': archive_hash})
    original = args.project_dir.resolve()
    if original == out or original in out.parents:
        raise ValueError('Output must be outside input project directory')
    inputs = {str(p.relative_to(original)): sha(p) for p in original.rglob('*') if p.is_file()}
    shutil.copytree(original, out / 'projects')
    for relative, expected in inputs.items():
        if sha(out / 'projects' / relative) != expected or sha(original / relative) != expected:
            raise RuntimeError('Fixture changed while copying: ' + relative)
    write('fixture-inputs.json', inputs)
    classes = out / 'classes'
    bootstrap = out / 'bootstrap'
    classes.mkdir()
    bootstrap.mkdir()
    (out / 'captures').mkdir()
    installed = args.runtime / 'Ghidra/Extensions/GhidraBoy/ghidra_scripts'
    sources = [Path(__file__), repo / 'tools/public_operations/W2NormalProbe.java', repo / 'tools/public_operations/W2Bootstrap.java',
               repo / 'tools/public_operations/fi/gekkio/ghidraboy/W2AuthorityProbe.java',
               *sorted((repo / 'src/test/scripts').glob('GhidraBoy*.java')), repo / 'src/test/scripts/Sm83PreservationInventory.java', installed / 'GhidraBoyTools.java']
    sources += [repo / 'tools/public_operations/normalize_w2.py', repo / 'tools/public_operations/check_window.py',
                repo / 'tools/check_conditional_calls.py', repo / 'tools/check_stock_window.py', repo / 'tools/check_predicated_calls.py']
    if args.observe_native:sources.append(repo / 'tools/public_operations/W2NativeObserver.java')
    identities = {str(p): sha(p) for p in sources}
    snapshots = {}
    for p in sources:
        dest = out / 'sources' / (p.relative_to(repo) if p.is_relative_to(repo) else Path('installed') / p.name)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(p, dest)
        if sha(dest) != identities[str(p)]:
            raise RuntimeError('Source changed while copying: ' + str(p))
        snapshots[str(p)] = str(dest.relative_to(out))
    write('source-inputs.json', identities)
    # Same observed source inventory under the aggregate checker's established name.
    write('driver-inputs.json', identities)
    write('source-snapshots.json', snapshots)
    runtime_files = [*args.runtime.rglob('*.jar'), *filter(Path.is_file, (args.runtime / 'Ghidra/Extensions/GhidraBoy').rglob('*')),
                     *args.runtime.glob('Ghidra/Features/Decompiler/os/*/decompile'), args.runtime / 'support/launch.properties', args.jdk / 'bin/java', args.jdk / 'bin/javac', args.candidate]
    runtime_ids = {str(p): sha(p) for p in runtime_files}
    write('runtime-inputs.json', runtime_ids)
    cmd = [str(args.jdk / 'bin/javac'), '-proc:none', '-cp', os.pathsep.join(map(str, args.runtime.rglob('*.jar'))),
           '-sourcepath', os.pathsep.join(map(str, [repo / 'src/test/scripts', installed, repo / 'tools/public_operations'])), '-d', str(classes), *map(str, sources[1:4])]
    result = subprocess.run(cmd, text=True, capture_output=True)
    write('compile.json', dict(argv=cmd, exit=result.returncode, stdout=result.stdout, stderr=result.stderr))
    result.check_returncode()
    (classes / 'W2Bootstrap.class').rename(bootstrap / 'W2Bootstrap.class')
    if args.observe_native:
        if 'application.version=12.1.3' not in (args.runtime / 'Ghidra/application.properties').read_text():
            raise RuntimeError('Public return breakpoints require pinned Ghidra 12.1.3')
        observer_compile = [str(args.jdk / 'bin/javac'), '--add-modules', 'jdk.jdi', '-d', str(out / 'observer'), str(repo / 'tools/public_operations/W2NativeObserver.java')]
        result = subprocess.run(observer_compile, text=True, capture_output=True)
        write('compile-observer.json', dict(argv=observer_compile, exit=result.returncode, stdout=result.stdout, stderr=result.stderr))
        result.check_returncode()
    class_ids = {str(p.relative_to(out)): sha(p) for d in [classes, bootstrap, out / 'observer'] for p in d.rglob('*.class')}
    write('compiled-classes.json', class_ids)
    vm = [line.split('=', 1)[1] for line in (args.runtime / 'support/launch.properties').read_text().splitlines() if line.startswith('VMARGS=')]
    for key, child in [('user.home', 'home'), ('application.settingsdir', 'settings'), ('application.cachedir', 'cache'), ('application.tempdir', 'temp'), ('java.io.tmpdir', 'temp')]:
        (out / 'profile' / child).mkdir(parents=True, exist_ok=True)
        vm.append('-D' + key + '=' + str(out / 'profile' / child))
    cmd = [str(args.jdk / 'bin/java'), *vm, '-Xdock:name=GhidraBoy W2 Passive Observer', '-cp',
           str(args.runtime / 'Ghidra/Framework/Utility/lib/Utility.jar') + os.pathsep + str(bootstrap), 'ghidra.Ghidra', 'W2Bootstrap',
           str(classes), str(out / 'projects'), args.project_name, str(out / 'captures'), str(repo / 'tools/public_operations'), str(installed), args.program]
    observer_cmd = None
    if args.desktop_capture:cmd.insert(1, '-Dghidraboy.desktopCapture=true')
    if args.comparison:cmd.insert(1, '-Dghidraboy.w2Comparison=true')
    if args.physical_diagnostic:cmd.insert(1, '-Dghidraboy.w2PhysicalDiagnostic=true')
    if args.w2_r3:cmd.insert(1, '-Dghidraboy.w2R3=true')
    if args.immutable_reopen:
        if args.baseline is None:
            parser.error('--immutable-reopen requires --baseline')
        cmd.insert(1, '-Dghidraboy.w2R3Immutable=true')
        cmd.insert(1, '-Dghidraboy.w2R3Baseline=' + str(args.baseline.resolve()))
    if args.observe_native:
        port = 5005  # Preparation only: no socket access or port reservation.
        if args.run:
            with socket.socket() as address:
                address.bind(('127.0.0.1', 0))
                port = address.getsockname()[1]
        cmd.insert(1, '-agentlib:jdwp=transport=dt_socket,server=y,suspend=y,address=127.0.0.1:' + str(port))
        observer_cmd = [str(args.jdk / 'bin/java'), '--add-modules', 'jdk.jdi', '-cp', str(out / 'observer'), 'W2NativeObserver', str(port), str(out / 'native-events.tsv')]
        write('observer-command.json', observer_cmd)
    write('command.json', cmd)
    write('command-sha256.json', sha(out / 'command.json'))
    if not args.run:
        return 0
    for name, expected in {**identities, **runtime_ids}.items():
        if sha(Path(name)) != expected:
            raise RuntimeError('Prepared input changed: ' + name)
    receipt = dict(start_ns=time.time_ns(), normal_provider_scripted_observation=True, screen_capture=args.desktop_capture,
                   visual_acceptance='CAPTURED_UNREVIEWED' if args.desktop_capture else 'UNOBSERVED', argv=cmd)
    with (out / 'launch.log').open('x') as log:
        process = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT)
        receipt['pid'] = process.pid
        observer = None
        observer_log = None
        if observer_cmd:
            time.sleep(1)
            observer_log = (out / 'observer.log').open('x')
            observer = subprocess.Popen(observer_cmd, stdout=observer_log, stderr=subprocess.STDOUT)
            receipt['observer_pid'] = observer.pid
            receipt['observer_effect'] = 'Public boundary and provider exception event threads suspend for supported snapshots; compare timing to uninstrumented run'
        write('process-start.json', receipt)
        try:
            receipt['exit'] = process.wait(timeout=600)
        except subprocess.TimeoutExpired:
            receipt['timeout'] = True
            process.terminate()
            try:
                receipt['exit'] = process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                process.kill()
                receipt['exit'] = process.wait()
                receipt['forced_cleanup'] = True
        if observer is not None:
            try:
                receipt['observer_exit'] = observer.wait(timeout=10)
            except subprocess.TimeoutExpired:
                observer.terminate()
                receipt['observer_exit'] = observer.wait(timeout=10)
            observer_log.close()
    receipt['end_ns'] = time.time_ns()
    write('process-exit.json', receipt)
    return 1 if receipt['exit'] or receipt.get('timeout') or receipt.get('observer_exit', 0) else 0


if __name__ == '__main__':
    raise SystemExit(main())
