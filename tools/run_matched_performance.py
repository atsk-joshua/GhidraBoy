#!/usr/bin/env python3
"""Run an identical external harness against two preserved runtime packages.

Package installers verify original payloads before the external measurement harness
is compiled. Alternating isolated JVMs avoid reusing warmed trace databases.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import time


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command, cwd, env, log, timeout=300):
    record = dict(command=list(map(str, command)), cwd=str(cwd), started_at=time.time(),
                  environment={key: env[key] for key in ('JAVA_HOME', 'GHIDRA_INSTALL_DIR',
                      'GBC_PYTHON', 'GBC_EVIDENCE_DIR') if key in env},
                  wrapper_pid=os.getpid(), pid=None, exit_code=None, status='STARTING')
    receipt = log.with_suffix('.command.json')
    def save():
        temporary = receipt.with_suffix('.tmp')
        temporary.write_text(json.dumps(record, indent=2) + '\n')
        temporary.replace(receipt)
    save()
    try:
        with log.open('w') as output:
            process = subprocess.Popen(command, cwd=cwd, env=env, stdout=output,
                                       stderr=subprocess.STDOUT, start_new_session=True)
            record.update(pid=process.pid, status='RUNNING'); save()
            try:
                code = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
                record.update(exit_code=process.returncode, status='TIMEOUT')
                raise RuntimeError(f'Timed out: {log}')
            record.update(exit_code=code, status='PASS' if code == 0 else 'FAIL')
    except BaseException as error:
        record['error'] = repr(error)
        if record['status'] in ('STARTING', 'RUNNING'): record['status'] = 'WRAPPER_ERROR'
        raise
    finally:
        record.update(ended_at=time.time(), log_sha256=sha(log) if log.exists() else None)
        save()
    if code:
        raise RuntimeError(f'Command exited {code}: {log}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('baseline', 'candidate', 'ghidra', 'jdk', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--runs', type=int, default=3)
    args = parser.parse_args()
    if args.runs < 3:
        parser.error('At least three runs per runtime are required')
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    source = Path(__file__).resolve().parents[1] / 'debugger/tests/ghidra'
    sources = [source / name for name in ('RealTraceTest.java', 'MappingContractTest.java')]
    receipt = dict(schema=1, scope='Matched latency measurements; no final release qualification',
                   harness={str(p): sha(p) for p in sources}, runs=[])
    receipt['ghidra_jars'] = {str(p.relative_to(args.ghidra)): sha(p)
                             for p in sorted(args.ghidra.rglob('*.jar')) if 'yajsw' not in str(p)}
    (args.output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    for index in range(1, args.runs + 1):
        for label in ('baseline', 'candidate'):
            root = getattr(args, label).resolve()
            (root / 'build/projects').mkdir(parents=True, exist_ok=True)
            directory = args.output / f'{label}-{index}'
            directory.mkdir()
            home = directory / 'home'
            env = dict(os.environ, JAVA_HOME=str(args.jdk), GHIDRA_INSTALL_DIR=str(args.ghidra),
                       GBC_PYTHON=str(root / '.venv12/bin/python'), GBC_EVIDENCE_DIR=str(directory))
            run([env['GBC_PYTHON'], 'scripts/install.py', '--user-home', str(home)],
                root, env, directory / 'install.log')
            jars = sorted(p for location in (args.ghidra, home) for p in location.rglob('*.jar')
                          if 'yajsw' not in str(p))
            classpath = os.pathsep.join(str(p) for p in jars)
            classes = directory / 'classes'
            classes.mkdir()
            run([str(args.jdk / 'bin/javac'), '-proc:none', '-cp', classpath, '-d', str(classes),
                 *map(str, sources)], root, env, directory / 'compile.log')
            command = [str(args.jdk / 'bin/java'), '-Duser.home=' + str(home), '-cp',
                       str(classes) + os.pathsep + classpath, 'RealTraceTest', str(root), '--metrics']
            if label == 'baseline':
                command.append('--legacy-baseline')
            started = time.monotonic()
            print(f'Starting {label}-{index}', flush=True)
            run(command, root, env, directory / 'harness.log')
            if 'REAL_TRACE_TEST_PASSED' not in (directory / 'harness.log').read_text():
                raise RuntimeError(f'Missing harness completion marker: {directory}')
            report = directory / 'session-performance.json'
            row = dict(runtime=label, index=index, seconds=time.monotonic() - started,
                       command=command, report_sha256=sha(report),
                       harness_log_sha256=sha(directory / 'harness.log'), exit_code=0,
                       payloads={str(p.relative_to(root)): sha(p) for p in sorted(root.rglob('*'))
                                 if p.is_file() and (p.suffix in ('.dylib', '.so', '.zip')
                                                    or p.name == 'dependencies.lock.json')})
            receipt['runs'].append(row)
            (args.output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
            print(f'Completed {label}-{index}', flush=True)


if __name__ == '__main__':
    main()
