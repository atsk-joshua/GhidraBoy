#!/usr/bin/env python3
"""Record fixed-workload idle resources and owned-process cleanup via real Ghidra RMI.

Install a verified, preserved runtime and compile only the external test harness.
The short idle series supplements, and cannot replace, the declared release soak.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import statistics
import subprocess
import time

from assess_performance import RESOURCES, trend
from run_matched_performance import run, sha


def processes():
    """Read identities for descendant and reparented-process accounting."""
    output = subprocess.check_output(['ps', '-axo', 'pid=,ppid=,pgid=,lstart=,comm='], text=True)
    result = {}
    for line in output.splitlines():
        fields = line.split(None, 8)
        if len(fields) == 9:
            result[int(fields[0])] = dict(pid=int(fields[0]), ppid=int(fields[1]),
                                         group=int(fields[2]), started=' '.join(fields[3:8]),
                                         command=fields[8])
    return result


def owned_processes(group, observed):
    all_processes = processes()
    # Group membership survives reparenting. Remembered identities cover descendants
    # that create another group/session; start time guards against PID reuse.
    owned = {pid: row for pid, row in all_processes.items()
             if row['group'] == group or (str(pid) in observed and
                                         row['started'] == observed[str(pid)]['started'])}
    while True:
        children = {pid: row for pid, row in all_processes.items() if row['ppid'] in owned}
        if children.keys() <= owned.keys():
            return owned
        owned.update(children)


def assess(report, limits):
    if report['status'] != 'COMPLETED_MEASUREMENTS':
        raise ValueError('Idle measurements did not complete')
    idle = [s for s in report['samples'] if s['phase'] == 'paused_idle']
    stable = [dict(s, cycle=i + 1) for i, s in enumerate(idle)
              if i + 1 > limits['warmup_cycles']]
    count = limits['window_samples']
    if len(stable) < 2 * count or idle[-1]['seconds'] - idle[0]['seconds'] < 119:
        raise ValueError('Insufficient fixed-workload idle series')
    for field in ('capture', 'snapshot', 'ticks', 'trace_bytes'):
        if len({s[field] for s in idle}) != 1:
            raise ValueError(f'Idle workload changed: {field}')
    if any(s['dropped'] != limits['dropped_events'] for s in idle):
        raise ValueError('Idle series has unexplained dropped events')
    checks = {}
    for field, budget in RESOURCES.items():
        before = statistics.median(s[field] for s in stable[:count])
        after = statistics.median(s[field] for s in stable[-count:])
        checks[field] = dict(initial_window=before, final_window=after,
                             growth=after - before, declared_soak_allowance=limits[budget],
                             within_comparator=after - before <= limits[budget],
                             trend=trend(stable, field, count))
    closed = [s for s in report['samples'] if s['phase'] == 'post_close']
    if len(closed) != 5 or any(s['agent_alive'] for s in closed):
        raise ValueError('Post-close primary agent cleanup incomplete')
    if report.get('surviving_owned_descendants') != []:
        raise ValueError('Owned launch-boundary descendant audit incomplete')
    return dict(scope='120s fixed-workload idle; original soak resource allowances used only as comparators. No new plateau threshold or full release-soak PASS.',
                comparators=checks,
                post_close={field: [s[field] for s in closed]
                            for field in ('seconds', 'ghidra_rss_kib', 'ghidra_threads', 'ghidra_handles')})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('runtime', 'ghidra', 'jdk', 'output', 'limits'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--scope', required=True, help='Exact candidate identity/qualification scope')
    args = parser.parse_args()
    root = args.runtime.resolve()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    home = output / 'home'
    source = Path(__file__).resolve().parents[1] / 'debugger/tests/ghidra'
    sources = [source / name for name in ('RealTraceTest.java', 'MappingContractTest.java')]
    harness_source = output / 'harness-source'
    harness_source.mkdir()
    for source_file in sources:
        (harness_source / source_file.name).write_bytes(source_file.read_bytes())
    sources = [harness_source / path.name for path in sources]
    limits = json.loads(args.limits.read_text())
    (output / 'declared-limits.json').write_bytes(args.limits.read_bytes())
    receipt = dict(schema=1, status='RUNNING', scope=args.scope, runtime=str(root),
                   harness={str(p): sha(p) for p in sources}, limits_sha256=sha(args.limits),
                   runner_sha256=sha(Path(__file__)),
                   process_audit_scope='Private process group and recursive descendants polled every second; observed identities followed across reparenting/session changes. Java also inventories ProcessHandles at owned launch boundaries and checks after disposal. Short-lived probe processes may be missed; no kernel-level exhaustive fork tracing claim.',
                   observed_processes={}, process_samples=[])
    env = dict(os.environ, JAVA_HOME=str(args.jdk), GHIDRA_INSTALL_DIR=str(args.ghidra),
               GBC_PYTHON=str(root / '.venv12/bin/python'), GBC_EVIDENCE_DIR=str(output))
    run([env['GBC_PYTHON'], 'scripts/install.py', '--user-home', str(home)], root, env, output / 'install.log')
    receipt['payloads'] = {str(p.relative_to(root)): sha(p) for p in sorted(root.rglob('*'))
                           if p.is_file() and (p.suffix in ('.dylib', '.so', '.zip')
                                              or p.name in ('dependencies.lock.json', 'runtime-manifest.json'))}
    jars = sorted(p for location in (args.ghidra, home) for p in location.rglob('*.jar') if 'yajsw' not in str(p))
    classpath = os.pathsep.join(str(p) for p in jars)
    classes = output / 'classes'
    classes.mkdir()
    run([str(args.jdk / 'bin/javac'), '-proc:none', '-cp', classpath, '-d', str(classes), *map(str, sources)],
        root, env, output / 'compile.log')
    command = [str(args.jdk / 'bin/java'), '-Duser.home=' + str(home), '-cp',
               str(classes) + os.pathsep + classpath, 'RealTraceTest', str(root), '--failure-lifecycle', '--idle-cleanup']
    receipt['command'] = command
    started = time.monotonic()
    def save():
        (output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    with (output / 'harness.log').open('w') as log:
        process = subprocess.Popen(command, cwd=root, env=env, stdout=log, stderr=subprocess.STDOUT,
                                   start_new_session=True)
        receipt['ghidra_pid'] = process.pid
        try:
            while process.poll() is None:
                group = owned_processes(process.pid, receipt['observed_processes'])
                receipt['observed_processes'].update({str(pid): row for pid, row in group.items()})
                receipt['process_samples'].append(dict(seconds=time.monotonic() - started, pids=sorted(group)))
                save()
                if time.monotonic() - started > 360:
                    raise RuntimeError('Idle/cleanup harness exceeded 360 seconds')
                time.sleep(1)
            receipt['exit_code'] = process.returncode
            # Allow ordinary child reaping, but never hide survivors by killing before receipt.
            time.sleep(2)
            survivors = owned_processes(process.pid, receipt['observed_processes'])
            receipt['surviving_processes'] = list(survivors.values())
            receipt['seconds'] = time.monotonic() - started
            if survivors or process.returncode:
                raise RuntimeError(f'Harness exit {process.returncode}; survivors {sorted(survivors)}')
            if 'REAL_TRACE_TEST_PASSED' not in (output / 'harness.log').read_text():
                raise RuntimeError('Missing real-RMI completion marker')
            report = output / 'session-idle-cleanup.json'
            assessment = assess(json.loads(report.read_text()), limits['soak'])
            (output / 'assessment.json').write_text(json.dumps(assessment, indent=2) + '\n')
            receipt['status'] = 'SCOPED_CHECKS_PASS'
        except BaseException as error:
            receipt['status'] = 'FAIL'
            receipt['error'] = repr(error)
            raise
        finally:
            receipt['final_group_before_forced_cleanup'] = list(owned_processes(process.pid, receipt['observed_processes']).values())
            for name in ('harness.log', 'session-idle-cleanup.json', 'assessment.json', 'real-agent.log'):
                path = output / name
                if path.exists():
                    receipt.setdefault('evidence_sha256', {})[name] = sha(path)
            save()
            for sig in (signal.SIGTERM, signal.SIGKILL):
                remaining = owned_processes(process.pid, receipt['observed_processes'])
                for pid in remaining:
                    try:
                        os.kill(pid, sig)
                    except ProcessLookupError:
                        pass
                if not remaining:
                    break
                time.sleep(2)
            process.wait()
    print(json.dumps(dict(status=receipt['status'], receipt=str(output / 'receipt.json'))))


if __name__ == '__main__':
    main()
