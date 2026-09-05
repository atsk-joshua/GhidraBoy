#!/usr/bin/env python3
"""Local setup, validation and result collection for the Steam Deck handoff."""
import argparse
import datetime
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
RESULT_NAMES = ('setup.log', 'failure.log', 'install.json', 'install.stderr.log', 'doctor.json', 'doctor.stderr.log', 'native.log', 'ghidra.log',
                'ui.log', 'integrated-growth.json', 'ui-actions.log')


def ghidra_version(path):
    properties = path / 'Ghidra/application.properties'
    if not properties.is_file():
        return None
    for line in properties.read_text().splitlines():
        if line.startswith('application.version='):
            return line.split('=', 1)[1].strip()
    return None


def choose_ghidra(explicit):
    if explicit:
        path = Path(explicit).expanduser().resolve()
    else:
        candidates = sorted({p.resolve() for base in (Path.home(), Path.home()/'Downloads', Path.home()/'Applications')
                             for p in base.glob('ghidra*PUBLIC') if ghidra_version(p) == '12.1.2'})
        if len(candidates) == 1:
            path = candidates[0]
        elif sys.stdin.isatty():
            for candidate in candidates:
                print('Found:', candidate)
            path = Path(input('Ghidra 12.1.2 folder: ').strip()).expanduser().resolve()
        else:
            raise RuntimeError('Pass --ghidra /absolute/path/to/ghidra_12.1.2_PUBLIC')
    if ghidra_version(path) != '12.1.2':
        raise RuntimeError(f'Ghidra 12.1.2 is required; selected folder: {path}')
    return path


def environment(args):
    if platform.system() != 'Linux' or platform.machine().lower() not in ('x86_64', 'amd64'):
        raise RuntimeError('This handoff setup targets Steam Deck desktop mode / Linux x86-64.')
    config_path = ROOT / '.local/deck-config.json'
    config = json.loads(config_path.read_text()) if config_path.exists() else {}
    ghidra = choose_ghidra(args.ghidra or config.get('ghidra') or os.environ.get('GHIDRA_INSTALL_DIR'))
    java_home = args.java_home or config.get('java_home') or os.environ.get('JAVA_HOME')
    if not java_home:
        java = shutil.which('java')
        if java:
            java_home = str(Path(java).resolve().parent.parent)
    if not java_home or not (Path(java_home).expanduser()/'bin/javac').is_file():
        raise RuntimeError('A JDK 21 or newer is required. Pass --java-home /absolute/path/to/jdk-21')
    java_home = Path(java_home).expanduser().resolve()
    version = subprocess.run([str(java_home/'bin/java'), '-version'], capture_output=True, text=True, timeout=8)
    major = re.search(r'version "(\d+)', version.stderr or version.stdout)
    if version.returncode or major is None or int(major.group(1)) < 21:
        raise RuntimeError('The selected JDK must be Java 21 or newer.')
    env = dict(os.environ, GHIDRA_INSTALL_DIR=str(ghidra), JAVA_HOME=str(java_home),
               GBC_PYTHON=str(ROOT/'.venv12/bin/python'))
    return env, {'ghidra': str(ghidra), 'java_home': str(java_home)}


def run(command, env, output):
    print('Running:', ' '.join(str(v) for v in command), flush=True)
    with output.open('w') as log:
        if output.suffix == '.json':
            with output.with_suffix('.stderr.log').open('w') as errors:
                result = subprocess.run([str(v) for v in command], cwd=ROOT, env=env, stdout=log, stderr=errors)
        else:
            result = subprocess.run([str(v) for v in command], cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
    if result.returncode:
        raise RuntimeError(f'Command failed ({result.returncode}). Details: {output}')


def collect(root=ROOT):
    results = root / '.local/deck-results'
    results.mkdir(parents=True, exist_ok=True)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    output = root / f'GhiGBC-results-{stamp}.zip'
    with zipfile.ZipFile(output, 'x', zipfile.ZIP_DEFLATED) as archive:
        for name in RESULT_NAMES:
            path = results / name
            if path.is_file() and not path.is_symlink():
                archive.write(path, 'GhiGBC-results/' + name)
        notes = root / 'NOTES.txt'
        if notes.is_file() and not notes.is_symlink():
            archive.write(notes, 'GhiGBC-results/notes.txt')
        archive.writestr('GhiGBC-results/README.txt',
                         'These local troubleshooting logs may include your hostname and file paths. Review before sending. '
                         'The collector does not include ROMs, projects, checkpoints, or saves.\n')
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('setup', 'validate', 'collect'))
    parser.add_argument('--ghidra', help='Ghidra 12.1.2 folder; remembered after setup')
    parser.add_argument('--java-home', help='JDK folder; remembered after setup')
    parser.add_argument('--ui', action='store_true', help='Run only the interactive teaching-ROM button walkthrough after the automated checks')
    args = parser.parse_args()
    if args.action == 'collect':
        print(collect())
        return
    env, config = environment(args)
    results = ROOT / '.local/deck-results'
    results.mkdir(parents=True, exist_ok=True)
    python = ROOT / '.venv12/bin/python'
    try:
        if args.action == 'setup':
            if not (3, 10) <= sys.version_info[:2] < (3, 15):
                raise RuntimeError('Use a supported Python version: 3.10–3.14.')
            print('Close Ghidra before installing. Existing managed extensions are backed up for rollback.')
            run([sys.executable, ROOT/'scripts/prepare_runtime.py'], env, results/'setup.log')
            run([python, ROOT/'scripts/install.py'], env, results/'install.json')
            (ROOT/'.local/deck-config.json').write_text(json.dumps(config, indent=2)+'\n')
        elif not python.is_file():
            raise RuntimeError('Run Setup.sh first to prepare the matched Python environment.')
        run([python, ROOT/'scripts/doctor.py', '--ghidra', config['ghidra'], '--rom', ROOT/'build/teaching.gbc'], env, results/'doctor.json')
        doctor = json.loads((results/'doctor.json').read_text())
        if not doctor.get('ready_for_desktop_validation'):
            raise RuntimeError(f'Desktop prerequisites are incomplete; inspect {results / "doctor.json"}. SDL2 and a desktop session are required.')
        if args.action == 'validate':
            if args.ui:
                print('Follow docs/UI_ACTION_VALIDATION.md in the Ghidra window. Each action has an eight-minute limit.', flush=True)
                run(['bash', ROOT/'scripts/test_ui_actions.sh'], env, results/'ui.log')
                source = ROOT/'docs/evidence/ui-actions.log'
                if source.exists():
                    shutil.copy2(source, results/source.name)
            else:
                run(['bash', ROOT/'scripts/test_native.sh'], env, results/'native.log')
                run(['bash', ROOT/'scripts/test_ghidra.sh', '--growth'], env, results/'ghidra.log')
                growth = ROOT/'docs/evidence/integrated-growth.json'
                if growth.exists():
                    shutil.copy2(growth, results/growth.name)
        print('Setup complete. Restart Ghidra and follow START-HERE.md.' if args.action == 'setup'
              else 'Checks passed. Complete the playable-window and focus checks in START-HERE.md.')
    finally:
        # Copy a partially completed UI log too, so failures are reviewable.
        if args.action == 'validate' and args.ui:
            source = ROOT/'docs/evidence/ui-actions.log'
            if source.exists():
                shutil.copy2(source, results/source.name)
        print('Results folder:', results)
        print('Collect a shareable log ZIP with: bash Collect-results.sh')


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError, ValueError, subprocess.TimeoutExpired) as error:
        print(f'GhiGBC: {error}', file=sys.stderr)
        try:
            failure = ROOT / '.local/deck-results/failure.log'
            failure.parent.mkdir(parents=True, exist_ok=True)
            failure.write_text(datetime.datetime.now(datetime.timezone.utc).isoformat()+'\n'+str(error)+'\n')
        except OSError:
            pass
        sys.exit(1)
