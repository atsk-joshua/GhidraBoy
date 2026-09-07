#!/usr/bin/env python3
"""Fresh rooted state-continuation qualification through separate installed public-workflow processes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import zipfile


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fixture_bytes():
    """Self-authored MBC3 instructions; CPU 4100 is visited in physical banks 3 and 2."""
    rom = bytearray(0x10000)
    rom[0x104:0x134] = bytes.fromhex(
        'ce ed 66 66 cc 0d 00 0b 03 73 00 83 00 0c 00 0d 00 08 11 1f 88 89 00 0e '
        'dc cc 6e e6 dd dd d9 99 bb bb 67 63 6e 0e ec cc dd dc 99 9f bb b9 33 3e')
    rom[0x147], rom[0x148] = 0x13, 1
    regions = {
        0x100: '00c35001',
        0x28: 'ea0020e9',
        0x150: 'cd0002020044ea14c2c9',
        0x180: 'efc9',
        0x190: 'efc9',
        0x200: 'e12aea00205e235623e5d5c9',
        0x240: 'ea0020c30041',
        0x260: '3e5b37c9',
        0x300: '3e03ea00202100427eea10c2c30041',
        0x4500: 'ef',
        0x8000: 'c9',
        0x8100: '2100427eea11c2cd6002ea12c2c9',
        0x8200: '5c',
        0x8400: '3e6ac9',
        0x8501: 'c30003',
        0x8600: 'ca20463e03ea0020',
        0x8620: '3e02ea0020c30047',
        0x8700: '3e22ea11c2c9',
        0xc100: '3e02c34002',
        0xc200: 'a7',
        0xc608: 'c30047',
        0xc700: '3e33ea11c2c9',
    }
    for offset, encoded in regions.items():
        code = bytes.fromhex(encoded)
        rom[offset:offset + len(code)] = code
    checksum = 0
    for byte in rom[0x134:0x14d]:
        checksum = (checksum - byte - 1) & 255
    rom[0x14d] = checksum
    rom[0x14e:0x150] = (sum(rom) & 65535).to_bytes(2, 'big')
    return rom


def classify_log(log):
    unexpected, native = [], []
    for line in log.splitlines():
        if 'ERROR' not in line and 'WARN' not in line:
            continue
        # This campaign catches intentional stale rejection inside its script.
        # No process WARN/ERROR is expected, including unreachable-block reports.
        unexpected.append(line)
        if 'WARN' in line and 'Removing unreachable block' in line:
            native.append(line)
    return unexpected, native


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('ghidra', 'jdk', 'zip', 'work'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    ghidra, work, jdk = args.ghidra.resolve(), args.work.resolve(), args.jdk.resolve()
    temporary_roots = (Path('/tmp').resolve(), Path(tempfile.gettempdir()).resolve())
    if not any(ghidra.is_relative_to(root) for root in temporary_roots) or 'ghidraboy' not in str(ghidra):
        parser.error('Requires a disposable temporary ghidraboy distribution')
    if work.exists():
        parser.error('Work must be new; preserve all earlier receipts')
    extension = ghidra / 'Ghidra/Extensions/GhidraBoy'
    if extension.exists():
        parser.error('Use a fresh disposable distribution without GhidraBoy')
    work.mkdir(parents=True)
    installed_members = {}
    with zipfile.ZipFile(args.zip) as archive:
        for member in archive.infolist():
            destination = (extension.parent / member.filename).resolve()
            if not destination.is_relative_to(extension) or Path(member.filename).is_absolute():
                parser.error('Extension archive contains a path outside GhidraBoy')
        archive.extractall(extension.parent)
        for member in archive.infolist():
            if member.is_dir():
                continue
            expected = hashlib.sha256(archive.read(member)).hexdigest()
            actual = digest(extension.parent / member.filename)
            if actual != expected:
                raise RuntimeError('Installed package member mismatch: ' + member.filename)
            installed_members[member.filename] = actual
    fixture = work / 'state-discovery-mbc3-v1.gb'
    fixture.write_bytes(fixture_bytes())
    repo = Path(__file__).resolve().parents[1]
    scripts = work / 'scripts'
    scripts.mkdir()
    script = scripts / 'GhidraBoySa01State.java'
    shutil.copyfile(repo / 'src/test/scripts/GhidraBoySa01State.java', script)
    for folder in ('profile', 'projects', 'cache'):
        (work / folder).mkdir()
    env = dict(os.environ, JAVA_HOME=str(jdk), JAVA_TOOL_OPTIONS=f'-Duser.home={work / "profile"}',
               XDG_CACHE_HOME=str(work / 'cache'))
    source_files = [repo / 'build.gradle.kts', Path(__file__).resolve()]
    for directory in ('src/main', 'src/test', 'data/languages', 'ghidra_scripts'):
        source_files.extend(path for path in (repo / directory).rglob('*') if path.is_file())
    identities = dict(
        fixtureSha256=digest(fixture), extensionSha256=digest(args.zip),
        scriptSha256=digest(script), driverSha256=digest(Path(__file__)),
        installedMembers=installed_members, ghidra=str(ghidra), jdk=str(jdk), extension=str(extension),
        sourceCommit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=repo, text=True).strip(),
        sourceHashes={str(path.relative_to(repo)): digest(path) for path in sorted(set(source_files))},
        discovery='fresh pre-analysis import: all consumed Instructions absent; state4500 and inline150 roots have no Functions; shared conditional callee4600 has an explicitly prepared user Function/name/comment to verify preservation, with no Instructions',
        scope='repeated same-CPU bank fetches, distinct banked data, direct mapper effects, later ordinary call, inline payload, two flag-qualified callee contexts, public selection and cancellation; not whole-ROM discovery',
    )
    for key, path in {
        'nativeDecompilerSha256': ghidra / 'Ghidra/Features/Decompiler/os/mac_arm_64/decompile',
        'ghidraApplicationPropertiesSha256': ghidra / 'Ghidra/application.properties',
        'softwareModelingSha256': ghidra / 'Ghidra/Framework/SoftwareModeling/lib/SoftwareModeling.jar',
        'jdkReleaseSha256': jdk / 'release',
        'jdkModulesSha256': jdk / 'lib/modules',
    }.items():
        if path.is_file():
            identities[key] = digest(path)
    records = []
    phases = [('prepare', 'verify'), ('context-cancel', 'verify'), ('annotated-reapply', 'verify'),
              (None, 'edit'), ('stale-reapply', 'verify'), ('remove', 'removed-verify'), (None, 'removed-reopen')]
    for index, (pre, post) in enumerate(phases):
        command = [str(ghidra / 'support/analyzeHeadless'), str(work / 'projects'), 'sa01-state']
        command += ['-import', str(fixture)] if index == 0 else ['-process', fixture.name]
        command += ['-scriptPath', str(scripts)]
        if pre:
            command += ['-preScript', script.name, pre, str(work)]
        command += ['-postScript', script.name, post, str(work)]
        logfile = work / f'phase-{index}.log'
        with logfile.open('w') as output:
            result = subprocess.run(command, cwd=work, env=env, stdout=output, stderr=subprocess.STDOUT)
        log = logfile.read_text()
        markers = ['SA01_STATE_' + mode.upper().replace('-', '_') + '_PASS' for mode in (pre, post) if mode]
        unexpected, native = classify_log(log)
        passed = result.returncode == 0 and all(marker in log for marker in markers) and not unexpected
        expected = work / 'expected-saved-rejections.json'
        records.append(dict(command=command, exitCode=result.returncode, markers=markers,
                            expectedRejections=json.loads(expected.read_text()) if pre == 'stale-reapply' and expected.exists() else [],
                            unexpectedWarningsAndErrors=unexpected, nativeDiagnostics=native, passed=passed))
        (work / 'run.json').write_text(json.dumps(dict(**identities, processes=records), indent=2) + '\n')
        print(f'phase {index}: {"PASS" if passed else "FAIL"} ({logfile})', flush=True)
        if not passed:
            raise SystemExit(1)
        if index == 2:
            shutil.copytree(work / 'projects', work / 'gui-projects')


if __name__ == '__main__':
    main()
