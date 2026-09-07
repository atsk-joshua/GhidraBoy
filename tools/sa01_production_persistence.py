#!/usr/bin/env python3
"""Installed production software-call workflow and native checks across separate processes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import shutil
import tempfile
import zipfile


def classify_log(log, post):
    expected, failures, native_diagnostics, other_warnings = [], [], [], []
    rejection = ('Unresolved software-call injection at 0150: '
                 'Software-call annotations changed after review')
    expected_lines = {
        'WARN  ' + rejection + ' (SymbolicPropogator)',
        'ERROR Unexpected Exception: ' + rejection
        + ' (DecompileProcess) java.lang.IllegalArgumentException: ' + rejection,
    }
    for line in log.splitlines():
        if 'ERROR' not in line and 'WARN' not in line:
            continue
        stale = post == 'edited-reopen' and line.strip() in expected_lines
        if stale:
            expected.append(line)
        else:
            # Categories remain useful evidence, but neither native diagnostics nor
            # unfamiliar warnings are permission to pass an installed phase.
            failures.append(line)
            if 'WARN' in line and 'Removing unreachable block' in line:
                native_diagnostics.append(line)
            elif 'WARN' in line:
                other_warnings.append(line)
    return expected, failures, native_diagnostics, other_warnings


def install_extension(package, extension):
    installed_members = {}
    with zipfile.ZipFile(package) as archive:
        for member in archive.infolist():
            destination = (extension.parent / member.filename).resolve()
            if not destination.is_relative_to(extension.resolve()) or Path(member.filename).is_absolute():
                raise ValueError('Extension archive contains a path outside GhidraBoy')
        archive.extractall(extension.parent)
        for member in archive.infolist():
            if member.is_dir():
                continue
            expected = hashlib.sha256(archive.read(member)).hexdigest()
            actual = hashlib.sha256((extension.parent / member.filename).read_bytes()).hexdigest()
            if actual != expected:
                raise RuntimeError('Installed package member mismatch: ' + member.filename)
            installed_members[member.filename] = actual
    return installed_members


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("ghidra", "jdk", "zip", "work"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    ghidra, work = args.ghidra.resolve(), args.work.resolve()
    roots = (Path('/tmp').resolve(), Path(tempfile.gettempdir()).resolve())
    if not any(ghidra.is_relative_to(root) for root in roots) or 'ghidraboy' not in str(ghidra):
        parser.error('Requires a disposable temporary ghidraboy distribution')
    if work.exists():
        parser.error('Work must be new; preserve earlier receipts')
    extension = ghidra / 'Ghidra/Extensions/GhidraBoy'
    if extension.exists():
        parser.error('Use a fresh disposable distribution without GhidraBoy')
    work.mkdir(parents=True)
    installed_members = install_extension(args.zip, extension)
    rom = bytearray(0x10000)
    rom[0x104:0x134] = bytes.fromhex(
        'ce ed 66 66 cc 0d 00 0b 03 73 00 83 00 0c 00 0d 00 08 11 1f 88 89 00 0e '
        'dc cc 6e e6 dd dd d9 99 bb bb 67 63 6e 0e ec cc dd dc 99 9f bb b9 33 3e')
    rom[0x100:0x104] = bytes.fromhex('00 c3 50 01')
    rom[0x147], rom[0x148] = 0x13, 1
    rom[0x200:0x20c] = bytes.fromhex('e1 2a ea 00 20 5e 23 56 23 e5 d5 c9')
    for site, bank in ((0x150, 1), (0x160, 2)):
        rom[site:site+10] = bytes([0xcd, 0, 2, bank, 0, 0x41, 0xea, 0, 0xc1, 0xc9])
        at = bank * 0x4000 + 0x100
        rom[at:at+4] = bytes([0x3e, 0x50 + bank, 0x37, 0xc9])
    rom[0x28:0x2c] = bytes.fromhex('ea 00 20 e9')
    rom[0x4200:0x4202] = bytes.fromhex('ef 76')
    rom[0x8201] = 0xc9
    rom[0x8300] = 0xc9
    rom[0x4500:0x4507] = bytes.fromhex('cd 00 02 02 00 50 76')
    rom[0x8504:0x8507] = bytes.fromhex('00 43 c9')
    rom[0x170:0x174] = bytes.fromhex('cd 00 03 c9')
    rom[0x300:0x304] = bytes.fromhex('ea 00 20 e9')
    nested_helper = bytes.fromhex('f5 79 ea 00 20 01 2a 03 c5 e9 c1 78 ea 00 20 c9')
    rom[0x320:0x320+len(nested_helper)] = nested_helper
    rom[0x8600:0x860c] = bytes.fromhex('3e 02 01 03 00 21 00 43 cd 20 03 c9')
    rom[0xc300:0xc307] = bytes.fromhex('cd 60 03 3e 5a 37 c9')
    rom[0x360:0x362] = bytes.fromhex('00 c9')
    # Separate banked restoring and constant-return callers, plus terminal/nonlocal cases.
    rom[0x340:0x34e] = bytes.fromhex('ea 00 20 01 48 03 c5 e9 3e 03 ea 00 20 c9')
    rom[0x4700:0x4707] = bytes.fromhex('cd 20 03 ea 02 c1 c9')
    rom[0x4800:0x4804] = bytes.fromhex('cd 40 03 76')
    rom[0xc803:0xc807] = bytes.fromhex('ea 03 c1 c9')
    rom[0x8400:0x8404] = bytes.fromhex('3e 5b 37 c9')
    rom[0x180:0x187] = bytes.fromhex('cd 40 03 ea 04 c1 c9')
    rom[0x8900:0x8902] = bytes.fromhex('18 fe')
    rom[0x190:0x196] = bytes.fromhex('cd 00 03 3e 55 c9')
    rom[0x1b0:0x1b3] = bytes.fromhex('3e 66 c9')
    rom[0x8a00:0x8a08] = bytes.fromhex('f8 00 36 b0 23 36 01 c9')
    checksum = 0
    for byte in rom[0x134:0x14d]:
        checksum = (checksum - byte - 1) & 255
    rom[0x14d] = checksum
    rom[0x14e:0x150] = (sum(rom) & 65535).to_bytes(2, 'big')
    fixture = work / 'production-mbc3-v2.gb'
    fixture.write_bytes(rom)
    repo = Path(__file__).resolve().parents[1]
    scripts = work / 'scripts'
    scripts.mkdir()
    shutil.copyfile(repo / 'src/test/scripts/GhidraBoySa01Production.java', scripts / 'GhidraBoySa01Production.java')
    script_digest = hashlib.sha256((scripts / 'GhidraBoySa01Production.java').read_bytes()).hexdigest()
    for folder in ('profile', 'projects', 'cache'):
        (work / folder).mkdir()
    env = dict(os.environ, JAVA_HOME=str(args.jdk.resolve()),
               JAVA_TOOL_OPTIONS=f'-Duser.home={work / "profile"}', XDG_CACHE_HOME=str(work / 'cache'))
    records = []
    identities = dict(
        fixtureSha256=hashlib.sha256(rom).hexdigest(),
        extensionSha256=hashlib.sha256(args.zip.read_bytes()).hexdigest(),
        scriptSha256=script_digest,
        driverSha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        installedMembers=installed_members,
        ghidra=str(ghidra), jdk=str(args.jdk.resolve()), extension=str(extension),
        discovery='prepared instruction fixtures; pre-prepare missing-instruction rejection recorded',
    )
    for key, path in {
        'nativeDecompilerSha256': ghidra / 'Ghidra/Features/Decompiler/os/mac_arm_64/decompile',
        'ghidraApplicationPropertiesSha256': ghidra / 'Ghidra/application.properties',
        'jdkReleaseSha256': args.jdk.resolve() / 'release',
    }.items():
        if path.is_file(): identities[key] = hashlib.sha256(path.read_bytes()).hexdigest()
    phases = [('prepare', 'verify'), (None, 'verify'), ('reapply', 'verify'), (None, 'edit'), (None, 'edited-reopen'), (None, 'removed-reopen')]
    for index, (pre, post) in enumerate(phases):
        command = [str(ghidra / 'support/analyzeHeadless'), str(work / 'projects'), 'sa01-production']
        command += ['-import', str(fixture)] if index == 0 else ['-process', fixture.name]
        command += ['-scriptPath', str(scripts)]
        if pre:
            command += ['-preScript', 'GhidraBoySa01Production.java', pre, str(work)]
        # Every phase uses ordinary automatic analysis; none disables its nonreturn analyzer.
        command += ['-postScript', 'GhidraBoySa01Production.java', post, str(work)]
        logfile = work / f'phase-{index}.log'
        with logfile.open('w') as output:
            completed = subprocess.run(command, env=env, cwd=work, stdout=output, stderr=subprocess.STDOUT)
        log = logfile.read_text()
        markers = ['SA01_PRODUCTION_' + mode.upper().replace('-', '_') + '_PASS' for mode in (pre, post) if mode]
        # Negative stale rejection is exact-site/phase scoped; WARN-level injection and
        # analyzer failures are failures too. Native diagnostics and other warnings
        # retain their categories and also count as unexpected failures.
        expected_errors, unexpected_errors, native_diagnostics, other_warnings = classify_log(log, post)
        passed = completed.returncode == 0 and all(m in log for m in markers) and not unexpected_errors
        records.append(dict(command=command, exitCode=completed.returncode, markers=markers,
                            expectedRejections=expected_errors, unexpectedErrors=unexpected_errors,
                            nativeDiagnostics=native_diagnostics, otherWarnings=other_warnings, passed=passed))
        (work / 'run.json').write_text(json.dumps(dict(**identities, processes=records), indent=2) + '\n')
        if passed and index == 2:
            shutil.copytree(work / 'projects', work / 'gui-projects')
        print(f'phase {index}: {"PASS" if passed else "FAIL"} ({logfile})', flush=True)
        if not passed:
            raise SystemExit(1)


if __name__ == '__main__':
    main()
