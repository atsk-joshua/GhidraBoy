#!/usr/bin/env python3
"""Isolated installed-ZIP and old-language reopening test. Never edits user's install/project."""
import argparse, os, pathlib, shutil, subprocess, tempfile, zipfile
parser=argparse.ArgumentParser()
parser.add_argument('--ghidra', type=pathlib.Path, required=True, help='Disposable extracted official distribution')
parser.add_argument('--zip', type=pathlib.Path, required=True)
parser.add_argument('--jdk', type=pathlib.Path, required=True)
parser.add_argument('--work', type=pathlib.Path, required=True)
args=parser.parse_args()
repo=pathlib.Path(__file__).resolve().parents[1]
ghidra=args.ghidra.resolve(); work=args.work.resolve(); work.mkdir(parents=True,exist_ok=True)
# Reject common real installation locations, and require dedicated disposable test prefix.
if not any(ghidra.is_relative_to(root) for root in [pathlib.Path('/tmp').resolve(), pathlib.Path(tempfile.gettempdir()).resolve()]) or 'ghidraboy' not in str(ghidra).lower():
    raise SystemExit('Use a disposable Ghidra distribution under the temporary ghidraboy test directory')
extensions=ghidra/'Ghidra/Extensions'; extensions.mkdir(exist_ok=True)
if work.is_relative_to(ghidra): raise SystemExit('Test work/profile directory must be outside the installation')
previous=extensions/'GhidraBoy'
if previous.exists(): shutil.move(str(previous),str(work/'previous-extension'))
with zipfile.ZipFile(args.zip) as z: z.extractall(extensions)
ext=extensions/'GhidraBoy'; languages=ext/'data/languages'
scripts=work/'scripts'; scripts.mkdir(exist_ok=True)
for source in (repo/'src/test/scripts').glob('*.java'): shutil.copy(source, scripts)
profile=work/'profile'; profile.mkdir(exist_ok=True)
projects=work/'projects'; projects.mkdir(exist_ok=True)
env=os.environ.copy(); env['JAVA_HOME']=str(args.jdk); env['JAVA_TOOL_OPTIONS']=f'-Duser.home={profile}'
classpath=os.pathsep.join(str(p) for p in ghidra.glob('Ghidra/**/*.jar'))
def run(cmd, name):
    with (work/(name+'.log')).open('w') as output:
        result=subprocess.run([str(c) for c in cmd],cwd=work,env=env,stdout=output,stderr=subprocess.STDOUT)
    text=(work/(name+'.log')).read_text()
    print(text[-7000:],flush=True)
    if result.returncode or ('ERROR' in text and name not in ['compile-old']):
        raise SystemExit(f'{name} failed, see log')
# Preserve maintained files and compile original upstream language independently of checkout files.
backup={p.name:p.read_bytes() for p in languages.iterdir() if p.is_file()}
try:
    for name in ['sm83.sinc','sm83_instructions.sinc','sm83.slaspec','sm83.ldefs','sm83.pspec','sm83.cspec']:
        data=subprocess.check_output(['git','show',f'42032f9:data/languages/{name}'],cwd=repo)
        (languages/name).write_bytes(data)
    run([args.jdk/'bin/java','-cp',classpath,'ghidra.pcodeCPort.slgh_compile.SleighCompile',languages/'sm83.slaspec'],'compile-old')
    run([ghidra/'support/analyzeHeadless',projects,'fixture','-scriptPath',scripts,'-preScript','GhidraBoyPreservation.java','create','-noanalysis'],'create-old')
finally:
    for name,data in backup.items(): (languages/name).write_bytes(data)
run([ghidra/'support/analyzeHeadless',projects,'fixture','-process','preserved','-scriptPath',scripts,'-postScript','GhidraBoyPreservation.java','verify','-noanalysis'],'reopen-current')
run([ghidra/'support/analyzeHeadless',projects,'fixture','-process','preserved','-postScript','GhidraBoyTools.java','inspect','-noanalysis'],'installed-tools')
# Synthetic code with the standard 48-byte detection signature; no commercial ROM.
rom=bytearray(0x10000)
rom[0x104:0x134]=bytes.fromhex('ce ed 66 66 cc 0d 00 0b 03 73 00 83 00 0c 00 0d 00 08 11 1f 88 89 00 0e dc cc 6e e6 dd dd d9 99 bb bb 67 63 6e 0e ec cc dd dc 99 9f bb b9 33 3e')
rom[0x143]=0x80; rom[0x147]=0x1b; rom[0x148]=1; rom[0x149]=3
rom[0x14e:0x150]=bytes.fromhex('12 34')
rom[0x150:0x153]=bytes.fromhex('3e 42 c9')
(work/'synthetic.gb').write_bytes(rom)
run([ghidra/'support/analyzeHeadless',projects,'fixture','-import',work/'synthetic.gb','-noanalysis'],'discover-loader')
run([ghidra/'support/analyzeHeadless',projects,'fixture','-process','synthetic.gb','-scriptPath',scripts,'-postScript','GhidraBoyInstalledCheck.java','-noanalysis'],'persisted-loader')
run([ghidra/'support/analyzeHeadless',projects,'fixture','-process','synthetic.gb','-scriptPath',scripts,'-postScript','GhidraBoyInstalledLifecycle.java','prepare','-noanalysis'],'lifecycle-prepare')
run([ghidra/'support/analyzeHeadless',projects,'fixture','-process','synthetic.gb','-scriptPath',scripts,'-postScript','GhidraBoyInstalledLifecycle.java','verify','-noanalysis'],'lifecycle-reopen')
print('INSTALLED_ZIP_PRESERVATION_PASS')
