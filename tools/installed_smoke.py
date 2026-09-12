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
for name in ('GhidraBoyPreservation','GhidraBoyInstructionCompatibility','Sm83PreservationInventory','GhidraBoyInstalledCheck','GhidraBoyInstalledLifecycle','GhidraBoyInstalledFunctionOwnership'):
    shutil.copy(repo/'src/test/scripts'/(name+'.java'),scripts)
profile=work/'profile'; profile.mkdir(exist_ok=True)
projects=work/'projects'; projects.mkdir(exist_ok=True)
env=os.environ.copy(); env['JAVA_HOME']=str(args.jdk); env['JAVA_TOOL_OPTIONS']=f'-Duser.home={profile}'; env['XDG_CACHE_HOME']=str(profile)
classpath=os.pathsep.join(str(p) for p in ghidra.glob('Ghidra/**/*.jar'))
def run(cmd, name):
    with (work/(name+'.log')).open('w') as output:
        result=subprocess.run([str(c) for c in cmd],cwd=work,env=env,stdout=output,stderr=subprocess.STDOUT)
    text=(work/(name+'.log')).read_text()
    print(text[-7000:],flush=True)
    if result.returncode or 'ERROR' in text or 'error:' in text:
        raise SystemExit(f'{name} failed, see log')
# Preserve maintained files and compile original upstream language independently of checkout files.
backup=work/'candidate-languages'
shutil.move(str(languages),str(backup)); languages.mkdir()
opcode_fixture=work/'instruction-compatibility.bin'
opcode_fixture.write_bytes(bytes(0x8000))
try:
    for name in ['sm83.sinc','sm83_instructions.sinc','sm83.slaspec','sm83.ldefs','sm83.pspec','sm83.cspec']:
        data=subprocess.check_output(['git','show',f'42032f9:data/languages/{name}'],cwd=repo)
        (languages/name).write_bytes(data)
    run([args.jdk/'bin/java','-cp',classpath,'ghidra.pcodeCPort.slgh_compile.SleighCompile',languages/'sm83.slaspec'],'compile-old')
    run([ghidra/'support/analyzeHeadless',projects,'fixture','-scriptPath',scripts,'-preScript','GhidraBoyPreservation.java','create','-noanalysis'],'create-old')
    run([ghidra/'support/analyzeHeadless',projects,'fixture','-import',opcode_fixture,
         '-loader','BinaryLoader','-processor','SM83:LE:16:default','-cspec','default',
         '-scriptPath',scripts,'-postScript','GhidraBoyInstructionCompatibility.java','seed',
         work/'instructions-old.txt','-noanalysis'],'create-old-instructions')
    for name in ('preserved', opcode_fixture.name):
        run([ghidra/'support/analyzeHeadless',projects,'fixture','-scriptPath',scripts,
             '-preScript','Sm83PreservationInventory.java','old-saved',work/(name+'-old.json'),name,'-noanalysis'], 'inventory-old-'+name)
finally:
    shutil.move(str(languages),str(work/'historical-42032f9-languages'))
    shutil.move(str(backup),str(languages))
# The historical project is retained; only its closed copy enters the candidate.
from sm83_compatibility import tree, write, compare, historical_transitions
original_projects=projects; original_hashes=tree(projects)
write(work/'original-project-hashes.json',original_hashes)
projects=work/'upgraded-projects';shutil.copytree(original_projects,projects)
for name in ('preserved', opcode_fixture.name):
    run([ghidra/'support/analyzeHeadless',projects,'fixture','-scriptPath',scripts,
         '-preScript','Sm83PreservationInventory.java','upgrade',work/(name+'-post.json'),name,'-noanalysis'], 'core-upgrade-'+name)
    text=(work/('core-upgrade-'+name+'.log')).read_text()
    if 'Setting language' not in text or 'sm83-1-2.trans' not in text: raise SystemExit('Missing installed translator')
    run([ghidra/'support/analyzeHeadless',projects,'fixture','-scriptPath',scripts,
         '-preScript','Sm83PreservationInventory.java','immutable',work/(name+'-immutable.json'),name,'-noanalysis'], 'first-immutable-'+name)
    if 'Setting language' in (work/('first-immutable-'+name+'.log')).read_text(): raise SystemExit('Repeated translation on immutable use')
    import json
    post=json.loads((work/(name+'-post.json')).read_text()); reopened=json.loads((work/(name+'-immutable.json')).read_text())
    if post['pid']==reopened['pid'] or reopened['changeable']: raise SystemExit('Not a separate immutable process')
    old=json.loads((work/(name+'-old.json')).read_text())
    write(work/(name+'-preservation-diff.json'),compare(old,post,reopened,corpus=name==opcode_fixture.name,transitions=historical_transitions()))
assert tree(original_projects)==original_hashes

run([ghidra/'support/analyzeHeadless',projects,'fixture','-process','preserved','-scriptPath',scripts,'-postScript','GhidraBoyPreservation.java','verify','-noanalysis'],'reopen-current')
run([ghidra/'support/analyzeHeadless',projects,'fixture','-process',opcode_fixture.name,
     '-scriptPath',scripts,'-postScript','GhidraBoyInstructionCompatibility.java','check',
     work/'instructions-current.txt','-noanalysis'],'reopen-current-instructions')
if 'INSTRUCTION_COMPATIBILITY_PASS instructions=501' not in (work/'reopen-current-instructions.log').read_text():
    raise SystemExit('Missing persisted instruction compatibility verification marker')
run([ghidra/'support/analyzeHeadless',projects,'fixture','-process','preserved','-postScript','GhidraBoyTools.java','inspect','-noanalysis'],'installed-tools')
# Synthetic code with the standard 48-byte detection signature; no commercial ROM.
rom=bytearray(0x10000)
rom[0x104:0x134]=bytes.fromhex('ce ed 66 66 cc 0d 00 0b 03 73 00 83 00 0c 00 0d 00 08 11 1f 88 89 00 0e dc cc 6e e6 dd dd d9 99 bb bb 67 63 6e 0e ec cc dd dc 99 9f bb b9 33 3e')
rom[0x143]=0x80; rom[0x147]=0x13; rom[0x148]=1; rom[0x149]=3
rom[0x14e:0x150]=bytes.fromhex('12 34')
rom[0x150:0x153]=bytes.fromhex('3e 42 c9')
(work/'synthetic.gb').write_bytes(rom)
run([ghidra/'support/analyzeHeadless',projects,'fixture','-import',work/'synthetic.gb','-noanalysis'],'discover-loader')
run([ghidra/'support/analyzeHeadless',projects,'fixture','-process','synthetic.gb','-scriptPath',scripts,'-postScript','GhidraBoyInstalledCheck.java','-noanalysis'],'persisted-loader')
run([ghidra/'support/analyzeHeadless',projects,'fixture','-process','synthetic.gb','-scriptPath',scripts,'-postScript','GhidraBoyInstalledLifecycle.java','prepare','-noanalysis'],'lifecycle-prepare')
run([ghidra/'support/analyzeHeadless',projects,'fixture','-process','synthetic.gb','-scriptPath',scripts,'-postScript','GhidraBoyInstalledLifecycle.java','verify','-noanalysis'],'lifecycle-reopen')
run([ghidra/'support/analyzeHeadless',projects,'fixture','-process','synthetic.gb','-scriptPath',scripts,'-postScript','GhidraBoyInstalledFunctionOwnership.java','prepare','-noanalysis'],'function-ownership-prepare')
run([ghidra/'support/analyzeHeadless',projects,'fixture','-process','synthetic.gb','-scriptPath',scripts,'-postScript','GhidraBoyInstalledFunctionOwnership.java','verify','-noanalysis'],'function-ownership-reopen')
if 'INSTALLED_FUNCTION_OWNERSHIP_REOPEN_REMOVE_RERUN_PASS' not in (work/'function-ownership-reopen.log').read_text():
    raise SystemExit('Missing installed function ownership verification marker')
# Compile and execute every public script from the installed ZIP, separately from GUI acceptance.
(work/'abi-request.json').write_text('{"profile":"sdcc451-call1","returnType":"u16","parameters":[{"name":"value","type":"u8"}]}')
run([ghidra/'support/analyzeHeadless',projects,'fixture','-process','synthetic.gb','-postScript','GhidraBoyAbi.java',work/'abi-request.json','persistent_bank::4000','-noanalysis'],'installed-abi-preview')
(work/'manual-salvage.gb').write_bytes(rom+b'preserved tail')
run([ghidra/'support/analyzeHeadless',projects,'fixture','-preScript','GhidraBoyImport.java',work/'manual-salvage.gb','SALVAGE','AUTO','CGB','-noanalysis'],'installed-manual-salvage')
assert tree(original_projects)==original_hashes
print('INSTALLED_ZIP_PRESERVATION_PASS')
