#!/usr/bin/env python3
"""Compile/run a hidden stock service probe; never captures the desktop."""
import argparse,hashlib,json,os,shutil,subprocess,time,zipfile
from pathlib import Path
p=argparse.ArgumentParser()
for name in ('runtime','jdk','out'):p.add_argument('--'+name,type=Path,required=True)
p.add_argument('--candidate',type=Path);p.add_argument('--compile-only',action='store_true');p.add_argument('--attended',action='store_true',help='Confirmed attended graphical session');a=p.parse_args()
if not a.compile_only and not a.attended:p.error('Execution requires confirmed attended permission; use --compile-only for preparation')
a.out.mkdir(parents=True,exist_ok=False);classes=a.out/'classes';classes.mkdir();boot=a.out/'bootstrap';boot.mkdir();repo=Path(__file__).resolve().parents[2]
cp=os.pathsep.join(map(str,a.runtime.rglob('*.jar')))
cmd=[str(a.jdk/'bin/javac'),'-proc:none','-cp',cp,'-d',str(classes),str(repo/'tools/public_operations/ServiceBootstrap.java'),str(repo/'tools/public_operations/ServiceProbe.java'),str(a.runtime/'Ghidra/Extensions/GhidraBoy/ghidra_scripts/GhidraBoyTools.java'),str(repo/'src/test/scripts/Sm83PreservationInventory.java')]
sha=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()
input_files=[repo/'tools/public_operations/run_service_probe.py',*[Path(x) for x in cmd if x.endswith('.java')],repo/'src/test/resources/conditional/carry.gb']
inputs={str(f):sha(f) for f in input_files};snapshots={}
for f in input_files:
 relative=f.relative_to(repo) if f.is_relative_to(repo) else Path('installed')/f.name
 dest=a.out/'sources'/relative;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(f,dest);snapshots[str(f)]=str(dest.relative_to(a.out))
 if sha(dest)!=inputs[str(f)]:raise RuntimeError('Source changed during preparation: '+str(f))
(a.out/'driver-inputs.json').write_text(json.dumps(inputs,indent=2));(a.out/'source-snapshots.json').write_text(json.dumps(snapshots,indent=2))
runtime_files=[*a.runtime.rglob('*.jar'),*filter(Path.is_file,(a.runtime/'Ghidra/Extensions/GhidraBoy').rglob('*')),*a.runtime.glob('Ghidra/Features/Decompiler/os/*/decompile'),a.runtime/'support/launch.properties',a.jdk/'bin/java',a.jdk/'bin/javac']
if a.candidate:
 with zipfile.ZipFile(a.candidate) as archive:
  for member in archive.infolist():
   if not member.is_dir() and archive.read(member)!=(a.runtime/'Ghidra/Extensions'/member.filename).read_bytes():raise RuntimeError('Installed candidate mismatch: '+member.filename)
 runtime_files.append(a.candidate);(a.out/'candidate.json').write_text(json.dumps({'archive':str(a.candidate),'sha256':sha(a.candidate)},indent=2))
runtime_inputs={str(f):sha(f) for f in runtime_files};(a.out/'runtime-inputs.json').write_text(json.dumps(runtime_inputs,indent=2))
r=subprocess.run(cmd,capture_output=True,text=True);(a.out/'compile.json').write_text(json.dumps(dict(argv=cmd,exit=r.returncode,stdout=r.stdout,stderr=r.stderr),indent=2));r.check_returncode()
if any(sha(Path(f))!=expected for f,expected in inputs.items()):raise RuntimeError('Source changed while compiling probe')
(classes/'ServiceBootstrap.class').rename(boot/'ServiceBootstrap.class')
vm=[line.split('=',1)[1] for line in (a.runtime/'support/launch.properties').read_text().splitlines() if line.startswith('VMARGS=')]
for key in ('user.home','application.settingsdir','application.cachedir','application.tempdir','java.io.tmpdir'):vm.append('-D'+key+'='+str(a.out/'profile'))
(a.out/'profile').mkdir()
cmd=[str(a.jdk/'bin/java'),*vm,'-cp',str(a.runtime/'Ghidra/Framework/Utility/lib/Utility.jar')+os.pathsep+str(boot),'ghidra.Ghidra','ServiceBootstrap',str(classes),str(a.out/'evidence'),str(repo/'src/test/resources/conditional/carry.gb')]
(a.out/'command.json').write_text(json.dumps(cmd,indent=2))
(a.out/'prepared-command-sha256.txt').write_text(sha(a.out/'command.json')+'\n')
sha=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()
(a.out/'compiled-classes.json').write_text(json.dumps({str(f.relative_to(a.out)):sha(f) for d in (classes,boot) for f in d.rglob('*.class')},indent=2))
if not a.compile_only:
 if any(sha(Path(f))!=expected for f,expected in runtime_inputs.items()):raise RuntimeError('Runtime changed after preparation')
 receipt={'start_ns':time.time_ns(),'attended':True,'kind':'HIDDEN_HEADED_SERVICE_NOT_GUI_ACCEPTANCE','argv':cmd,'runtime_manifest_checked':True,'command_manifest_checked':True}
 with (a.out/'run.log').open('x') as log:
  process=subprocess.Popen(cmd,stdout=log,stderr=subprocess.STDOUT);receipt['pid']=process.pid
  (a.out/'process-start.json').write_text(json.dumps(receipt,indent=2))
  try:receipt['exit']=process.wait(timeout=240)
  except subprocess.TimeoutExpired:
   receipt['timeout']=True;process.terminate()
   try:receipt['exit']=process.wait(timeout=20)
   except subprocess.TimeoutExpired:process.kill();receipt['exit']=process.wait();receipt['forced_failure_cleanup']=True
 receipt['end_ns']=time.time_ns();(a.out/'exit.json').write_text(json.dumps(receipt,indent=2))
 if receipt['exit'] or receipt.get('timeout'):raise SystemExit(1)
 if 'PUBLIC_SERVICE_PROBE_PASS' not in (a.out/'run.log').read_text():raise RuntimeError('Missing completed service probe')
