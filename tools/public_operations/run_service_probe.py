#!/usr/bin/env python3
"""Compile/run a hidden stock service probe; never captures the desktop."""
import argparse,json,os,subprocess
from pathlib import Path
p=argparse.ArgumentParser()
for name in ('runtime','jdk','out'):p.add_argument('--'+name,type=Path,required=True)
p.add_argument('--compile-only',action='store_true');a=p.parse_args()
a.out.mkdir(parents=True,exist_ok=False);classes=a.out/'classes';classes.mkdir();repo=Path(__file__).resolve().parents[2]
cp=os.pathsep.join(map(str,a.runtime.rglob('*.jar')))
cmd=[str(a.jdk/'bin/javac'),'-cp',cp,'-d',str(classes),str(repo/'tools/public_operations/ServiceBootstrap.java'),str(repo/'tools/public_operations/ServiceProbe.java'),str(a.runtime/'Ghidra/Extensions/GhidraBoy/ghidra_scripts/GhidraBoyTools.java')]
r=subprocess.run(cmd,capture_output=True,text=True);(a.out/'compile.json').write_text(json.dumps(dict(argv=cmd,exit=r.returncode,stdout=r.stdout,stderr=r.stderr),indent=2));r.check_returncode()
vm=[line.split('=',1)[1] for line in (a.runtime/'support/launch.properties').read_text().splitlines() if line.startswith('VMARGS=')]
for key in ('user.home','application.settingsdir','application.cachedir','application.tempdir','java.io.tmpdir'):vm.append('-D'+key+'='+str(a.out/'profile'))
(a.out/'profile').mkdir()
cmd=[str(a.jdk/'bin/java'),*vm,'-cp',str(a.runtime/'Ghidra/Framework/Utility/lib/Utility.jar')+os.pathsep+str(classes),'ghidra.Ghidra','ServiceBootstrap',str(classes),str(a.out/'evidence'),str(repo/'src/test/resources/conditional/carry.gb')]
(a.out/'command.json').write_text(json.dumps(cmd,indent=2))
if not a.compile_only:
 with (a.out/'run.log').open('w') as log:r=subprocess.run(cmd,stdout=log,stderr=subprocess.STDOUT,timeout=240)
 (a.out/'exit.json').write_text(json.dumps(dict(exit=r.returncode,kind='HIDDEN_HEADED_SERVICE_NOT_GUI_ACCEPTANCE')));r.check_returncode()
 if 'PUBLIC_SERVICE_PROBE_PASS' not in (a.out/'run.log').read_text():raise RuntimeError('Missing completed service probe')
