#!/usr/bin/env python3
"""Real package install/recovery/remove/rollback tests in an isolated home."""
import argparse,hashlib,importlib.util,json,os,shutil,subprocess,sys,tempfile
from pathlib import Path
p=argparse.ArgumentParser()
for name in ('manifest','study','ghidra','java-home','work'):p.add_argument('--'+name,type=Path,required=True)
a=p.parse_args();a.work.mkdir(parents=True,exist_ok=False)
root=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('suite_installer',root/'scripts/install.py');installer=importlib.util.module_from_spec(spec);spec.loader.exec_module(installer)
home=a.work/'home with spaces';home.mkdir()
settings=home/('Library/ghidra' if sys.platform=='darwin' else '.config/ghidra')/'ghidra_12.1.3_PUBLIC'
(settings/'Extensions/GhiGBC').mkdir(parents=True);(settings/'Extensions/GhiGBC/original-user-file.txt').write_text('preserve original user work\n')
(settings/'Extensions/Unrelated').mkdir();(settings/'Extensions/Unrelated/notes.txt').write_text('unrelated\n')
base=[sys.executable,str(root/'scripts/install.py'),'--manifest',str(a.manifest),'--ghidra',str(a.ghidra),'--java-home',str(a.java_home),'--user-home',str(home)]
results=[]
def run(name,command,expected=0,env=None):
 result=subprocess.run(command,text=True,capture_output=True,env=dict(os.environ,**(env or {})))
 log=a.work/(name+'.log');log.write_text(result.stdout+result.stderr)
 assert result.returncode==expected,(name,result.returncode,result.stdout,result.stderr)
 results.append({'name':name,'command':command,'exit_code':result.returncode,'status':'PASS','log':str(log)})
 return json.loads(result.stdout) if expected==0 else None
first=run('install',base);active=installer.hashes(settings/'Extensions')
# Fail after moving one prior extension, then recover using the durable journal.
run('crash-after-backup',base,86,{'GBC_INSTALL_FAIL_AFTER':'backup:GhidraBoy'})
interrupted=sorted((settings/'GhiGBC-rollback').glob('*/manifest.json'))[-1]
run('recover', [sys.executable,str(root/'scripts/install.py'),'--recover',str(interrupted)])
assert installer.hashes(settings/'Extensions')==active
# Fail after committing a different extension, still restore the complete old tuple.
run('crash-after-install',base,86,{'GBC_INSTALL_FAIL_AFTER':'install:GhiGBC'})
interrupted=sorted((settings/'GhiGBC-rollback').glob('*/manifest.json'))[-1]
run('recover-second',[sys.executable,str(root/'scripts/install.py'),'--recover',str(interrupted)])
assert installer.hashes(settings/'Extensions')==active
study=run('install-study',base+['--study',str(a.study)])
assert (Path(study['runtime'])/'python/ghibw3/profile.py').exists()
assert (settings/'Extensions/GhiBW3Live').is_dir()
removed=run('remove-study',base+['--remove-study'])
assert not (settings/'Extensions/GhiBW3Live').exists() and not (Path(removed['runtime'])/'profiles.json').exists()
assert (settings/'Extensions/Unrelated/notes.txt').read_text()=='unrelated\n'
# Rollback from the installed runtime restores the optional composition.
run('self-rollback',[sys.executable,str(Path(removed['runtime'])/'scripts/install.py'),'--rollback',removed['rollback_manifest']])
assert (settings/'Extensions/GhiBW3Live').exists()
# A user edit must reject rollback before any other managed extension is changed.
marker=settings/'Extensions/GhiGBC/user-change.txt';marker.write_text('must not delete\n')
before=installer.hashes(settings/'Extensions')
run('user-edit-refused',[sys.executable,str(root/'scripts/install.py'),'--rollback',study['rollback_manifest']],1)
assert installer.hashes(settings/'Extensions')==before
# Remove only this test-authored marker so the valid rollback can be exercised.
marker.unlink()
run('rollback-study',[sys.executable,str(root/'scripts/install.py'),'--rollback',study['rollback_manifest']])
assert installer.hashes(settings/'Extensions')==active
run('rollback-original',[sys.executable,str(root/'scripts/install.py'),'--rollback',first['rollback_manifest']])
assert (settings/'Extensions/GhiGBC/original-user-file.txt').read_text()=='preserve original user work\n'
assert not (settings/'Extensions/GhidraBoy').exists()
# Corrupt a copy of a package payload; no managed directory may be created.
copied=a.work/'corrupt-package';shutil.copytree(a.manifest.parent,copied)
relative=json.loads(a.manifest.read_text())['runtime_files'][0];(copied/relative).write_bytes(b'corrupt')
run('hash-refused',[sys.executable,str(root/'scripts/install.py'),'--manifest',str(copied/a.manifest.name),'--ghidra',str(a.ghidra),'--java-home',str(a.java_home),'--user-home',str(a.work/'rejected-home')],1)
assert not (a.work/'rejected-home').exists()
(a.work/'results.json').write_text(json.dumps(results,indent=2)+'\n')
print(json.dumps({'status':'PASS','checks':len(results),'results':str(a.work/'results.json')}))
