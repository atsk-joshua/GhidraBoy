#!/usr/bin/env python3
"""Actual 11.3.1 -> 12.1.3 database migration using a copied, self-authored project."""
import argparse,hashlib,json,os,pathlib,shutil,subprocess,tempfile,zipfile
p=argparse.ArgumentParser()
for name in ['legacy-ghidra','ghidra','zip','jdk','work']: p.add_argument('--'+name,type=pathlib.Path,required=True)
a=p.parse_args(); repo=pathlib.Path(__file__).resolve().parents[1]
work=a.work.resolve(); work.mkdir(parents=True,exist_ok=False)
for install,version in [(a.legacy_ghidra,'11.3.1'),(a.ghidra,'12.1.3')]:
 install=install.resolve()
 if not any(install.is_relative_to(root) for root in [pathlib.Path('/tmp').resolve(),pathlib.Path(tempfile.gettempdir()).resolve()]) or 'ghidraboy' not in str(install): raise SystemExit('Disposable ghidraboy installations required')
 if f'application.version={version}\n' not in (install/'Ghidra/application.properties').read_text(): raise SystemExit('Wrong version')
ext=a.ghidra/'Ghidra/Extensions/GhidraBoy'
if ext.exists(): shutil.move(str(ext),str(work/'previous-extension'))
with zipfile.ZipFile(a.zip) as z: z.extractall(a.ghidra/'Ghidra/Extensions')
scripts=work/'scripts';scripts.mkdir()
old_scripts=work/'old-scripts';old_scripts.mkdir()
shutil.copy2(repo/'src/test/migration/Create1131Fixture.java',old_scripts)
shutil.copy2(repo/'src/test/migration/Verify1131Upgrade.java',scripts)
for directory in (scripts,old_scripts):shutil.copy2(repo/'src/test/scripts/Sm83PreservationInventory.java',directory)
commands=[]
def run(install,project,phase,arguments,marker):
 profile=work/(phase+'-profile');profile.mkdir()
 env=os.environ.copy();env['JAVA_HOME']=str(a.jdk);env['JAVA_TOOL_OPTIONS']=f'-Duser.home={profile}';env['XDG_CACHE_HOME']=str(profile)
 cmd=[str(x) for x in [install/'support/analyzeHeadless',project,'fixture','-scriptPath',old_scripts if install==a.legacy_ghidra else scripts,*arguments,'-noanalysis']]
 with (work/(phase+'.log')).open('w') as out:r=subprocess.run(cmd,cwd=work,env=env,stdout=out,stderr=subprocess.STDOUT)
 text=(work/(phase+'.log')).read_text()
 commands.append({'phase':phase,'command':cmd,'exitCode':r.returncode,'marker':marker,'markerObserved':marker in text})
 (work/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
 if r.returncode or marker not in text or 'ERROR' in text or 'error:' in text:
  print(text[-7000:]);raise SystemExit(phase+' failed')
def treehash(root):
 d=hashlib.sha256()
 for f in sorted(root.rglob('*')):
  if f.is_file():d.update(str(f.relative_to(root)).encode());d.update(f.read_bytes())
 return d.hexdigest()
old=work/'original-project';old.mkdir()
run(a.legacy_ghidra,old,'create1131',['-preScript','Create1131Fixture.java'],'ACTUAL_1131_CREATED_WITH_OLD_ADC')
run(a.legacy_ghidra,old,'inventory1131',['-preScript','Sm83PreservationInventory.java','old-saved',work/'old.json','preserved1131'],'SM83_INVENTORY_PASS old-saved')
originalHash=treehash(old)
copy=work/'upgraded-copy';shutil.copytree(old,copy)
run(a.ghidra,copy,'upgrade1213',['-preScript','Sm83PreservationInventory.java','upgrade',work/'post.json','preserved1131'],'SM83_INVENTORY_PASS upgrade')
if 'sm83-1-2.trans' not in (work/'upgrade1213.log').read_text() or 'Setting language' not in (work/'upgrade1213.log').read_text(): raise SystemExit('Actual installed translator required')
run(a.ghidra,copy,'immutable1213',['-preScript','Sm83PreservationInventory.java','immutable',work/'immutable.json','preserved1131'],'SM83_INVENTORY_PASS immutable')
if 'Setting language' in (work/'immutable1213.log').read_text(): raise SystemExit('Repeated upgrade during immutable reopen')
post=json.loads((work/'post.json').read_text()); immutable=json.loads((work/'immutable.json').read_text())
assert not immutable['changeable'] and post['pid']!=immutable['pid']
# Enhancement and analysis have their own disposable branch and observations.
enhanced=work/'enhanced-copy';shutil.copytree(copy,enhanced)
run(a.ghidra,enhanced,'enhance1213',['-process','preserved1131','-postScript','Verify1131Upgrade.java','-postScript','Sm83PreservationInventory.java','enhanced',work/'enhanced.json'],'ACTUAL_1131_UPGRADE_REANALYSIS_AND_NEW_ADC_PASS')
run(a.ghidra,enhanced,'enhancedImmutable1213',['-preScript','Sm83PreservationInventory.java','immutable',work/'enhanced-immutable.json','preserved1131'],'SM83_INVENTORY_PASS immutable')
from sm83_compatibility import differences, write, compare, historical_transitions
write(work/'preservation-diff.json',compare(json.loads((work/'old.json').read_text()),post,immutable,transitions=historical_transitions()))
write(work/'complete-diffs.json',{'old_core':differences(json.loads((work/'old.json').read_text())['state'],post['state']),'core_immutable':differences(post['state'],immutable['state']),'core_enhanced':differences(post['state'],json.loads((work/'enhanced.json').read_text())['state']),'enhanced_immutable':differences(json.loads((work/'enhanced.json').read_text())['state'],json.loads((work/'enhanced-immutable.json').read_text())['state'])})
result={'gate':'actual-database-migration','from':'11.3.1','to':'12.1.3','originalProjectUnchanged':treehash(old)==originalHash,'originalTreeSha256':originalHash,'commands':commands}
(work/'migration-evidence.json').write_text(json.dumps(result,indent=2)+'\n')
assert result['originalProjectUnchanged']
print(json.dumps(result,indent=2))
