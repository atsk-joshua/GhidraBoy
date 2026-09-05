#!/usr/bin/env python3
"""Run auditable local/CI gates. Missing or blocked gates remain explicit in receipts."""
import argparse,hashlib,json,os,pathlib,shutil,subprocess,sys,tempfile,time
p=argparse.ArgumentParser()
for name in ['ghidra','jdk','installed-ghidra','legacy-ghidra','vectors','work']:p.add_argument('--'+name,type=pathlib.Path,required=name in ['ghidra','jdk'])
p.add_argument('--native',action='store_true',help='Run native decompiler/full build and installed process gates')
p.add_argument('--gui-evidence',type=pathlib.Path)
p.add_argument('--dependency-file',action='append',default=[],help='Verify NAME=PATH against tools/dependencies.json')
a=p.parse_args();repo=pathlib.Path(__file__).resolve().parents[1]
work=(a.work or pathlib.Path(tempfile.mkdtemp(prefix='ghidraboy-validation-'))).resolve();work.mkdir(parents=True,exist_ok=True)
if (work/'commands.json').exists():raise SystemExit('Use a fresh work directory so receipts cannot mix runs')
if work.is_relative_to(repo):raise SystemExit('Work receipts must survive Gradle clean; use a separate temporary directory')
env=os.environ.copy();env['JAVA_HOME']=str(a.jdk);env['GHIDRA_INSTALL_DIR']=str(a.ghidra)
receipts=[]
def run(name,gate,command,extra=None,marker=None):
 log=work/(name+'.log');started=time.time();runenv=env.copy();runenv.update(extra or {})
 with log.open('w') as out:result=subprocess.run([str(c) for c in command],cwd=repo,env=runenv,stdout=out,stderr=subprocess.STDOUT)
 text=log.read_text(errors='replace');ok=result.returncode==0 and (marker is None or marker in text)
 receipts.append({'name':name,'gate':gate,'command':[str(c) for c in command],'environmentOverrides':extra or {},'exitCode':result.returncode,'status':'PASS' if ok else 'FAIL','log':str(log),'durationSeconds':round(time.time()-started,3),'requiredMarker':marker})
 print(name,receipts[-1]['status'],flush=True)
 (work/'commands.json').write_text(json.dumps(receipts,indent=2)+'\n')
 return ok
def blocked(gate,reason):receipts.append({'gate':gate,'status':'BLOCKED','reason':reason})
locks=json.loads((repo/'tools/dependencies.json').read_text())
for supplied in a.dependency_file:
 name,filename=supplied.split('=',1);path=pathlib.Path(filename)
 actual=hashlib.sha256(path.read_bytes()).hexdigest()
 receipts.append({'gate':'dependency-digest','dependency':name,'file':str(path),'sha256':actual,'expectedSha256':locks[name]['sha256'],'status':'PASS' if actual==locks[name]['sha256'] else 'FAIL'})
 if actual!=locks[name]['sha256']:raise SystemExit('Dependency digest mismatch: '+name)
for binary in sorted((a.ghidra/'Ghidra/Features/Decompiler/os').glob('*/decompile')):
 receipts.append({'gate':'native-binary-inventory','status':'RECORDED','file':str(binary),'sha256':hashlib.sha256(binary.read_bytes()).hexdigest()})
run('toolchain','toolchain',[a.jdk/'bin/java','-version'])
run('wrapper','toolchain',['./gradlew','--version','--console=plain'])
if a.vectors:
 if run('external-vectors','external-vectors',['./gradlew','test','--tests','*ExternalVectorTest','-Dghidraboy.vector.dir='+str(a.vectors),'--console=plain']):
  shutil.copytree(repo/'build/test-results/test',work/'external-vector-results',dirs_exist_ok=True)
else:blocked('external-vectors','No comprehensive vector directory supplied; ordinary samples are counted separately')
if a.native:
 built=run('clean-build','full-build',['./gradlew','clean','build','--console=plain'])
else:
 blocked('full-build','Native decompiler/full suite not enabled for this run')
 patterns=['*AuditRegressionTest','*CartridgeTest','*MapperTopologyTest','*Symbol*Test','*SalvageTest','*AnalysisHardeningTest','*AnalysisBoundaryTest','*BankAnalysisTest','*emu.*','*CompilerSpecTest']
 command=['./gradlew','clean','test','assemble','ktlintCheck','--console=plain']
 for pattern in patterns:command+=['--tests',pattern]
 built=run('pure-java-gates','pure-java-gates',command)
archives=sorted((repo/'build/distributions').glob('*_GhidraBoy.zip'))
if len(archives)!=1:raise SystemExit('Expected one current artifact after build')
artifact=archives[0]
firstHash=hashlib.sha256(artifact.read_bytes()).hexdigest()
# A separate clean package build compares identical inputs without claiming a second native test run.
run('rebuild-package','package-rebuild',['./gradlew','clean','assemble','--console=plain'])
secondHash=hashlib.sha256(artifact.read_bytes()).hexdigest()
receipts.append({'gate':'reproducibility','status':'PASS' if firstHash==secondHash else 'FAIL','firstSha256':firstHash,'secondSha256':secondHash,'conditions':'same checkout, platform, JDK, Ghidra and SOURCE_DATE_EPOCH'})
# Test reports must not be inferred from a package build. Rerun the chosen tests after clean.
if a.native:run('final-tests','full-build',['./gradlew','test','ktlintCheck','--console=plain'])
else:run('final-pure-tests','pure-java-gates',['./gradlew','test','--console=plain',*[item for pattern in patterns for item in ['--tests',pattern]]])
run('schema','schema',[sys.executable,'tools/validate_schema.py','build/test-fixtures/*.json'])
run('doctor','doctor',[sys.executable,'tools/doctor.py','--ghidra',a.ghidra,'--jdk',a.jdk,'--zip',artifact],marker='DOCTOR_PASS')
props=repo/'build/generated/extension.properties';original=props.read_bytes()
run('epoch-change','metadata-incremental',['./gradlew','generateExtensionProps','--console=plain'],{'SOURCE_DATE_EPOCH':'1788566401'})
changed=props.read_bytes()!=original
run('epoch-restore','metadata-incremental',['./gradlew','generateExtensionProps','--console=plain'],{'SOURCE_DATE_EPOCH':env.get('SOURCE_DATE_EPOCH','1788566400')})
receipts.append({'gate':'metadata-incremental','status':'PASS' if changed and props.read_bytes()==original else 'FAIL','changedThenRestored':changed and props.read_bytes()==original})
if a.native and a.installed_ghidra:
 run('installed','installed',[sys.executable,'tools/installed_smoke.py','--ghidra',a.installed_ghidra,'--zip',artifact,'--jdk',a.jdk,'--work',work/'installed'],marker='INSTALLED_ZIP_PRESERVATION_PASS')
else:blocked('installed','Native process gates or disposable installed distribution not supplied')
if a.native and a.installed_ghidra and a.legacy_ghidra:
 run('migration','migration',[sys.executable,'tools/migration_smoke.py','--legacy-ghidra',a.legacy_ghidra,'--ghidra',a.installed_ghidra,'--zip',artifact,'--jdk',a.jdk,'--work',work/'migration'],marker='"originalProjectUnchanged": true')
else:blocked('migration','Actual historical/disposable process environments not enabled for this run')
if a.gui_evidence:receipts.append(json.loads(a.gui_evidence.read_text()))
else:blocked('gui','Interactive dialogs have not been verified by this runner; see manual GUI checklist')
(work/'commands.json').write_text(json.dumps(receipts,indent=2)+'\n')
reports=repo/'build/reports/evidence';shutil.copytree(work,reports,dirs_exist_ok=True,ignore=shutil.ignore_patterns('previous-extension','*-profile','profile','original-project','upgraded-copy','projects'))
subprocess.run([sys.executable,'tools/release_evidence.py','--receipts',work/'commands.json','--zip',artifact,'--output',reports/'release-evidence.json','--external-results',reports/'external-vector-results'],cwd=repo,check=True)
if any(r['status']=='FAIL' for r in receipts):raise SystemExit('One or more validation commands failed; reports retained')
