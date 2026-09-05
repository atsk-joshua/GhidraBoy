#!/usr/bin/env python3
"""Generate release evidence from actual JUnit XML, command receipts, vector metrics and ZIP bytes."""
import argparse,hashlib,json,pathlib,platform,re,subprocess,xml.etree.ElementTree as ET
p=argparse.ArgumentParser();p.add_argument('--receipts',type=pathlib.Path,required=True);p.add_argument('--zip',type=pathlib.Path,required=True);p.add_argument('--output',type=pathlib.Path,required=True);p.add_argument('--external-results',type=pathlib.Path);p.add_argument('--test-results',type=pathlib.Path,default=pathlib.Path('build/test-results/test'));a=p.parse_args()
repo=pathlib.Path(__file__).resolve().parents[1]
receipts=json.loads(a.receipts.read_text()); suites=[];cases=[];vectorRuns=[]
for path in sorted(a.test_results.glob('TEST-*.xml')):
 root=ET.parse(path).getroot(); stats={k:int(root.get(k,'0')) for k in ['tests','failures','errors','skipped']}
 suites.append({'name':root.get('name'),'report':str(path),'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),**stats})
 for case in root.findall('testcase'):cases.append({'name':case.get('name'),'class':root.get('name'),'passed':case.find('failure') is None and case.find('error') is None and case.find('skipped') is None})
 for text in root.findall('system-out'):
  for match in re.findall(r'GHIDRABOY_VECTOR_EVIDENCE=(\{[^\n]+\})',text.text or ''):vectorRuns.append(json.loads(match))
if not suites:raise SystemExit('No actual test reports found')
counts={key:sum(s[key] for s in suites) for key in ['tests','failures','errors','skipped']}
checks={}
for audit in ['R1','R2','R3','R4','R5','R6']:
 matches=[case for case in cases if case['class'].endswith('AuditRegressionTest') and case['name'].startswith(audit+' ')]
 checks[audit]={'status':'PASS' if matches and all(c['passed'] for c in matches) else 'NOT_PASSED','tests':matches}
for label,classes in {'function-ownership':['FunctionOwnershipTest'],'analysis':['AnalysisLifecycleTest','AnalysisHardeningTest','AnalysisBoundaryTest'],'symbols':['SymbolTest','SymbolOwnershipTest','SymbolBoundaryTest'],'mapping':['CartridgeTest','MapperTopologyTest','SalvageTest'],'abi':['CompilerAbiTest','CompilerSpecTest']}.items():
 matches=[s for s in suites if s['name'].split('.')[-1] in classes]
 checks[label]={'status':'PASS' if len(matches)==len(classes) and all(s['failures']==s['errors']==s['skipped']==0 for s in matches) else 'NOT_PASSED','reports':[s['report'] for s in matches]}
externalRuns=[]
externalReports=[]
if a.external_results:
 for path in sorted(a.external_results.glob('TEST-*.xml')):
  root=ET.parse(path).getroot()
  externalReports.append({'path':str(path),'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'tests':int(root.get('tests','0')),'failures':int(root.get('failures','0')),'errors':int(root.get('errors','0'))})
  for out in root.findall('system-out'):
   for match in re.findall(r'GHIDRABOY_VECTOR_EVIDENCE=(\{[^\n]+\})',out.text or ''):externalRuns.append(json.loads(match))
commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip()
dirty=subprocess.check_output(['git','status','--porcelain'],cwd=repo,text=True).splitlines()
zipHash=hashlib.sha256(a.zip.read_bytes()).hexdigest()
record={'schemaVersion':1,'commit':commit,'dirty':bool(dirty),'dirtyPaths':dirty,'platform':{'system':platform.system(),'machine':platform.machine(),'release':platform.release()},'dependencies':json.loads((repo/'tools/dependencies.json').read_text()),'tests':counts,'testSuites':suites,'unitVectorRuns':vectorRuns,'comprehensiveVectorRuns':externalRuns,'comprehensiveReports':externalReports,'commands':receipts,'requirements':checks,'artifact':{'path':str(a.zip.resolve()),'sha256':zipHash},'complete':False}
required=['full-build','external-vectors','reproducibility','installed','migration','schema','doctor','metadata-incremental','gui']
record['complete']=not dirty and not any(r.get('status')=='FAIL' for r in receipts) and bool(externalRuns) and all(v['status']=='PASS' for v in checks.values()) and counts['failures']==counts['errors']==counts['skipped']==0 and all(any(r.get('gate')==gate and r.get('status')=='PASS' for r in receipts) for gate in required)
a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(record,indent=2)+'\n')
a.zip.with_name('SHA256SUMS').write_text(zipHash+'  '+a.zip.name+'\n')
rows=['# Generated requirement ledger','',f'Commit: `{commit}`; dirty: `{bool(dirty)}`.', '', '| Gate | Status | Evidence |','| --- | --- | --- |']
for name,check in checks.items():rows.append(f'| {name} | {check["status"]} | '+', '.join(check.get('reports',[]) or [c['name'] for c in check.get('tests',[])])+' |')
for r in receipts:rows.append(f'| {r.get("gate",r.get("name","command"))} | {r.get("status","UNKNOWN")} | {r.get("log",r.get("reason",""))} |')
rows+=['',f'Tests: {counts}.',f'ZIP SHA256: `{zipHash}`.',f'Full acceptance complete: **{record["complete"]}**.']
a.output.with_name('requirements.md').write_text('\n'.join(rows)+'\n')
print(json.dumps({'tests':counts,'sha256':zipHash,'complete':record['complete'],'unitVectorRuns':vectorRuns,'comprehensiveVectorRuns':externalRuns}))
