#!/usr/bin/env python3
"""One genuine registry-4 witness and one old-provider edited copy. No proof conversion."""
import argparse
import hashlib
import copy
import json
from pathlib import Path
import shutil
from sm83_compatibility import REPO, Runner, compare, digest, differences, tree, write

def execute(a):
    for p in (a.ghidra,a.old_ghidra,a.projects):
        assert p.resolve().is_relative_to(Path('/tmp').resolve()) and 'ghidraboy' in str(p), 'Copied task-owned inputs only'
    assert digest(a.projects/'sa01-production.rep/idata/00/~00000000.db/db.3.gbf') == '7d5fd40dde93845453f8ffc4f91b1cbb581ba556b3d4cd8616acdcc57bc4511e'
    jars=list((a.old_ghidra/'Ghidra/Extensions/GhidraBoy/lib').glob('GhidraBoy-*.jar'))
    assert len(jars)==1 and digest(jars[0])=='f7502b8a0c7d80c0e171b5f77ca51f08e9f4f190e680217c1c99e40923c8f9f7'
    w=a.work;w.mkdir(parents=True,exist_ok=False);(w/'scripts').mkdir()
    for name in ('Sm83PreservationInventory','Sm83LegacyLaterEdit','Sm83LegacyAuthority'):
        shutil.copy2(REPO/'src/test/scripts'/(name+'.java'),w/'scripts')
    r=Runner(w,a.jdk,'sa01-production');source=tree(a.projects);write(w/'original-hashes.json',source)
    original=w/'old-copy';shutil.copytree(a.projects,original)
    r.capture(a.old_ghidra,original,'legacy-old','old-saved','production-mbc3-v2.gb')
    edited=w/'edited-old-copy';shutil.copytree(original,edited)
    r.run(a.old_ghidra,edited,'later-edit',['-process','production-mbc3-v2.gb','-postScript','Sm83LegacyLaterEdit.java'],'GENUINE_REGISTRY4_LATER_EDIT_SAVED')
    r.capture(a.old_ghidra,edited,'edited-old','old-saved','production-mbc3-v2.gb')
    results={}
    for tag,project in [('legacy',original),('edited',edited)]:
        upgraded=w/(tag+'-upgraded');shutil.copytree(project,upgraded)
        r.capture(a.ghidra,upgraded,tag+'-upgrade','upgrade','production-mbc3-v2.gb')
        r.capture(a.ghidra,upgraded,tag+'-immutable','immutable','production-mbc3-v2.gb')
        snapshots=[json.loads((w/(tag+'-'+phase+'.json')).read_text()) for phase in ('old','upgrade','immutable')]
        results[tag]=compare(*snapshots);write(w/(tag+'-diff.json'),results[tag])
        r.run(a.ghidra,upgraded,tag+'-refusal',['-preScript','Sm83LegacyAuthority.java',w/(tag+'-refusal.json'),'production-mbc3-v2.gb'],'SM83_LEGACY_RECORD_REFUSAL_PASS',expected_native_refusal=True)
        refusal=json.loads((w/(tag+'-refusal.json')).read_text());assert refusal['before']==refusal['after']
        # After core translation, record consumption is separately required to be nonmutating.
        assert refusal['before']==snapshots[2]['state']
    before=json.loads((w/'legacy-old.json').read_text())['state'];later=json.loads((w/'edited-old.json').read_text())['state']
    assert hashlib.sha256(bytes.fromhex(before['files'][0]['original'])).hexdigest()=='b7e0403c9c8c6cfb182be91bb771016b4c588f4793e8e271c330f57f988bd5b8'
    edits=differences(before,later);write(w/'later-edit-diff.json',edits)
    assert later['options']['GhidraBoy']['softwareCall.sites.v1']==before['options']['GhidraBoy']['softwareCall.sites.v1']
    assert later['options']['GhidraBoy']['analysis.ownership.v1']==before['options']['GhidraBoy']['analysis.ownership.v1']
    assert next(i for i in later['instructions'] if i['address']=='ram:0150')['fallthrough']=='ram:0159'
    mutated=copy.deepcopy(later);key='softwareCall.sites.v1'
    raw=mutated['options']['GhidraBoy'][key]['value'];assert 'software-call-registry-4' in raw
    mutated['options']['GhidraBoy'][key]['value']=raw.replace('software-call-registry-4','stock-software-call-registry-2')
    assert differences(later,mutated)
    overwritten=copy.deepcopy(later);next(i for i in overwritten['instructions'] if i['address']=='ram:0150')['fallthrough']='ram:0156'
    assert differences(later,overwritten)
    write(w/'genuine-controls.json',{'oldProofRelabeledCurrentRejected':True,'laterEditOverwriteRejected':True,'originalProof':raw,'mutatedProof':mutated['options']['GhidraBoy'][key]['value']})
    assert tree(a.projects)==source
    results['originalUnchanged']=True;results['disposition']='SCOPED_SAFE_REJECTION; general proof migration and final G4 master disposition remain open'
    write(w/'result.json',results);print('GENUINE_REGISTRY4_COMPATIBILITY_PASS')

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('ghidra','old-ghidra','projects','jdk','work'):p.add_argument('--'+name,type=Path,required=True)
    execute(p.parse_args())
