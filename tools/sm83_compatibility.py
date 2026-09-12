#!/usr/bin/env python3
"""Installed final-SM83-1 upgrade, core-only capture, immutable first use and cancellation.
All runtimes and projects are disposable copies. The old installed provider must match
all ten pinned final-language-1 inputs; historical protocol/core binaries are not candidates.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import zipfile

REPO = Path(__file__).resolve().parents[1]
OLD_SOURCE = 'eaf60575e212ae91e64aef48ba691fed2d3f878a'
INPUTS = ['sm83.ldefs', 'sm83.pspec', 'sm83.sinc', 'sm83.slaspec', 'sm83_instructions.sinc',
          'sm83.cspec', 'sdcc451-call0.cspec', 'sdcc451-call1-first8.cspec',
          'sdcc451-call1-first16.cspec', 'sdcc451-call1-first32.cspec']

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def tree(path):
    return {str(p.relative_to(path)): digest(p) for p in sorted(path.rglob('*')) if p.is_file()}

def write(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')

def differences(a, b, path=''):
    if type(a) is not type(b): return [{'path': path, 'old': a, 'new': b}]
    if isinstance(a, dict):
        result = []
        for k in sorted(a.keys() | b.keys()):
            if k not in a or k not in b: result.append({'path': path+'/'+k, 'old': a.get(k), 'new': b.get(k)})
            else: result.extend(differences(a[k], b[k], path+'/'+k))
        return result
    if isinstance(a, list):
        if len(a) != len(b): return [{'path': path, 'old': a, 'new': b}]
        return [d for i, (x, y) in enumerate(zip(a, b)) for d in differences(x, y, path+'/'+str(i))]
    return [] if a == b else [{'path': path, 'old': a, 'new': b}]

def canonical(state, version):
    s = copy.deepcopy(state)
    assert s['language']['id'] == 'SM83:LE:16:default'
    assert s['language']['version'] == version and s['language']['minor'] == 0
    s['language']['version'] = 1
    context = [r for r in s['registers'] if r['context']]
    if version == 2:
        assert context == [
            {'address': 'register:10', 'base': 'contextreg', 'bits': 32, 'context': True, 'lsb': 0, 'minimumByteSize': 4, 'name': 'contextreg'},
            {'address': 'register:10', 'base': 'contextreg', 'bits': 1, 'context': True, 'lsb': 7, 'minimumByteSize': 1, 'name': 'gb_analysis_entry'}]
    else: assert not context
    s['registers'] = [r for r in s['registers'] if not r['context']]
    facts = []
    for r in s['registerFacts']:
        if r['register'] in ('contextreg', 'gb_analysis_entry'):
            assert version == 2 and r['value'].endswith('value=0x00000000'), r
        else: facts.append(r)
    s['registerFacts'] = facts
    for ins in s['instructions']:
        assert ins['analysisMode'] == ('0' if version == 2 else 'absent'), ins['address']
        ins['analysisMode'] = 'ordinary'
        # The structured p-code preserves opcode, order, widths, spaces and relative UNIQUE
        # byte offsets. Raw text is retained as evidence, but UNIQUE allocation is not semantics.
        del ins['rawPcode']
    return s

def compare(old, post, reopened, corpus=False, transitions=None):
    assert old['phase'] == 'old-saved' and post['phase'] == 'upgrade' and reopened['phase'] == 'immutable'
    assert len({old['pid'], post['pid'], reopened['pid']}) == 3, 'Separate processes required'
    assert old['changeable'] is False and post['changeable'] is True and reopened['changeable'] is False
    a, b, c = canonical(old['state'], 1), canonical(post['state'], 2), canonical(reopened['state'], 2)
    # Core upgrade invalidates the in-memory default of this single optional Ghidra field;
    # the saved blank returns on immutable reopen. Never normalize a nonblank user value.
    key = 'Preferred Root Namespace Category'
    av = a['options'].get('Program Information', {}).get(key)
    bv = b['options'].get('Program Information', {}).get(key)
    cv = c['options'].get('Program Information', {}).get(key)
    classified = []
    if av == cv == {'type': 'STRING_TYPE', 'value': ''} and bv == {'type': 'STRING_TYPE', 'value': 'null'}:
        classified.append({'path': 'options/Program Information/'+key, 'old': av, 'post': bv, 'reopen': cv, 'reason': 'Transient absent blank default during core translation; saved value restored on immutable use'})
        b['options']['Program Information'][key] = av
    if transitions is not None:
        assert len(a['instructions']) == len(b['instructions'])
        for prior, current in zip(a['instructions'], b['instructions']):
            if prior['pcode'] == current['pcode']: continue
            entry = next((t for t in transitions if t['bytes'] == prior['bytes'] and t['mnemonic'] == prior['mnemonic'] and t['old_sha256'] == pcode_digest(prior['pcode']) and t['current_sha256'] == pcode_digest(current['pcode'])), None)
            assert entry is not None, 'Unclassified historical p-code change: '+prior['address']
            classified.append({'address': prior['address'], 'historical_semantic_correction': entry})
            prior['pcode'] = current['pcode']
    delta = differences(a, b) + differences(b, c)
    assert not delta, json.dumps(delta[:8], indent=2)
    if corpus: assert len(a['instructions']) == 501, 'Complete 501-member old inventory required'
    return {'status': 'PASS', 'instructions': len(a['instructions']), 'unclassified': delta,
            'classified': classified, 'raw_old_post_diff': differences(old['state'], post['state']),
            'raw_post_reopen_diff': differences(post['state'], reopened['state'])}

class Runner:
    def __init__(self, work, jdk, project_name="fixture"):
        self.project_name = project_name
        self.work, self.jdk = work, jdk
        self.commands = json.loads((work/'commands.json').read_text()) if (work/'commands.json').exists() else []
    def run(self, runtime, project, phase, arguments, marker, expected_native_refusal=False):
        profile = self.work/(phase+'-profile'); profile.mkdir()
        project.mkdir(exist_ok=True)
        cmd = [str(runtime/'support/analyzeHeadless'), str(project), self.project_name, '-scriptPath', str(self.work/'scripts'), *map(str, arguments), '-noanalysis']
        env = dict(os.environ, JAVA_HOME=str(self.jdk), XDG_CACHE_HOME=str(profile), JAVA_TOOL_OPTIONS='-Duser.home='+str(profile))
        with (self.work/(phase+'.log')).open('w') as out:
            r = subprocess.run(cmd, env=env, cwd=self.work, stdout=out, stderr=subprocess.STDOUT)
        text = (self.work/(phase+'.log')).read_text()
        errors = [line for line in text.splitlines() if 'ERROR' in line or 'error:' in line]
        expected_error = ('ERROR Unexpected Exception: Unavailable stock analysis entry: Stale predicated graph registration; explicit refresh required' if expected_native_refusal == 'stock-stale' else 'ERROR Unexpected Exception: Unresolved software-call injection at 0150: Incompatible software-call registry; retained without migration')
        accounted = bool(expected_native_refusal) and len(errors) == 1 and expected_error in errors[0]
        record = {'errors': errors, 'expectedNativeRefusalAccounted': accounted, 'phase': phase, 'command': cmd, 'exit': r.returncode, 'marker': marker, 'markerObserved': marker in text}
        self.commands.append(record); write(self.work/'commands.json', self.commands)
        assert r.returncode == 0 and marker in text and (not errors or accounted), phase+' failed; retained log'
        if 'upgrade' in phase:
            assert 'sm83-1-2.trans' in text and 'Setting language' in text, 'Actual installed core translator required'
        if 'immutable' in phase:
            assert 'Setting language' not in text, 'Reopen must already be current format'
        return record

    def capture(self, runtime, project, phase, mode, name):
        return self.run(runtime, project, phase, ['-preScript', 'Sm83PreservationInventory.java', mode, self.work/(phase+'.json'), name], 'SM83_INVENTORY_PASS '+mode)

def execute(args):
    w=args.work.resolve(); w.mkdir(parents=True, exist_ok=False)
    for runtime in (args.old_ghidra, args.ghidra):
        assert runtime.resolve().is_relative_to(Path('/tmp').resolve()) and 'ghidraboy' in str(runtime), 'Task-owned temporary runtimes required'
    old=args.old_ghidra; new=args.ghidra
    expected={name:hashlib.sha256(subprocess.check_output(['git','show',OLD_SOURCE+':data/languages/'+name],cwd=REPO)).hexdigest() for name in INPUTS}
    languages=old/'Ghidra/Extensions/GhidraBoy/data/languages'
    assert {n:digest(languages/n) for n in INPUTS} == expected, 'Wrong final language-1 provider inputs'
    assert digest(languages/'sm83.sla') == '02f52cc6eeb44ebc94cfda1d24e58e73b27b8585e729ea30dff1807a0a994a2a', 'Wrong compiled final-language-1 decoder'
    manifest={'source':OLD_SOURCE,'inputs':expected,'old_provider':tree(old/'Ghidra/Extensions/GhidraBoy'),'candidate_zip':digest(args.zip)}
    write(w/'inputs.json',manifest)
    target=new/'Ghidra/Extensions/GhidraBoy'
    if target.exists():shutil.move(target,w/'previous-candidate-extension')
    with zipfile.ZipFile(args.zip) as z:z.extractall(new/'Ghidra/Extensions')
    scripts=w/'scripts';scripts.mkdir()
    for name in ('GhidraBoyPreservation','GhidraBoyInstructionCompatibility','Sm83CompatibilityFixture','Sm83PreservationInventory','Sm83CancelUpgrade','GenerateSm83OldLanguage'):
        shutil.copy2(REPO/'src/test/scripts'/(name+'.java'),scripts)
    run=Runner(w,args.jdk); original=w/'original'; original.mkdir()
    run.run(old,original,'create',['-preScript','GhidraBoyPreservation.java','create','mbc5'],'PRESERVATION_CREATED')
    run.run(old,original,'annotate',['-process','preserved','-postScript','Sm83CompatibilityFixture.java'],'SM83_ANNOTATED_FIXTURE_PASS')
    (w/'corpus.bin').write_bytes(bytes(0x8000))
    run.run(old,original,'corpus-seed',['-import',w/'corpus.bin','-loader','BinaryLoader','-processor','SM83:LE:16:default','-cspec','default','-postScript','GhidraBoyInstructionCompatibility.java','seed',w/'corpus-seed.txt'],'INSTRUCTION_COMPATIBILITY_PASS instructions=501')
    for name,tag in [('preserved','annotated'),('corpus.bin','corpus')]:run.capture(old,original,tag+'-old','old-saved',name)
    frozen=tree(original);write(w/'original-hashes.json',frozen)
    upgraded=w/'upgraded';shutil.copytree(original,upgraded)
    results={}
    for name,tag in [('preserved','annotated'),('corpus.bin','corpus')]:
        run.capture(new,upgraded,tag+'-upgrade','upgrade',name)
        run.capture(new,upgraded,tag+'-immutable','immutable',name)
        snapshots=[json.loads((w/(tag+'-'+phase+'.json')).read_text()) for phase in ('old','upgrade','immutable')]
        results[tag]=compare(*snapshots,corpus=tag=='corpus');write(w/(tag+'-diff.json'),results[tag])
    aborted=w/'cancelled-copy';shutil.copytree(original,aborted)
    run.run(new,aborted,'cancel',['-preScript','Sm83CancelUpgrade.java','preserved',w/'cancel.json'],'SM83_CANCEL_AFTER_UPGRADE_ROLLBACK_NO_SAVE_PASS')
    restored=w/'restored-original';shutil.copytree(original,restored)
    run.capture(old,restored,'recovered','old-saved','preserved')
    assert json.loads((w/'recovered.json').read_text())['state']==json.loads((w/'annotated-old.json').read_text())['state']
    assert tree(original)==frozen, 'Original project changed'
    shutil.copy2(REPO/'src/test/scripts/Sm83MigratedStock.java',scripts)
    stock_variant=w/'new-stock-variant';shutil.copytree(upgraded,stock_variant)
    run.run(new,stock_variant,'new-stock',['-process','preserved','-postScript','Sm83MigratedStock.java',w/'new-stock.json'],'SM83_MIGRATED_NEW_STOCK_PASS',expected_native_refusal='stock-stale')
    results['sensitivity']=sensitivity(w)
    results['cancellation']={'status':'PASS','originalUnchanged':True,'restoredOldProviderInventoryEqual':True,'failedCopyPublished':False}
    write(w/'result.json',results)
    print('SM83_INSTALLED_COMPATIBILITY_PASS',flush=True)


def validate_capture_commands(records, tag):
    for suffix, mode in [('old', 'old-saved'), ('upgrade', 'upgrade'), ('immutable', 'immutable')]:
        record = next(r for r in records if r['phase'] == tag+'-'+suffix)
        command = record['command']
        at = command.index('-scriptPath')
        assert command[at+2:at+5] == ['-preScript', 'Sm83PreservationInventory.java', mode]
        assert len(command[at+2:]) == 6 and command[-1] == '-noanalysis', 'Hidden intervention before first use'
        assert record['exit'] == 0 and record['markerObserved']

def sensitivity(work):
    def load(name): return json.loads((work/name).read_text())
    trio = [load('annotated-'+s+'.json') for s in ('old','upgrade','immutable')]
    compare(*trio)
    results = []
    mutations = {
        'lost comment': lambda s: s['comments'].pop(),
        'lost Function field': lambda s: s['functions'][0].update(comment='lost'),
        'altered reference binding': lambda s: s['references'][0].update(symbolId=99999),
        'altered primary symbol': lambda s: s['symbols'][0].update(primary=not s['symbols'][0]['primary']),
        'lost overlay': lambda s: s['blocks'].pop(),
        'lost ROM patch': lambda s: s['files'][0].update(modified=s['files'][0]['original']),
        'changed register storage': lambda s: s['registers'][0].update(address='register:77'),
        'changed custom Function storage': lambda s: s['functions'][0]['return']['storage'][0].__setitem__(1,77),
        'changed p-code operand width': lambda s: s['instructions'][0]['pcode'][0]['inputs'][0].update(size=8),
        'canonical analysis mode': lambda s: s['instructions'][0].update(analysisMode='1'),
        'old proof relabeled current': lambda s: s['options']['GhidraBoy'].update({'softwareCall.sites.v1': {'type':'STRING_TYPE','value':'{"version":"stock-software-call-registry-2"}'}}),
        'later user edit overwritten': lambda s: s['instructions'][0].update(fallthrough='ram:0156'),
    }
    for name, mutation in mutations.items():
        changed=copy.deepcopy(trio);mutation(changed[1]['state'])
        try:compare(*changed)
        except AssertionError:results.append({'control':name,'rejected':True})
        else:raise AssertionError('Insensitive comparator: '+name)
    changed=copy.deepcopy(trio);changed[2]['pid']=changed[1]['pid']
    try:compare(*changed)
    except AssertionError:results.append({'control':'fake same-process reopen','rejected':True})
    else:raise AssertionError('Accepted same-process reopen')
    corpus=[load('corpus-'+s+'.json') for s in ('old','upgrade','immutable')];compare(*corpus,corpus=True)
    corpus[1]['state']['instructions'].pop()
    try:compare(*corpus,corpus=True)
    except AssertionError:results.append({'control':'omitted corpus member','rejected':True})
    else:raise AssertionError('Accepted omitted corpus member')
    commands=load('commands.json');validate_capture_commands(commands,'annotated')
    changed=copy.deepcopy(commands)
    next(r for r in changed if r['phase']=='annotated-immutable')['command'].extend(['-postScript','Verify1131Upgrade.java'])
    try:validate_capture_commands(changed,'annotated')
    except AssertionError:results.append({'control':'hidden enhancement/reanalysis before first use','rejected':True})
    else:raise AssertionError('Accepted hidden intervention')
    write(work/'sensitivity.json',results)
    return results


def pcode_digest(code):
    return hashlib.sha256(json.dumps(code, sort_keys=True, separators=(',', ':')).encode()).hexdigest()

def historical_transitions():
    return json.loads((REPO/'src/test/resources/compatibility/historical-pcode-transitions.json').read_text())['transitions']

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('old-ghidra','ghidra','zip','jdk','work'):p.add_argument('--'+n,type=Path,required=True)
    execute(p.parse_args())
