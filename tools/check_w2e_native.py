#!/usr/bin/env python3
"""Execute captured W2e payload and native HighFunction, never provider transfer code.
Adapted from W2a check-finite.py SHA256
806d22454ae145e8dd043b8ffb43fb6cca318ed8676975afb4a6d3355eb6718b.
Only observed straight-line p-code forms are supported. Synthetic mutants are checker tests.
"""
import argparse
import collections
import copy
import hashlib
import re
import subprocess
import tempfile
import json
from pathlib import Path
import xml.etree.ElementTree as ET

NATIVE = 'd60be1dd82b660b4123adbe2a8c7c3353a7974e856d4298208f8dc68490db871'
class Refusal(Exception): pass
class Insufficient(Exception): pass

def require(ok, message):
    if not ok: raise Refusal(message)
def read(path): return json.loads(path.read_text())
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def signature(v): return None if v is None else (v['space'], v['offset'], v['size'])

def debug_identity(path, emitted, entry, inject_name="__ghidraboy_state_entry_v1@@inject_uponentry"):
    """Compare a named actual debug replay; callers must separately verify runtime identity."""
    root = ET.fromstring(path.read_text())
    matches = [n for n in root.findall('.//injectdebug/inject') if n.get('name') == inject_name]
    require(len(matches) == 1, 'missing actual debug-recorded injection')
    node = matches[0]; at = node.find('addr'); space, offset = entry.split('::')
    require(at is not None and at.get('space') == space and int(at.get('offset'), 0) == int(offset, 16), 'foreign debug entry')
    operations = ET.fromstring(node.findtext('payload', '')).findall('op')
    require(len(operations) == len(emitted), 'debug/request operation count differs')
    for actual, expected in zip(operations, emitted):
        require(actual.get('code') == expected['mnemonic'], 'debug/request operation differs')
        nodes = list(actual); expected_nodes = [expected.get('output')] + expected['inputs']
        require(len(nodes) == len(expected_nodes), 'debug/request arity differs')
        for n, v in zip(nodes, expected_nodes):
            if v is None: require(n.tag == 'void', 'debug output differs')
            elif n.tag == 'spaceid':
                require(expected['mnemonic'] in {'LOAD', 'STORE'} and n.get('name') == 'ram' and v['constant'], 'debug space differs')
            else:
                require(n.tag == 'addr' and (n.get('space'), int(n.get('offset'), 0), int(n.get('size'))) == signature(v), 'debug operand differs')
    return {'status':'PASS','operations':len(operations),'surface':'debug replay injection record, not packed wire capture'}

def run_ops(ops, b, d, high=False):
    # Register offsets are pinned compiled SM83 language storage, checked by raw structured capture.
    entry = {0:0xf0, 1:0x95, 2:0x53, 3:b, 4:0xa6, 5:d, 6:0xef, 7:0xbe, 8:0x50, 9:1, 10:0xfc, 11:0xcf}
    storage = {('register', k):v for k,v in entry.items()}
    storage.update({('ram',0xcffc):0x90, ('ram',0xcffd):1})
    values = {}; outputs = {}; effects = []; returns = 0
    def get(v):
        if v['constant']: return v['offset'] & ((1 << (v['size']*8))-1)
        if high and v['id'] in values: return values[v['id']]
        if high and v['space'] == 'register':
            octets = [entry.get(v['offset']+i) for i in range(v['size'])]
        else: octets = [storage.get((v['space'],v['offset']+i)) for i in range(v['size'])]
        return None if any(x is None for x in octets) else sum(x << (8*i) for i,x in enumerate(octets))
    def put(v, value):
        if value is not None: value &= (1 << (v['size']*8))-1
        if high: values[v['id']] = value
        else:
            for i in range(v['size']): storage[(v['space'],v['offset']+i)] = None if value is None else (value >> (8*i)) & 255
        if v.get('address'):
            require(v['space']=='ram' and 0xc030 <= v['offset'] <= 0xc032 and v['size']==1, 'unexpected rooted memory write')
            # Native final SSA copies may repeat a rooted cell after its actual earlier definition.
            if outputs.get(v['offset']) != value or v['offset'] not in outputs:
                effects.append(['write',v['offset'],value])
            outputs[v['offset']] = value
    for index, op in enumerate(ops):
        code=op['mnemonic']; nodes=op['inputs']; args=[get(v) for v in nodes]; out=op.get('output'); result=None
        if code in {'COPY','CAST'}:
            if code=='CAST': require(high and out['size']==nodes[0]['size'], 'unsupported cast width')
            result=args[0]
        elif code == 'CALLOTHER':
            require(op.get('userop_name') in {'gb_direct_write8','gb_cartridge_write8'}, 'unknown userop')
            require(len(args)==3 and args[1] is not None and args[2] is not None, 'unconstrained effect')
            cpu,value=args[1:]
            if cpu==0x2000: effects.append(['mapper',cpu,value])
            else:
                require(not high and 0xc030 <= cpu <= 0xc032, 'unexpected native/device write')
                outputs[cpu]=value; effects.append(['write',cpu,value])
        elif code == 'STORE':
            require(high and len(args)==3 and nodes[0]['constant'] and nodes[1]['size']==2 and nodes[2]['size']==1, 'unsupported store shape')
            require(args[1] in {0xc030,0xc031,0xc032} and args[2] is not None, 'unproved store address/value')
            outputs[args[1]]=args[2];effects.append(['write',args[1],args[2]])
        elif code == 'LOAD':
            require(len(args)==2 and nodes[1]['size']==2 and args[1] in {0xcffc,0xcffd}, 'non-stack or unproved load remains')
            require(out['size']==1, 'stack load width changed'); result=0x90 if args[1]==0xcffc else 1
        elif code == 'RETURN':
            require(index==len(ops)-1, 'unreachable operations after return')
            returns += 1
            if not high: require(args==[0x190], 'raw symbolic stack return lost')
        elif code in {'INT_ADD','INT_SUB','INT_MULT','INT_AND','INT_OR','INT_XOR','INT_LEFT','INT_RIGHT','INT_EQUAL',
                      'INT_NOTEQUAL','INT_LESS','INT_LESSEQUAL','BOOL_NEGATE','BOOL_AND','BOOL_OR','BOOL_XOR',
                      'INT_ZEXT','INT_SEXT','INT_NEGATE','PIECE','SUBPIECE','INT_CARRY'}:
            if all(x is not None for x in args):
                a=args[0]; z=args[1] if len(args)>1 else None
                if code=='INT_ADD': result=a+z
                elif code=='INT_SUB': result=a-z
                elif code=='INT_MULT': result=a*z
                elif code in {'INT_AND','BOOL_AND'}: result=a&z
                elif code in {'INT_OR','BOOL_OR'}: result=a|z
                elif code in {'INT_XOR','BOOL_XOR'}: result=a^z
                elif code=='INT_LEFT': result=a<<z
                elif code=='INT_RIGHT': result=a>>z
                elif code=='INT_EQUAL': result=int(a==z)
                elif code=='INT_NOTEQUAL': result=int(a!=z)
                elif code=='INT_LESS': result=int(a<z)
                elif code=='INT_LESSEQUAL': result=int(a<=z)
                elif code=='BOOL_NEGATE': result=int(not a)
                elif code=='INT_ZEXT': result=a
                elif code=='INT_SEXT': result=a-(1 << (8*nodes[0]['size'])) if a & (1 << (8*nodes[0]['size']-1)) else a
                elif code=='INT_NEGATE': result=~a
                elif code=='PIECE': result=(a << (8*nodes[1]['size'])) | z
                elif code=='SUBPIECE': result=a >> (8*z)
                elif code=='INT_CARRY': result=int(a+z >= 1 << (8*nodes[0]['size']))
        else: raise Insufficient('unsupported observed operator '+code)
        if out is not None: put(out,result)
    require(returns==1, 'missing return')
    require(set(outputs)=={0xc030,0xc031}, 'missing rooted outputs')
    return {'outputs':[outputs[k] for k in (0xc030,0xc031)], 'effects':effects}

def flatten(blocks):
    if not (len(blocks)==1 and blocks[0]['index']==0 and not blocks[0]['in'] and not blocks[0]['out']):
        raise Insufficient('unsupported native CFG; no unreachable branch union accepted')
    return blocks[0]['ops']

def check_domain(ops, marker3, high=False):
    counts = collections.Counter()
    if not high:
        guards = [i for i, op in enumerate(ops) if op['mnemonic']=='INT_EQUAL'
                  and op['inputs'][1]['constant'] and op['inputs'][1]['offset'] in {2,3,4}]
        mapper = [i for i, op in enumerate(ops) if op['mnemonic']=='CALLOTHER'
                  and op['inputs'][1]['offset']==0x2000]
        require(len(mapper)==1 and guards and mapper[0] < min(guards),
                'requested mapper write deleted or moved after finite read lowering')
    for b in range(256):
        selector = (b & 3) + 1
        value = {1:0x31, 2:0xa7, 3:marker3, 4:0x5c}[selector]
        actual = run_ops(ops, b, 0xa3, high)
        require(actual['outputs'] == [value, selector], f'wrong rooted pair B={b}: {actual}')
        require(actual['effects'] == [['write',0xc031,selector], ['mapper',0x2000,selector],
                                      ['write',0xc030,value]], f'wrong ordered effects B={b}: {actual}')
        counts[(selector,value)] += 1
    return [{'selector':s, 'C030':v, 'C031':s, 'count':n} for (s,v),n in sorted(counts.items())]


def finite_choice_fields(proof):
    finite=proof['finite']
    if 'choices' in finite:
        require(finite['version']=='finite-entry-producer-w2g-joint-3','unexpected current finite authority')
        return 'choices','choice','key'
    return 'selectors','selector','selector'

def check_proof(proof, marker3):
    require(proof['entry']=='0150' and proof['analysis'].get('assumption') is None
            and proof.get('invocation') is None, 'foreign/selected static entry premise')
    require(''.join(i['bytes'] for i in proof['instructions']) ==
            '78e6033cea31c0ea00202100607eea30c0c9', 'proof does not bind exact four-way code')
    finite = proof['finite']; choices_key,choice_key,alternative_key=finite_choice_fields(proof); selectors = finite[choices_key]
    if choices_key=='choices':require(all(c['kind']=='MAPPER_SELECTOR' for c in selectors),'unexpected choice kind')
    require(len(selectors)==1 and selectors[0]['values']==[1,2,3,4]
            and selectors[0]['width']==1 and 'entry-register-byte@3' in selectors[0]['expression'],
            'missing, extra or unproduced selector')
    reads = [r for r in finite['reads'] if r.get(choice_key) is not None]
    require(len(reads)==1 and reads[0][choice_key]==selectors[0], 'uncorrelated read/selector')
    alternatives=reads[0]['alternatives']
    require(len(alternatives)==4 and [a[alternative_key] for a in alternatives]==[1,2,3,4],
            'missing, duplicate, reordered or extra alternative')
    for a in alternatives:
        s=a[alternative_key]; expected={1:0x31,2:0xa7,3:marker3,4:0x5c}[s]
        require(a['value']==expected and len(a['sources'])==1, 'swapped selector/physical value')
        source=a['sources'][0]; physical=source['physical']
        require(source['byteIndex']==0 and source['value']==expected
                and physical['region']=='ROM' and physical['bank']==s and physical['offset']==0x2000,
                'wrong physical source identity')


def check_c(path, marker3):
    """Compile the captured rooted C verbatim with only its named ABI/device stubs."""
    source=path.read_text()
    require(re.search(r'gb_ordinary_150_conditional\(undefined2 param_1\)', source), 'unsupported C ABI')
    header='''#include <stdio.h>
#include <stdint.h>
typedef uint8_t byte, undefined1; typedef uint16_t undefined2; typedef unsigned int uint;
#define __ghidraboy_state_entry_v1
#define __ghidraboy_stock_entry_v1
byte DAT_c030, DAT_c031; int mapper_count, mapper_selector, early;
void gb_cartridge_write8(unsigned cpu, unsigned value) {
  if (cpu != 0x2000 || DAT_c031 != (byte)value || DAT_c030 != 0) early=1;
  mapper_count++; mapper_selector=(byte)value;
}
'''
    driver='''int main(void) { for (int b=0;b<256;b++) {
  DAT_c030=DAT_c031=mapper_count=mapper_selector=early=0;
  gb_ordinary_150_conditional((b<<8)|0x53);
  printf("%d %d %d %d %d %d\\n",b,DAT_c030,DAT_c031,mapper_count,mapper_selector,early);
} return 0; }
'''
    with tempfile.TemporaryDirectory(prefix='w2e-rooted-c-') as tmp:
        c=Path(tmp)/'capture.c'; exe=Path(tmp)/'capture'; c.write_text(header+source+driver)
        build=subprocess.run(['cc','-std=c11','-O0',str(c),'-o',str(exe)], capture_output=True,text=True)
        require(build.returncode==0, 'captured C compile refused: '+build.stderr)
        run=subprocess.run([str(exe)],capture_output=True,text=True,check=True)
    rows=[list(map(int,line.split())) for line in run.stdout.splitlines()]
    require(len(rows)==256, 'C enumeration incomplete')
    for b,value,selector,count,mapper,early in rows:
        s=(b&3)+1; v={1:0x31,2:0xa7,3:marker3,4:0x5c}[s]
        require([value,selector,count,mapper,early]==[v,s,1,s,0], f'wrong rooted C relation/order B={b}')
    return {'status':'PASS','inputs':256,'c_sha256':sha(path),'compiler':'cc -std=c11 -O0'}


def negative_controls(emitted, high, proof):
    _,choice_key,alternative_key=finite_choice_fields(proof)
    results=[]
    def reject(name, function):
        try: function()
        except (Refusal, Insufficient) as e: results.append({'name':name,'status':'REJECTED','reason':str(e)})
        else: raise Refusal('negative control escaped: '+name)
    for name, mutation in [
        ('missing-alternative', lambda a: a.pop()),
        ('conflicting-duplicate-selector', lambda a: a[3].update({alternative_key:3})),
        ('swapped-selector-values', lambda a: (a[1].update(value=0xd3),a[2].update(value=0xa7))),
        ('unproduced-selector', lambda a: a.append(dict(a[-1],**{alternative_key:5}))),
        ('silent-budget-truncation', lambda a: a.__delitem__(slice(2,None))),
    ]:
        mutant=copy.deepcopy(proof); mutation(next(r for r in mutant['finite']['reads'] if r.get(choice_key))['alternatives'])
        reject(name, lambda m=mutant: check_proof(m,0xd3))
    choices=[i for i,o in enumerate(emitted) if o['mnemonic']=='INT_EQUAL' and o['inputs'][1]['constant'] and o['inputs'][1]['offset'] in {2,3,4}]
    require(len(choices)==3, 'unexpected branchless selection guard shape')
    mutant=copy.deepcopy(emitted)
    for i in choices:
        mutant[i]['inputs'][0]=dict(mutant[i]['inputs'][0], constant=True, space='const',
                                     offset=99, address=False, register=False)
    reject('selector-independent-constant',lambda:check_domain(mutant,0xd3))
    mutant=copy.deepcopy(emitted)
    mutant[choices[0]]['inputs'][1]['offset']=3;mutant[choices[1]]['inputs'][1]['offset']=2
    reject('swapped-runtime-association',lambda:check_domain(mutant,0xd3))
    writes=[i for i,o in enumerate(emitted) if o['mnemonic']=='CALLOTHER' and o['inputs'][1]['offset']==0x2000]
    require(len(writes)==1,'expected exactly one ordered mapper write')
    mutant=copy.deepcopy(emitted);del mutant[writes[0]]
    reject('deleted-mapper-write',lambda:check_domain(mutant,0xd3))
    mutant=copy.deepcopy(emitted); op=mutant.pop(writes[0]); mutant.insert(len(mutant)-1,op)
    reject('mapper-write-after-read',lambda:check_domain(mutant,0xd3))
    mutant=copy.deepcopy(high)
    root=next(o for o in mutant if o.get('output',{}).get('space')=='ram' and o['output']['offset']==0xc030)
    root['mnemonic']='COPY';root['inputs']=[dict(root['inputs'][0],constant=True,space='const',offset=0x31,size=1)]
    reject('native-constant-selected-display',lambda:check_domain(mutant,0xd3,True))
    reject('cartesian-unreachable-union',lambda:flatten([{'index':0,'in':[],'out':[],'ops':high},
                                                       {'index':1,'in':[],'out':[],'ops':high}]))
    return results


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture',type=Path,required=True);parser.add_argument('--fixture',type=Path,required=True)
    parser.add_argument('--out',type=Path,required=True);args=parser.parse_args();root=args.capture
    program=read(root/'program.json')
    require(program['image_sha256']==sha(args.fixture),'foreign fixture')
    require(read(root/'canonical-before.json')==read(root/'canonical-after-install.json'),'canonical modified')
    stale=read(root/'stale-request.json');mutation=read(root/'mutation.json')
    require(not stale['completed'] and not stale['highfunction_available']
            and 'Stale ordinary-entry registration' in stale['error'],'stale proof produced semantic output')
    require(mutation['changed_file_offsets']==[0xe000] and mutation['old']==0xd3 and mutation['new']==0xe4
            and mutation['old_registration_retained'] and mutation['read_only_ROM'],'not exactly consumed bank3 mutation')
    result={'checker_sha256':sha(Path(__file__)),'fixture_sha256':sha(args.fixture),'stages':{},
            'scope':'One unspecialized provider-owned native entry per revision; all 256 incoming B values. No display premise.'}
    owners=[]
    for label,marker in [('original',0xd3),('refreshed',0xe4)]:
        proof=read(root/f'{label}-proof.json');check_proof(proof,marker)
        emitted=read(root/f'{label}-requested-entry-pcode.json');request=read(root/f'{label}-request.json')
        require(request['completed'] and request['highfunction_available'],'native request failed')
        native=[p for p in request['processes_after'] if p.get('binary_sha256')==NATIVE and p.get('parent')==request['owner_java_pid']]
        require(len(native)==1,'native binary/owner mismatch');owners.append((request['owner_java_pid'],native[0]['pid'],request['entry']))
        debug=root/f'{label}-debug.xml';require(sha(debug)==request['debug']['sha256'],'changed debug capture')
        high=flatten(read(root/f'{label}-high.json'))
        stage={'requested':check_domain(emitted,marker),'native_high':check_domain(high,marker,True),
               'actual_requested_binding':debug_identity(debug,emitted,request['entry']),
               'native_c':check_c(root/f'{label}.c',marker),'native_owner':owners[-1]}
        result['stages'][label]=stage
        if label=='original':result['negative_controls']=negative_controls(emitted,high,proof)
    require(owners[0]==owners[1],'native owner/entry changed between revisions')
    result['status']='PASS';args.out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))

if __name__=='__main__': main()
