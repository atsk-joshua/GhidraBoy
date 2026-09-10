#!/usr/bin/env python3
"""Aggregate exact-artifact stock subresults; failures remain separate, never a product PASS."""
import argparse,json,hashlib,zipfile,xml.etree.ElementTree as ET
from pathlib import Path
import check_stock_entry as stock
import check_predicated_calls as core
import check_w3b_cfg as loops
import check_w4_memory_images as memory
import check_w3b_order as order
import check_w2e_native as ordinary

def check(a):
    root=a.root;mac=root/'mac';runtime=root/'mac-purity.json';result={}
    def record(name,fn):
        try:result[name]={'status':'PASS','result':fn()}
        except Exception as e:result[name]={'status':'FAIL','reason':type(e).__name__+': '+str(e)}
    for name,fn in [('g2',lambda c,i:core.run_stage(c,i)),('loop',lambda c,i:loops.loop_stage(c,i))]:
        fixture=Path(__file__).resolve().parents[1]/'src/test/resources/ordinary/PREDICATED_CALLS.gb' if name=='g2' else mac/'fixtures/W3B_LOOP.gb'
        record(name,lambda name=name,fn=fn,fixture=fixture:fn(stock.StockCapture(mac/name,runtime),fixture.read_bytes()))
        record(name+'-mutants',lambda name=name,fixture=fixture:(core.mutants if name=='g2' else loops.loop_negatives)(stock.StockCapture(mac/name,runtime),fixture.read_bytes()))
    image=(mac/'fixtures/W4_MEMORY_IMAGE.gb').read_bytes()
    for folder,label,mode,binding in [('memory',x,'A','memory') for x in ['memory','poison83','poison255']]+[('image','image1','I1','image'),('image','image2','I2','image'),('source','source','I1','source'),('image-reopen','reopen','I2','reopen'),('controls-samebytes','image3','I2','samebytes')]:
        record(folder+'/'+label,lambda folder=folder,label=label,mode=mode,binding=binding:memory.evaluate(mac/folder,label,mode,image,core.read(mac/folder/(binding+'-bindings.json')),stock.StockCapture(mac/folder,runtime,label)))
    for folder,label in [('domains','forward'),('domains','reverse'),('domains-reopen','reopened')]:
        record(folder+'/'+label,lambda folder=folder,label=label:loops.domains_stage(stock.StockCapture(mac/folder,runtime,label),(mac/'fixtures/W3B_DOMAINS.gb').read_bytes()))
    def ordinary_check():
        results={}
        for label,value in [('original',0xd3),('refreshed',0xe4)]:
            folder=mac/'ordinary';proof=core.read(folder/(label+'-proof.json'));emitted=core.read(folder/(label+'-requested-entry-pcode.json'));high=ordinary.flatten(core.read(folder/(label+'-high.json')))
            results[label]={'proof':ordinary.check_proof(proof,value),'emitted':ordinary.check_domain(emitted,value),'native':ordinary.check_domain(high,value,True),'native_c':ordinary.check_c(folder/(label+'.c'),value)}
            if label=='original':results['mutants']=ordinary.negative_controls(emitted,high,proof)
            ordinary.debug_identity(folder/(label+'-debug.xml'),emitted,core.read(folder/(label+'-request.json'))['entry'],inject_name='gb_analysis_entry_v1')
        return results
    record('ordinary',ordinary_check)
    def native_order(req):
        r=core.read(runtime);core.require(any(p.get('parent')==req['owner_java_pid'] and p.get('command')==r['native_path'] and p.get('binary_sha256')==r['native_sha256'] for p in req['processes_after']),'wrong stock order process')
        ordinary.debug_identity(mac/'order/root-debug.xml',core.read(mac/'order/root-requested.json'),req['entry'],inject_name='ghidraboy_software_call_v1')
    record('exact-continuation',lambda:order.check(mac/'order',root/'continuation-order.json',native_order))
    def lifecycle():
        values={}
        for name in ['g2','loop']:
            folder=mac/name;good=core.read(folder/'original-root-request.json');bad=core.read(folder/'missing-authority-root-request.json');again=core.read(folder/'restored-authority-root-request.json')
            core.require(good['completed'] and again['completed'] and not bad['completed'] and not bad['highfunction_available'],'wrong authority lifecycle '+name)
            core.require(len({x['native_interface_identity'] for x in [good,bad,again]})==1,'different interface '+name);values[name]='positive / missing / explicit refresh passed on one interface'
        folder=mac/'image';good=core.read(folder/'image1-root-request.json');bad=core.read(folder/'stale-image1-request.json');again=core.read(folder/'image2-root-request.json')
        core.require(good['completed'] and again['completed'] and not bad['completed'] and not bad['highfunction_available'],'replacement did not refuse')
        core.require(len({x['native_interface_identity'] for x in [good,bad,again]})==1,'image interface replaced');values['replacement']='same interface, explicit new lifetime'
        for folder in [mac/'damage',mac/'controls-interference']:
            bad=core.read(folder/('damaged-request.json' if folder.name=='damage' else 'interference-request.json'))
            core.require(not bad['completed'] and not bad['highfunction_available'] and bad['error'],'invalid authority exposed native function');values[folder.name]=bad['error']
        bad=core.read(mac/'controls-samebytes/same-bytes-stale-image2-request.json');core.require(not bad['completed'] and not bad['highfunction_available'] and 'Noncurrent executable generation' in bad['error'],'same bytes old lifetime consumed')
        path=core.read(mac/'controls-samebytes/path-controls.json');core.require(path['authorityUnchanged'] and not path['overlap']['coverageComplete'] and path['disjoint']['coverageComplete'] and not path['disjoint']['frontier'],'image footprint controls failed')
        values['samebytes']=core.read(mac/'controls-samebytes/same-bytes-old-generation.json');values['image-footprints']='overlap kills fetch; disjoint retains fetch; persistent image authority unchanged'
        return values
    record('lifecycle-and-controls',lifecycle)
    def persistence():
        core.require((mac/'image/saved-authority.json').read_bytes()==(mac/'image-reopen/reopen-authority.json').read_bytes(),'image authority changed')
        core.require((mac/'domains/persisted-registration.json').read_bytes()==(mac/'domains-reopen/reopened-registration.json').read_bytes(),'domain authority changed')
        before=core.read(mac/'image/image2-before-identity.json');after=core.read(mac/'image-reopen/reopen-before-identity.json')
        core.require(before['java_pid']!=after['java_pid'] and all(before[k]==after[k] for k in ['program_id','views','current_image_sha256','provider_jar_sha256']),'image identity mismatch')
        c=core.read(mac/'domains-reopen/reopen-compatibility.json');core.require(c['readOnly'] and c['registrationUnchanged'],'reopen mutated domain')
        differences=core.read(mac/'project-reopen-differences.json');core.require(set(differences)<= {'idata/~journal.bak','idata/~index.bak'},'Program/database change on read-only reopen')
        return {'separate_processes':True,'image_and_domain_authority_unchanged':True,'exact_project_housekeeping':differences}
    record('persistence',persistence)
    a.out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({k:v['status']+((': '+v['reason']) if 'reason'in v else '') for k,v in result.items()},indent=2))
    return all(v['status']=='PASS' for v in result.values())
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True);p.add_argument('--out',type=Path,required=True);raise SystemExit(0 if check(p.parse_args()) else 1)
