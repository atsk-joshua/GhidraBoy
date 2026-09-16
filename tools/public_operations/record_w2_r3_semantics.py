#!/usr/bin/env python3
"""Run and fingerprint every maintained semantic replay used by W2-R3."""
import argparse
import hashlib
import json
from pathlib import Path
import check_window


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('root',type=Path);parser.add_argument('--out',type=Path,required=True);args=parser.parse_args()
    lanes={'first':args.root/'first-jvm-final'/'captures','second':args.root/'second-jvm-final'/'captures'}
    labels=[('first','genuine-carrier-positive'),('first','topology-first-use'),('first','saved-current-positive'),('second','immutable-first')]
    results={};inputs={}
    for lane,label in labels:
        root=lanes[lane];results[label]=check_window.check(root,label,1,support_only=True)
        request=json.loads((root/(label+'-request.json')).read_text())
        retained=root/(request['retained_display_prefix']+'.json')
        consumed=[root/'timeline.json',retained,*sorted(root.glob(label+'*'))]
        inputs[label]={str(path.relative_to(args.root)):sha(path) for path in consumed if path.is_file()}
    sources=[Path(__file__).resolve(),Path(check_window.__file__).resolve(),Path(check_window.conditional.__file__).resolve(),Path(check_window.window.__file__).resolve(),Path(check_window.core.__file__).resolve()]
    record=dict(status='PASS',kernel='tools/public_operations/check_window.py -> tools/check_conditional_calls.py',checker_sources={str(path):sha(path) for path in sources},inputs=inputs,labels=results,total_cases=sum(result['cases'] for result in results.values()),delta=1,visual='UNOBSERVED')
    args.out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record,indent=2))


if __name__=='__main__':main()
