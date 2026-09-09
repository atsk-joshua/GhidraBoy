#!/usr/bin/env python3
"""Collect allowlisted candidate logs only; never private ROM/project/checkpoint files."""
from pathlib import Path
import datetime,os,zipfile
root=Path(__file__).resolve().parents[1]
results=root/'.local/results'
results.mkdir(parents=True,exist_ok=True)
evidence=Path(os.environ.get('GBC_EVIDENCE_DIR',str(results))).expanduser().resolve()
output=results/('GhiGBC-results-'+datetime.datetime.now().strftime('%Y%m%dT%H%M%S')+'.zip')
with zipfile.ZipFile(output,'x',compression=zipfile.ZIP_DEFLATED) as z:
    for folder in dict.fromkeys((evidence,results.resolve())):
        for file in sorted(folder.rglob('*')):
            if file.is_symlink() or any(p.is_symlink() for p in file.parents if p!=root) or not file.is_file():continue
            if file.suffix in ('.log','.txt','.json') and file.stat().st_size<=10*1024*1024:z.write(file,Path('evidence' if folder==evidence else 'results')/file.relative_to(folder))
    if (root/'NOTES.txt').is_file() and not (root/'NOTES.txt').is_symlink():z.write(root/'NOTES.txt','NOTES.txt')
print(output)
