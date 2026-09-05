#!/usr/bin/env python3
"""Collect allowlisted candidate logs only; never private ROM/project/checkpoint files."""
from pathlib import Path
import datetime,zipfile
root=Path(__file__).resolve().parents[1]
output=root/('GhiGBC-results-'+datetime.datetime.now().strftime('%Y%m%dT%H%M%S')+'.zip')
with zipfile.ZipFile(output,'x',compression=zipfile.ZIP_DEFLATED) as z:
    for folder in (root/'docs/evidence',root/'.local/results'):
        for file in sorted(folder.rglob('*')):
            if file.is_symlink() or any(p.is_symlink() for p in file.parents if p!=root) or not file.is_file():continue
            if file.suffix in ('.log','.txt','.json') and file.stat().st_size<=10*1024*1024:z.write(file,file.relative_to(root))
    if (root/'NOTES.txt').is_file() and not (root/'NOTES.txt').is_symlink():z.write(root/'NOTES.txt','NOTES.txt')
print(output)
