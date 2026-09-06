#!/usr/bin/env python3
"""Compatibility reader and rollback for historical schema-2 install journals."""
import argparse,hashlib,json,os,shutil
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser();p.add_argument('--user-home',type=Path,default=Path.home());p.add_argument('--ghidra',type=Path,default=os.environ.get('GHIDRA_INSTALL_DIR'));p.add_argument('--rollback',type=Path);args=p.parse_args()
def hashes(folder):
    result={}
    for f in folder.rglob('*'):
        rel=f.relative_to(folder)
        if '__pycache__' in rel.parts or f.suffix in ('.sla','.pyc','.pyo'):continue
        if f.is_symlink():result[str(rel)]='link:'+os.readlink(f)
        elif f.is_file():result[str(rel)]=hashlib.sha256(f.read_bytes()).hexdigest()
    return result
if args.rollback:
    manifest=json.loads(args.rollback.read_text())
    manifest_path=args.rollback.resolve()
    if manifest_path.parent.parent.name!='GhiGBC-rollback':raise RuntimeError('Not a GhiGBC rollback manifest location')
    settings_root=manifest_path.parents[2]
    for entry in manifest['entries']:
        relative=Path(entry['destination']).resolve().relative_to(settings_root)
        if len(relative.parts)!=2 or not (relative.parts[0]=='GhiGBC-runtime' or (relative.parts[0]=='Extensions' and relative.parts[1] in ('GhidraBoy','GhiGBC'))):raise RuntimeError('Rollback destination is outside managed install paths')
        if entry.get('backup') and Path(entry['backup']).absolute().parent!=manifest_path.parent:raise RuntimeError('Rollback backup is outside its manifest directory')
    # Validate the entire rollback before changing anything.
    for entry in manifest['entries']:
        dest=Path(entry['destination'])
        if dest.exists() and hashes(dest)!=entry['installed']:raise RuntimeError(f'Installed files changed at {dest}; preserve them before rollback')
        if entry.get('backup') and not Path(entry['backup']).exists():raise RuntimeError('Rollback backup is missing')
    for entry in reversed(manifest['entries']):
        dest=Path(entry['destination'])
        if dest.exists():shutil.rmtree(dest)
        if entry.get('backup'):shutil.move(entry['backup'],dest)
    print('Rolled back',args.rollback);raise SystemExit
raise SystemExit('This compatibility helper only restores schema-2 journals; use scripts/install.py for new installations')
