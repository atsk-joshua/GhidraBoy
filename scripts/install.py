#!/usr/bin/env python3
"""Install versioned per-user runtime + extensions; rollback preserves prior runtime."""
import argparse,datetime,hashlib,json,os,platform,shutil,subprocess,zipfile
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
if not args.ghidra:raise SystemExit('Set GHIDRA_INSTALL_DIR or pass --ghidra /path/to/ghidra_12.1.2_PUBLIC')
properties=dict(line.split('=',1) for line in (args.ghidra/'Ghidra/application.properties').read_text().splitlines() if '=' in line and not line.startswith('#'))
if properties.get('application.version')!='12.1.2':raise SystemExit('This package requires Ghidra 12.1.2')
home=args.user_home.resolve()
if platform.system()=='Darwin':settings=home/'Library/ghidra/ghidra_12.1.2_PUBLIC';suffix='dylib'
elif platform.system()=='Linux':settings=home/'.config/ghidra/ghidra_12.1.2_PUBLIC';suffix='so'
else:raise SystemExit('Target Linux x86-64 or development macOS arm64 required')
archives=[max((ROOT/'.deps/GhidraBoy/build/distributions').glob('ghidra_12.1.2_*.zip'),key=lambda x:x.stat().st_mtime),max((ROOT/'ghidra-extension/dist').glob('ghidra_12.1.2_*_GhiGBC.zip'),key=lambda x:x.stat().st_mtime)]
for file in (ROOT/f'build/libghigbc.{suffix}',ROOT/'.deps/SameBoy/build/bin/BootROMs/cgb_boot.bin',ROOT/'.venv12/bin/python'):
    if not file.is_file():raise SystemExit(f'Build prerequisite missing: {file}')
extensions=settings/'Extensions'
# Reject duplicate language definitions in either installation or per-user modules.
for folder in (extensions,args.ghidra/'Ghidra/Extensions'):
    for language in folder.rglob('*.ldefs'):
        if 'SM83:LE:16:default' not in language.read_text():continue
        if folder!=extensions or language.relative_to(extensions).parts[0]!='GhidraBoy':raise RuntimeError(f'Existing SM83 language in {language}; use a single compatible GhidraBoy installation')
stamp=datetime.datetime.now().strftime('%Y%m%dT%H%M%S%f')
backup=settings/'GhiGBC-rollback'/stamp;backup.mkdir(parents=True)
runtime=settings/'GhiGBC-runtime'/('0.1.0-'+stamp)
manifest={'schema':2,'ghidra':'12.1.2','source':str(ROOT),'runtime':str(runtime),'entries':[]}
def record(entry):
    entry['installed']=hashes(Path(entry['destination']));manifest['entries'].append(entry)
    (backup/'manifest.json').write_text(json.dumps(manifest,indent=2))
def copy_file(relative):
    dest=runtime/relative;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(ROOT/relative,dest)
try:
    runtime.mkdir(parents=True)
    for relative in ('python/ghigbc','LICENSES'):
        shutil.copytree(ROOT/relative,runtime/relative,ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
    for relative in (f'build/libghigbc.{suffix}','build/teaching.gbc','.deps/SameBoy/build/bin/BootROMs/cgb_boot.bin','native/patches/0001-cpu-bus-provenance.patch','legacy/gbw3-live-lab/gbw3_core.py','legacy/gbw3-live-lab/gbw3_lab.py','dependencies.lock.json','LICENSE','scripts/doctor.py','scripts/install.py'):
        copy_file(relative)
    subprocess.run([str(ROOT/'.venv12/bin/python'),'-m','venv',str(runtime/'.venv12')],check=True,stdout=subprocess.DEVNULL)
    python=runtime/'.venv12/bin/python'
    subprocess.run([str(python),'-m','pip','install','--no-index','--find-links',str(args.ghidra.resolve()/'Ghidra/Debug/Debugger-rmi-trace/pypkg/dist'),'ghidratrace==12.1','protobuf==6.31.0'],check=True,stdout=subprocess.DEVNULL)
    env=dict(os.environ,PYTHONPATH=str(runtime/'python'))
    subprocess.run([str(python),'-c','from ghigbc.native import Machine,ROOT; m=Machine(ROOT/"build/teaching.gbc"); assert m.capture().state["abi"]==1; m.close()'],check=True,env=env)
    record({'kind':'runtime','destination':str(runtime),'backup':None})
    extensions.mkdir(parents=True,exist_ok=True)
    for archive in archives:
        with zipfile.ZipFile(archive) as z:
            names=z.namelist();top=names[0].split('/')[0]
            if top not in ('GhidraBoy','GhiGBC') or any(Path(n).is_absolute() or '..' in Path(n).parts or n.split('/')[0]!=top for n in names):raise RuntimeError('Unsafe archive layout')
            dest=extensions/top;entry={'kind':'extension','destination':str(dest),'backup':None}
            if dest.exists():entry['backup']=str(backup/top);shutil.move(dest,backup/top)
            try:
                z.extractall(extensions)
                launcher=dest/'data/debugger-launchers/sameboy.sh'
                if launcher.exists():
                    launcher.write_text(launcher.read_text().replace('OPT_GBC_HOME:dir=""',f'OPT_GBC_HOME:dir="{runtime}"'));launcher.chmod(0o755)
                record(entry)
            except Exception:
                if dest.exists():shutil.rmtree(dest)
                if entry['backup']:shutil.move(entry['backup'],dest)
                raise
except Exception:
    # Undo only this installer invocation's mutations on failure.
    for entry in reversed(manifest['entries']):
        dest=Path(entry['destination'])
        if dest.exists():shutil.rmtree(dest)
        if entry.get('backup'):shutil.move(entry['backup'],dest)
    if runtime.exists():shutil.rmtree(runtime)
    raise
print(json.dumps({'installed':[e['destination'] for e in manifest['entries']],'runtime':str(runtime),'rollback_manifest':str(backup/'manifest.json')},indent=2))
