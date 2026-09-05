#!/usr/bin/env python3
"""Matched home-folder installation with verified staging, durable journal and safe rollback."""
import argparse
import datetime
import hashlib
import fcntl
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import zipfile

from runtime_python import check_runtime, prepare_environment

ROOT=Path(__file__).resolve().parents[1]
MANAGED={'GhidraBoy','GhiGBC','GhiBW3Static','GhiBW3Live'}


def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def hashes(folder):
    result={}
    if not folder.exists():return result
    for file in sorted(folder.rglob('*')):
        relative=file.relative_to(folder)
        if '__pycache__' in relative.parts or file.suffix in ('.pyc','.pyo'):continue
        if file.is_symlink():result[str(relative)]='link:'+os.readlink(file)
        elif file.is_file():result[str(relative)]=digest(file)
    return result


def save(path,value):
    temporary=path.with_suffix('.tmp')
    with temporary.open('w') as out:
        json.dump(value,out,indent=2);out.write('\n');out.flush();os.fsync(out.fileno())
    os.replace(temporary,path)
    descriptor=os.open(path.parent,os.O_RDONLY)
    try:os.fsync(descriptor)
    finally:os.close(descriptor)


def safe(root,relative):
    path=Path(relative)
    if path.is_absolute() or '..' in path.parts:raise ValueError('Unsafe manifest path: '+str(relative))
    result=root/path
    if not result.resolve().is_relative_to(root.resolve()):raise ValueError('Manifest path escapes package')
    return result


def verify_package(path,kind):
    data=json.loads(path.read_text());root=path.parent
    if data.get('schema')!=1 or data.get('kind')!=kind:raise ValueError('Unsupported package manifest')
    for name,expected in data['files'].items():
        file=safe(root,name)
        if not file.is_file() or file.is_symlink() or digest(file)!=expected:raise ValueError('Package hash mismatch: '+name)
    return data,root


def unpack(archive,target,expected_top):
    with zipfile.ZipFile(archive) as z:
        for member in z.infolist():
            path=Path(member.filename)
            if path.is_absolute() or '..' in path.parts or not path.parts or path.parts[0]!=expected_top or (member.external_attr>>16)&0o170000==0o120000:raise ValueError('Unsafe extension member')
        z.extractall(target)
    return target/expected_top


def failpoint(name):
    if os.environ.get('GBC_INSTALL_FAIL_AFTER')==name:os._exit(86)


def rollback(path):
    path=path.resolve();data=json.loads(path.read_text())
    if data.get('schema')!=3:
        if data.get('schema')==2:
            subprocess.run([sys.executable,str(ROOT/'scripts/install_legacy_v2.py'),'--rollback',str(path)],check=True);return
        raise ValueError('Unsupported rollback schema')
    if path.parent.parent.name!='GhiGBC-rollback':raise ValueError('Not a managed rollback journal')
    settings=path.parents[2]
    if data['state']=='rolled-back':return
    operations=[]
    for entry in data['entries']:
        dest_input=Path(entry['destination'])
        if dest_input.is_symlink():raise ValueError('Managed destination replaced by symlink')
        dest=dest_input.resolve();relative=dest.relative_to(settings)
        if len(relative.parts)!=2 or not (relative.parts[0]=='GhiGBC-runtime' or relative.parts[0]=='Extensions' and relative.parts[1] in MANAGED):raise ValueError('Rollback destination outside managed paths')
        if dest.is_symlink():raise ValueError('Managed destination replaced by symlink')
        backup=Path(entry['backup']).resolve() if entry.get('backup') else None
        if backup and backup.parent!=path.parent:raise ValueError('Invalid backup location')
        exists=dest.exists();actual=hashes(dest)
        installed=entry.get('installed');prior=entry.get('prior')
        # A crash before/after either rename is distinguishable using hashes and backup existence.
        partial=data['state']=='preparing' and relative.parts[0]=='GhiGBC-runtime' and installed=={} and exists
        if partial:data['retained_partial_runtime']=str(dest)
        untouched=partial or exists and prior is not None and actual==prior and (backup is None or not backup.exists())
        if exists and not untouched and actual!=installed:raise ValueError('User-modified installed files preserved: '+str(dest))
        if backup and backup.exists() and hashes(backup)!=prior:raise ValueError('Backup modified; refusing rollback')
        if prior is not None and not untouched and (backup is None or not backup.exists()):raise ValueError('Required rollback backup missing')
        operations.append((dest,backup,untouched))
    for dest,backup,untouched in reversed(operations):
        if untouched:continue
        if dest.exists():shutil.rmtree(dest)
        if backup and backup.exists():shutil.move(backup,dest)
    data['state']='rolled-back';save(path,data)


def running_instance(ghidra,home):
    try:rows=subprocess.check_output(['ps','-axo','pid=,command='],text=True).splitlines()
    except (OSError,subprocess.CalledProcessError):raise ValueError('Cannot inspect selected Ghidra lifecycle; close it and make ps available')
    for row in rows:
        if '/bin/java ' not in row or str(ghidra) not in row:continue
        if '-Duser.home=' in row:
            same=any('-Duser.home='+str(p) in row for p in (home,home.resolve()))
        else:same=home.resolve()==Path.home().resolve()
        if same:raise ValueError('Close the selected Ghidra instance before replacing extensions (PID '+row.split()[0]+')')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest',type=Path,default=os.environ.get('GBC_SUITE_MANIFEST',ROOT/'suite.json'))
    parser.add_argument('--study',type=Path,default=os.environ.get('GBC_STUDY_MANIFEST'))
    parser.add_argument('--remove-study',action='store_true')
    parser.add_argument('--ghidra',type=Path,default=os.environ.get('GHIDRA_INSTALL_DIR'))
    parser.add_argument('--java-home',type=Path,default=os.environ.get('JAVA_HOME'))
    parser.add_argument('--user-home',type=Path,default=Path.home())
    parser.add_argument('--python',type=Path,default=Path(sys.executable))
    parser.add_argument('--rollback',type=Path);parser.add_argument('--recover',type=Path)
    args=parser.parse_args()
    if args.rollback or args.recover:
        journal=(args.rollback or args.recover).resolve();record=json.loads(journal.read_text())
        lock_file=(journal.parents[2]/'.ghigbc-install.lock').open('a+')
        fcntl.flock(lock_file,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if record.get('ghidra_path'):running_instance(Path(record['ghidra_path']),Path(record['user_home']))
        rollback(journal);print(json.dumps({'status':'rolled-back','journal':str(args.rollback or args.recover)}));return
    if not args.ghidra or not args.java_home:parser.error('Select --ghidra and --java-home (or GHIDRA_INSTALL_DIR/JAVA_HOME)')
    manifest,package=verify_package(args.manifest,'generic')
    properties=dict(line.split('=',1) for line in (args.ghidra/'Ghidra/application.properties').read_text().splitlines() if '=' in line and not line.startswith('#'))
    if properties.get('application.version')!=manifest['ghidra']:raise ValueError('Package requires Ghidra '+manifest['ghidra'])
    for name,sha in manifest['python_wheels'].items():
        if digest(args.ghidra/'Ghidra/Debug/Debugger-rmi-trace/pypkg/dist'/name)!=sha:raise ValueError('Selected Ghidra wheel hash mismatch: '+name)
    system=platform.system();arch=platform.machine().lower();target=('macos-arm64' if system=='Darwin' and arch=='arm64' else 'linux-x86_64' if system=='Linux' and arch in ('x86_64','amd64') else 'unsupported')
    if manifest['platform']!=target:raise ValueError('Wrong native package for '+system+'/'+arch)
    python_info=check_runtime(args.python)
    java=subprocess.run([str(args.java_home/'bin/java'),'-version'],text=True,capture_output=True,check=True)
    if 'version "21.' not in java.stderr+java.stdout:raise ValueError('This candidate requires tested JDK/JRE21')
    home=args.user_home.resolve();home.mkdir(parents=True,exist_ok=True)
    settings=home/('Library/ghidra' if system=='Darwin' else '.config/ghidra')/('ghidra_'+manifest['ghidra']+'_PUBLIC')
    settings.mkdir(parents=True,exist_ok=True)
    lock_file=(settings/'.ghigbc-install.lock').open('a+');fcntl.flock(lock_file,fcntl.LOCK_EX|fcntl.LOCK_NB)
    running_instance(args.ghidra,home)
    extensions=settings/'Extensions'
    for base in (extensions,args.ghidra/'Ghidra/Extensions'):
        for file in base.rglob('*.ldefs'):
            if 'SM83:LE:16:default' in file.read_text() and (base!=extensions or file.relative_to(extensions).parts[0]!='GhidraBoy'):raise ValueError('Duplicate SM83 provider: '+str(file))
    # Recover an interrupted prior transaction before preparing another candidate.
    for journal in (settings/'GhiGBC-rollback').glob('*/manifest.json'):
        previous=json.loads(journal.read_text())
        if previous.get('schema')==3 and previous.get('state') not in ('committed','rolled-back'):rollback(journal)
    study=None;study_root=None
    if args.study:
        if args.remove_study:raise ValueError('Choose study installation or removal')
        study,study_root=verify_package(args.study,'study')
        if study['generic_manifests'].get(target)!=digest(args.manifest):raise ValueError('Study/generic composition mismatch')
    existing_study=[name for name in ('GhiBW3Static','GhiBW3Live') if (extensions/name).exists()]
    if existing_study and study is None and not args.remove_study:raise ValueError('Existing study extension: supply matched --study or explicit --remove-study')
    # Refuse to replace any tracked install modified by the user since installation.
    receipts=sorted((settings/'GhiGBC-rollback').glob('*/manifest.json'),reverse=True)
    latest=next((json.loads(p.read_text()) for p in receipts if json.loads(p.read_text()).get('state')=='committed'),None)
    if latest:
        for entry in latest['entries']:
            dest=Path(entry['destination'])
            if dest.exists() and hashes(dest)!=entry['installed']:raise ValueError('User-modified managed files preserved: '+str(dest))
    stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%f')
    journal_dir=settings/'GhiGBC-rollback'/stamp;journal_dir.mkdir(parents=True)
    journal=journal_dir/'manifest.json';runtime=settings/'GhiGBC-runtime'/(manifest['version'].removesuffix('-candidate')+'-'+stamp)
    staging=journal_dir/'staging';staging.mkdir()
    data=dict(schema=3,state='preparing',python=python_info,ghidra_path=str(args.ghidra.resolve()),user_home=str(home),ghidra=manifest['ghidra'],platform=target,manifest_sha256=digest(args.manifest),study_sha256=digest(args.study) if args.study else None,runtime=str(runtime),entries=[])
    save(journal,data)
    try:
        runtime.mkdir(parents=True)
        # Journal expected files before materialization so partial preparation can be identified.
        runtime_entry=dict(destination=str(runtime),backup=None,prior=None,installed={})
        data['entries'].append(runtime_entry);save(journal,data)
        for root,spec in [(package,manifest)]+([(study_root,study)] if study else []):
            for relative in spec['runtime_files']:
                src=safe(root,relative);dest=safe(runtime,relative);dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(src,dest)
        python=prepare_environment(args.python,runtime/'.venv12',args.ghidra.resolve()/'Ghidra/Debug/Debugger-rmi-trace/pypkg/dist')
        env=dict(os.environ,PYTHONPATH=str(runtime/'python'),PYTHONDONTWRITEBYTECODE='1')
        subprocess.run([str(python),'-c','from ghigbc.native import Machine,ROOT; from ghigbc.profile import installed_providers; m=Machine(ROOT/"build/teaching.gbc"); assert m.capture().state["abi"]==1; m.close(); assert not installed_providers(ROOT)[1]; from ghigbc.display import load_sdl; load_sdl()'],env=env,check=True,stdout=subprocess.DEVNULL)
        runtime_entry['installed']=hashes(runtime);save(journal,data);failpoint('runtime')
        extensions.mkdir(exist_ok=True)
        plans=[]
        for root,spec in [(package,manifest)]+([(study_root,study)] if study else []):
            for item in spec['extensions']:
                name=item['name']
                if name not in MANAGED:raise ValueError('Unknown extension')
                staged=unpack(safe(root,item['path']),staging,name)
                launcher=staged/'data/debugger-launchers/sameboy.sh'
                if launcher.exists():
                    if any(c in str(runtime) for c in ('"','\n','`','$')):raise ValueError('Unsupported shell metacharacter in selected install path')
                    launcher.write_text(launcher.read_text().replace('OPT_GBC_HOME:dir=""','OPT_GBC_HOME:dir="'+str(runtime)+'"'));launcher.chmod(0o755)
                plans.append((name,staged))
        if args.remove_study:plans += [(name,None) for name in existing_study]
        for name,staged in plans:
            dest=extensions/name
            if dest.is_symlink():raise ValueError('Managed extension path is a symlink')
            entry=dict(destination=str(dest),backup=str(journal_dir/name) if dest.exists() else None,prior=hashes(dest) if dest.exists() else None,installed=hashes(staged) if staged else {},staged=str(staged) if staged else None)
            data['entries'].append(entry)
        data['state']='prepared';save(journal,data);failpoint('prepare')
        data['state']='committing';save(journal,data)
        for entry in data['entries'][1:]:
            dest=Path(entry['destination']);name=dest.name
            if entry['backup']:shutil.move(dest,entry['backup'])
            failpoint('backup:'+name)
            if entry['staged']:shutil.move(entry['staged'],dest)
            failpoint('install:'+name)
        data['state']='committed';save(journal,data);failpoint('commit')
    except Exception:
        # Partial preparation has never been activated; account for its exact current tree before rollback.
        if data['state']=='preparing' and runtime.exists():runtime_entry['installed']=hashes(runtime);save(journal,data)
        rollback(journal)
        raise
    print(json.dumps(dict(status='installed',runtime=str(runtime),installed=[e['destination'] for e in data['entries']],rollback_manifest=str(journal),manifest_sha256=data['manifest_sha256']),indent=2))

if __name__=='__main__':
    try:main()
    except Exception as error:raise SystemExit(str(error))
