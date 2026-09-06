#!/usr/bin/env python3
"""Read-only local debugger diagnostics. No ROM contents or unrelated paths exported."""
import argparse, ctypes, hashlib, json, os, platform, re, shutil, socket, subprocess
import ctypes.util
from pathlib import Path
from build_inputs import runtime_dependencies, verify_native_decompiler
root=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser();p.add_argument('--ghidra',type=Path,default=os.environ.get('GHIDRA_INSTALL_DIR'));p.add_argument('--rom',type=Path);p.add_argument('--user-home',type=Path,default=Path(os.environ.get('GBC_TEST_HOME',str(Path.home()))));p.add_argument('--java-home',type=Path,default=os.environ.get('JAVA_HOME'));p.add_argument('--require-ready',action='store_true');a=p.parse_args()
report={'host':platform.node(),'os':platform.system(),'architecture':platform.machine(),'python':platform.python_version(),'ghidra':None,'native':False,'display':bool(os.environ.get('DISPLAY') or os.environ.get('WAYLAND_DISPLAY') or platform.system()=='Darwin'),'loopback':False}
if a.ghidra:
 f=a.ghidra/'Ghidra/application.properties'
 if f.is_file():
  props=dict(line.split('=',1) for line in f.read_text().splitlines() if '=' in line and not line.startswith('#'))
  report['ghidra']=props.get('application.version');report['ghidra_revision']=props.get('application.revision.ghidra')
  report['trace_wheels']=[x.name for x in (a.ghidra/'Ghidra/Debug/Debugger-rmi-trace/pypkg/dist').glob('ghidratrace-*.whl')]
try:
 from runtime_probe import probe, selected_backends
 report['backends']=probe(selected_backends())
 report['native']=True
except Exception as e:report['native_error']=str(e)
try:
 import sys
 sys.path.insert(0,str(root/'python'))
 from ghigbc.display import load_sdl
 sdl=load_sdl()
 class SDLVersion(ctypes.Structure):
  _fields_=[('major',ctypes.c_uint8),('minor',ctypes.c_uint8),('patch',ctypes.c_uint8)]
 version=SDLVersion();sdl.SDL_GetVersion.argtypes=[ctypes.POINTER(SDLVersion)];sdl.SDL_GetVersion.restype=None;sdl.SDL_GetVersion(ctypes.byref(version))
 for name in ('SDL_Init','SDL_CreateWindow','SDL_PollEvent'):getattr(sdl,name)
 report['sdl2_available']=version.major==2;report['sdl2_version']=f'{version.major}.{version.minor}.{version.patch}'
except (OSError,AttributeError) as error:report['sdl2_available']=False;report['sdl2_error']=str(error)
try:
 with socket.socket() as s:s.bind(('127.0.0.1',0));report['loopback']=True
except OSError as e:report['loopback_error']=str(e)
if a.rom:
 data=a.rom.read_bytes();h=hashlib.sha256(data).hexdigest()
 from ghigbc.profile import installed_providers, ProfileSession
 providers,errors=installed_providers(root)
 report['rom']={'sha256':h,'size':len(data),'mapper':data[0x147] if len(data)>0x147 else None,'profile':ProfileSession(data,providers,errors).id}
report['tools']={n:shutil.which(n) for n in ('cc','make','rgbasm','java','gradle')}
try:
 import importlib.metadata as metadata
 report['ghidratrace_client']=metadata.version('ghidratrace')
 report['protobuf']=metadata.version('protobuf')
except Exception:report['ghidratrace_client']=None
if platform.system()=='Darwin':user_extensions=a.user_home/'Library/ghidra/ghidra_12.1.3_PUBLIC/Extensions'
else:user_extensions=a.user_home/'.config/ghidra/ghidra_12.1.3_PUBLIC/Extensions'
roots=[user_extensions]
if a.ghidra:roots.append(a.ghidra/'Ghidra/Extensions')
report['sm83_definitions']=[str(f) for folder in roots for f in folder.rglob('*.ldefs') if 'SM83:LE:16:default' in f.read_text()]
java=a.java_home/'bin/java' if a.java_home else Path('/opt/homebrew/opt/openjdk@21/bin/java') if platform.system()=='Darwin' and Path('/opt/homebrew/opt/openjdk@21/bin/java').exists() else shutil.which('java')
try:
 result=subprocess.run([str(java),'-version'],capture_output=True,text=True,timeout=8)
 version=(result.stderr or result.stdout).splitlines()[0]
 major=re.search(r'version "(\d+)',version)
 report['java_version']=version;report['java_usable']=result.returncode==0 and major is not None and int(major.group(1))==21
except Exception as error:report['java_usable']=False;report['java_error']=str(error)
try:
 lane='macos-arm64' if platform.system()=='Darwin' and platform.machine()=='arm64' else 'linux-x86_64'
 requirement=runtime_dependencies(root).get('native_decompiler')
 report['native_decompiler']=verify_native_decompiler(a.ghidra,requirement,lane)
 report['native_decompiler_usable']=report['native_decompiler']['status']=='MATCHED'
except Exception as error:report['native_decompiler_usable']=False;report['native_decompiler_error']=str(error)
report['ready_for_generic_tests']=report['native'] and report['ghidra']=='12.1.3' and report['loopback'] and report['java_usable'] and report.get('ghidratrace_client')=='12.1' and report.get('protobuf')=='6.31.0' and len(report['sm83_definitions'])==1 and report['native_decompiler_usable']
report['ready_for_desktop_validation']=report['ready_for_generic_tests'] and report['display'] and report['sdl2_available']
print(json.dumps(report,indent=2))

if a.require_ready and not report['ready_for_generic_tests']:raise SystemExit(1)
