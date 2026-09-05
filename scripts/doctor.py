#!/usr/bin/env python3
"""Read-only local debugger diagnostics. No ROM contents or unrelated paths exported."""
import argparse, ctypes, hashlib, json, os, platform, re, shutil, socket, subprocess
import ctypes.util
from pathlib import Path
root=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser();p.add_argument('--ghidra',type=Path,default=os.environ.get('GHIDRA_INSTALL_DIR'));p.add_argument('--rom',type=Path);a=p.parse_args()
report={'host':platform.node(),'os':platform.system(),'architecture':platform.machine(),'python':platform.python_version(),'ghidra':None,'native':False,'display':bool(os.environ.get('DISPLAY') or os.environ.get('WAYLAND_DISPLAY') or platform.system()=='Darwin'),'loopback':False}
if a.ghidra:
 f=a.ghidra/'Ghidra/application.properties'
 if f.is_file():
  props=dict(line.split('=',1) for line in f.read_text().splitlines() if '=' in line and not line.startswith('#'))
  report['ghidra']=props.get('application.version');report['ghidra_revision']=props.get('application.revision.ghidra')
  report['trace_wheels']=[x.name for x in (a.ghidra/'Ghidra/Debug/Debugger-rmi-trace/pypkg/dist').glob('ghidratrace-*.whl')]
lib=root/'build'/('libghigbc.dylib' if platform.system()=='Darwin' else 'libghigbc.so')
try:ctypes.CDLL(str(lib));report['native']=True
except OSError as e:report['native_error']=str(e)
try:
 sdl_path=ctypes.util.find_library('SDL2') or ('/opt/homebrew/opt/sdl2/lib/libSDL2.dylib' if platform.system()=='Darwin' else 'libSDL2-2.0.so.0')
 sdl=ctypes.CDLL(sdl_path)
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
 report['rom']={'sha256':h,'size':len(data),'mapper':data[0x147] if len(data)>0x147 else None,'gbw3_profile':h=='e779a6b56575a2afafb7e1e99411b23d7400a8fddbda8bd52c660b7903c3b451'}
report['tools']={n:shutil.which(n) for n in ('cc','make','rgbasm','java','gradle')}
try:
 import importlib.metadata as metadata
 report['ghidratrace_client']=metadata.version('ghidratrace')
 report['protobuf']=metadata.version('protobuf')
except Exception:report['ghidratrace_client']=None
if platform.system()=='Darwin':user_extensions=Path.home()/'Library/ghidra/ghidra_12.1.2_PUBLIC/Extensions'
else:user_extensions=Path.home()/'.config/ghidra/ghidra_12.1.2_PUBLIC/Extensions'
roots=[user_extensions]
if a.ghidra:roots.append(a.ghidra/'Ghidra/Extensions')
report['sm83_definitions']=[str(f) for folder in roots for f in folder.rglob('*.ldefs') if 'SM83:LE:16:default' in f.read_text()]
java=Path(os.environ['JAVA_HOME'])/'bin/java' if os.environ.get('JAVA_HOME') else Path('/opt/homebrew/opt/openjdk@21/bin/java') if platform.system()=='Darwin' and Path('/opt/homebrew/opt/openjdk@21/bin/java').exists() else shutil.which('java')
try:
 result=subprocess.run([str(java),'-version'],capture_output=True,text=True,timeout=8)
 version=(result.stderr or result.stdout).splitlines()[0]
 major=re.search(r'version "(\d+)',version)
 report['java_version']=version;report['java_usable']=result.returncode==0 and major is not None and int(major.group(1))>=21
except Exception as error:report['java_usable']=False;report['java_error']=str(error)
report['ready_for_generic_tests']=report['native'] and report['ghidra']=='12.1.2' and report['loopback'] and report['java_usable'] and report.get('ghidratrace_client')=='12.1' and len(report['sm83_definitions'])==1
report['ready_for_desktop_validation']=report['ready_for_generic_tests'] and report['display'] and report['sdl2_available']
print(json.dumps(report,indent=2))
