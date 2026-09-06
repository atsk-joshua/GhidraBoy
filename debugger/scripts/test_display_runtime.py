#!/usr/bin/env python3
"""Bounded SDL window/pump/cleanup smoke. Virtual display is not physical GUI acceptance."""
import argparse,json,threading,time,sys
from pathlib import Path
root=Path(__file__).resolve().parents[1];sys.path.insert(0,str(root/'python'))
from ghigbc.native import Machine
from ghigbc.display import load_sdl,run
p=argparse.ArgumentParser();p.add_argument('--require-local-sdl',action='store_true');a=p.parse_args()
lib=load_sdl();name=str(lib._name)
if a.require_local_sdl:assert 'runtime-libs' in name,name
stopped=threading.Event();timer=threading.Timer(1.0,stopped.set)
with Machine(root/'build/teaching.gbc') as machine:
    timer.start();started=time.monotonic()
    try:run(machine,stopped)
    finally:stopped.set();timer.cancel()
print(json.dumps({'status':'PASS','sdl_library':name,'seconds':time.monotonic()-started,'scope':'SDL window creation, paused event pumping and cleanup on current display; no physical input/focus claim'}))
