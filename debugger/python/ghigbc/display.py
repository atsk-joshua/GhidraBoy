"""SDL2 window: event processing stays on the main thread even while paused."""
import ctypes as C
import ctypes.util
import sys
import os
from pathlib import Path
import time

def load_sdl():
    explicit=os.environ.get('GBC_SDL2_LIBRARY')
    if explicit:return C.CDLL(explicit)
    system=ctypes.util.find_library('SDL2') or ('/opt/homebrew/opt/sdl2/lib/libSDL2.dylib' if sys.platform=='darwin' else 'libSDL2-2.0.so.0')
    try:return C.CDLL(system)
    except OSError:
        local=Path(__file__).resolve().parents[2]/'build/runtime-libs/libSDL2-2.0.so.0'
        if sys.platform=='linux' and local.is_file():return C.CDLL(str(local))
        raise

def run(machine,quit_event,on_close=None):
    s=load_sdl();p=C.c_void_p;i=C.c_int;u=C.c_uint32
    specs={'SDL_Init':([u],i),'SDL_CreateWindow':([C.c_char_p,i,i,i,i,u],p),'SDL_CreateRenderer':([p,i,u],p),'SDL_CreateTexture':([p,u,i,i,i],p),'SDL_PollEvent':([p],i),'SDL_UpdateTexture':([p,p,p,i],i),'SDL_RenderClear':([p],i),'SDL_RenderCopy':([p,p,p,p],i),'SDL_RenderPresent':([p],None),'SDL_DestroyTexture':([p],None),'SDL_DestroyRenderer':([p],None),'SDL_DestroyWindow':([p],None),'SDL_Quit':([],None),'SDL_GetError':([],C.c_char_p)}
    for name,(args,result) in specs.items():fn=getattr(s,name);fn.argtypes=args;fn.restype=result
    if s.SDL_Init(0x20):raise RuntimeError(s.SDL_GetError().decode())
    window=s.SDL_CreateWindow(b'GBC / SameBoy - arrows, Z/X, Enter, Backspace',0x2fff0000,0x2fff0000,640,576,0x24)
    renderer=s.SDL_CreateRenderer(window,-1,2)
    if not renderer:renderer=s.SDL_CreateRenderer(window,-1,1)
    texture=s.SDL_CreateTexture(renderer,0x16362004,1,160,144) # ARGB8888 streaming
    if not texture:raise RuntimeError(s.SDL_GetError().decode())
    event=(C.c_uint8*56)();pixels=(u*(160*144))()
    # SDL scancodes; SameBoy key enum is right,left,up,down,A,B,select,start.
    keys={79:0,80:1,82:2,81:3,29:4,27:5,42:6,40:7}
    pressed_at={};release_after={};closing=False
    try:
        while not quit_event.is_set():
            while s.SDL_PollEvent(event):
                raw=bytes(event);kind=int.from_bytes(raw[:4],sys.byteorder)
                if kind==0x100 and not closing:
                    closing=True;machine.pause()
                    for key in range(8):machine.lib.gc_key(machine.handle,key,0)
                    pressed_at.clear();release_after.clear()
                    if on_close:on_close()
                    else:quit_event.set()
                elif kind==0x200 and raw[12] in (13,14):
                    for key in range(8):machine.lib.gc_key(machine.handle,key,0)
                    pressed_at.clear();release_after.clear()
                elif kind in (0x300,0x301):
                    scan=int.from_bytes(raw[16:20],sys.byteorder)
                    if scan in keys:
                        key=keys[scan]
                        if kind==0x300:
                            pressed_at[key]=time.monotonic();release_after.pop(key,None);machine.lib.gc_key(machine.handle,key,1)
                        else:release_after[key]=max(time.monotonic(),pressed_at.get(key,0)+.03)
            now=time.monotonic()
            for key,deadline in list(release_after.items()):
                if now>=deadline:machine.lib.gc_key(machine.handle,key,0);release_after.pop(key);pressed_at.pop(key,None)
            machine.lib.gc_copy_frame(machine.handle,pixels,len(pixels))
            s.SDL_UpdateTexture(texture,None,pixels,160*4);s.SDL_RenderClear(renderer);s.SDL_RenderCopy(renderer,texture,None,None);s.SDL_RenderPresent(renderer)
            time.sleep(.016)
    finally:
        for key in range(8):machine.lib.gc_key(machine.handle,key,0)
        s.SDL_DestroyTexture(texture);s.SDL_DestroyRenderer(renderer);s.SDL_DestroyWindow(window);s.SDL_Quit()
