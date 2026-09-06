"""SDL2 window: event processing stays on the main thread even while paused."""
import ctypes as C
import ctypes.util
import sys
import os
from pathlib import Path
import time
from .backend import Button

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
    machine.descriptor.require('video','input')
    initial=machine.frame()
    if s.SDL_Init(0x20):raise RuntimeError(s.SDL_GetError().decode())
    window=renderer=texture=None
    event=(C.c_uint8*56)()
    # SDL scancodes map to the backend contract: right,left,up,down,A,B,select,start.
    keys={79:Button.RIGHT,80:Button.LEFT,82:Button.UP,81:Button.DOWN,
          29:Button.A,27:Button.B,42:Button.SELECT,40:Button.START}
    pressed_at={};release_after={};closing=False
    try:
        title=('GBC / '+machine.descriptor.name+' - arrows, Z/X, Enter, Backspace').encode()
        window=s.SDL_CreateWindow(title,0x2fff0000,0x2fff0000,initial.width*4,initial.height*4,0x24)
        if not window:raise RuntimeError(s.SDL_GetError().decode())
        renderer=s.SDL_CreateRenderer(window,-1,2)
        if not renderer:renderer=s.SDL_CreateRenderer(window,-1,1)
        if not renderer:raise RuntimeError(s.SDL_GetError().decode())
        dimensions=None
        while not quit_event.is_set():
            while s.SDL_PollEvent(event):
                raw=bytes(event);kind=int.from_bytes(raw[:4],sys.byteorder)
                if kind==0x100 and not closing:
                    closing=True;machine.pause()
                    for key in range(8):machine.key(key,False)
                    pressed_at.clear();release_after.clear()
                    if on_close:on_close()
                    else:quit_event.set()
                elif kind==0x200 and raw[12] in (13,14):
                    for key in range(8):machine.key(key,False)
                    pressed_at.clear();release_after.clear()
                elif kind in (0x300,0x301):
                    scan=int.from_bytes(raw[16:20],sys.byteorder)
                    if scan in keys:
                        key=keys[scan]
                        if kind==0x300:
                            pressed_at[key]=time.monotonic();release_after.pop(key,None);machine.key(key,True)
                        else:release_after[key]=max(time.monotonic(),pressed_at.get(key,0)+.03)
            now=time.monotonic()
            for key,deadline in list(release_after.items()):
                if now>=deadline:machine.key(key,False);release_after.pop(key);pressed_at.pop(key,None)
            frame=machine.frame()
            if dimensions!=(frame.width,frame.height):
                if texture:s.SDL_DestroyTexture(texture)
                texture=s.SDL_CreateTexture(renderer,0x16362004,1,frame.width,frame.height)
                if not texture:raise RuntimeError(s.SDL_GetError().decode())
                dimensions=(frame.width,frame.height)
            pixels=(C.c_uint8*len(frame.data)).from_buffer_copy(frame.data)
            s.SDL_UpdateTexture(texture,None,pixels,frame.width*4);s.SDL_RenderClear(renderer);s.SDL_RenderCopy(renderer,texture,None,None);s.SDL_RenderPresent(renderer)
            time.sleep(.016)
    finally:
        try:
            for key in range(8):machine.key(key,False)
        finally:
            if texture:s.SDL_DestroyTexture(texture)
            if renderer:s.SDL_DestroyRenderer(renderer)
            if window:s.SDL_DestroyWindow(window)
            s.SDL_Quit()
