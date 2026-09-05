"""Developer-only native game acceptance driver. JSON stdin, framebuffer artifacts.
No ROM/state bytes leave the local machine. This is not the student debugger UI.
"""
import json,sys,struct,zlib,binascii,ctypes as C
from pathlib import Path
from ghigbc.native import Machine
from ghigbc.profile import Profile
root=Path(__file__).resolve().parents[1];out=root/'.local/game-evidence';out.mkdir(exist_ok=True)
m=Machine(root/'.local/experiments/student.gbc');profile=Profile(m);count=0
keys={'right':0,'left':1,'up':2,'down':3,'a':4,'b':5,'select':6,'start':7}
def png(path):
 pixels=(C.c_uint32*(160*144))();m.lib.gc_copy_frame(m.handle,pixels,len(pixels))
 data=b''.join(b'\0'+b''.join(bytes(((pixels[y*160+x]>>16)&255,(pixels[y*160+x]>>8)&255,pixels[y*160+x]&255)) for x in range(160)) for y in range(144))
 def chunk(t,d):return struct.pack('>I',len(d))+t+d+struct.pack('>I',binascii.crc32(t+d)&0xffffffff)
 path.write_bytes(b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR',struct.pack('>IIBBBBB',160,144,8,2,0,0,0))+chunk(b'IDAT',zlib.compress(data))+chunk(b'IEND',b''))
try:
 for line in sys.stdin:
  cmd=json.loads(line)
  if 'restore' in cmd:m.restore(out/cmd['restore'])
  if 'checkpoint' in cmd:m.checkpoint(out/cmd['checkpoint'])
  if 'watch' in cmd:
   slot=cmd['watch'];m.breakpoint('wram',3,slot*16+4,kinds=4)
  for key in cmd.get('keys',[]):m.lib.gc_key(m.handle,keys[key],1)
  m.prepare();target=m.lib.gc_ticks(m.handle)+int(cmd.get('frames',1))*140448
  while m.lib.gc_ticks(m.handle)<target:
   if m.run_slice():break
  for key in range(8):m.lib.gc_key(m.handle,key,0)
  c=m.capture();count+=1;path=out/f'frame-{count:03}.png';png(path)
  study=profile.capture(c);units=[u for u in study['units'] if u['plausible']]
  events=[{k:dict(v) if hasattr(v,'items') else v for k,v in e.items()} for e in c.events]
  print(json.dumps({'image':str(path),'pc':hex(c.state['pc']),'romx':c.state['romx'],'reason':c.state['reason'],'units':units,'combat':study['combat'],'events':events}),flush=True)
finally:m.close()
