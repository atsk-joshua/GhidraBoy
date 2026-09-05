#!/usr/bin/env python3
"""Inspect ELF class, machine, ABI exports and required libraries; does not claim execution."""
import hashlib,json,struct
from pathlib import Path
root=Path(__file__).resolve().parents[1];file=root/'build/libghigbc.so';data=file.read_bytes()
assert data[:6]==b'\x7fELF\x02\x01'
assert struct.unpack_from('<HH',data,16)==(3,62)
offset=struct.unpack_from('<Q',data,40)[0];size,count,names=struct.unpack_from('<HHH',data,58)
sections=[struct.unpack_from('<IIQQQQIIQQ',data,offset+i*size) for i in range(count)]
def content(s):return data[s[4]:s[4]+s[5]]
def string(buf,index):return buf[index:buf.index(0,index)].decode()
exports=set();needed=[];versions=[]
for s in sections:
 if s[1]==11:
  strings=content(sections[s[6]]);buf=content(s)
  for i in range(0,len(buf),s[9]):
   name,info,other,index,value,length=struct.unpack_from('<IBBHQQ',buf,i)
   if index and name:exports.add(string(strings,name))
 if s[1]==6:
  strings=content(sections[s[6]]);buf=content(s)
  for i in range(0,len(buf),16):
   tag,value=struct.unpack_from('<qQ',buf,i)
   if tag==1:needed.append(string(strings,value))
 if s[1]==0x6ffffffe:
  strings=content(sections[s[6]]);buf=content(s);cursor=0
  while cursor<len(buf):
   version,n,file_name,aux,next_record=struct.unpack_from('<HHIII',buf,cursor);a=cursor+aux
   for _ in range(n):
    h,flags,other,name,next_aux=struct.unpack_from('<IHHII',buf,a);versions.append(string(strings,name));a+=next_aux
   if not next_record:break
   cursor+=next_record
required={'gc_create','gc_create_buffers','gc_destroy','gc_run','gc_snapshot','gc_request_pause','gc_prepare_run','gc_prepare_step','gc_breakpoint','gc_remove_breakpoint','gc_state_save','gc_state_load','gc_edit_register','gc_edit_memory','gc_edit_wram','gc_copy_frame','gc_key','gc_key_mask','gc_ticks'}
assert required<=exports,required-exports
report={'format':'ELF64 little-endian shared object','architecture':'x86-64','target':'x86_64-linux-gnu.2.28','compiler':'Zig 0.14.1','sha256':hashlib.sha256(data).hexdigest(),'required_libraries':needed,'symbol_versions':sorted(set(versions)),'abi_exports_verified':sorted(required),'linux_execution_verified':False,'steam_deck_desktop_verified':False}
(root/'docs/evidence/linux-library.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
