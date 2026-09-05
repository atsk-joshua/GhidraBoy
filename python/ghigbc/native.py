"""Fixed-width ABI only; no SameBoy structure layouts cross into Python."""
import ctypes as C
import hashlib
import json
import os
import sys
from pathlib import Path
import threading
import uuid
from dataclasses import dataclass, replace
from types import MappingProxyType

ROOT = Path(__file__).resolve().parents[2]
CORE = '208ba4afabffab9edde416f2dbb8ae459e34adb8'
CONFIG = 'ghigbc-abi1-cpu-bus-v1:CGB-E:accurate-rtc:copied-stop'
PATCH = hashlib.sha256((ROOT/'native/patches/0001-cpu-bus-provenance.patch').read_bytes()).hexdigest()
PROFILE = 'e779a6b56575a2afafb7e1e99411b23d7400a8fddbda8bd52c660b7903c3b451'
REGIONS = ('cpu','rom','wram','vram','cart','boot','oam','hram','io','unknown')
REASONS = ('slice','step','pause','breakpoint','watchpoint','halt-wait','stop-wait','interrupt','error')
MEMORY_SIZE = 245760
class Address(C.Structure):
    _fields_ = [(n,C.c_uint32) for n in ('region','bank','offset')]
class Event(C.Structure):
    _fields_ = [('sequence',C.c_uint64),('target',Address),('writer',Address)] + [(n,C.c_uint32) for n in ('cpu_address','writer_pc','origin','access','value','before','after','valid','breakpoint_id')]
class State(C.Structure):
    _fields_ = [(n,C.c_uint64) for n in ('capture_id','epoch','instructions','ticks','mapping_generation','dropped')] + [(n,C.c_uint32) for n in ('abi','reason','hit_id','event_count')] + [(n,C.c_uint16) for n in ('af','bc','de','hl','sp','pc','rom0','romx','wram','vram','cart')] + [(n,C.c_uint8) for n in ('ime','halted','stopped','double_speed','boot','cart_enabled','rtc_selected','reserved')] + [(n,C.c_uint32) for n in ('rom_size','cart_size')]
def as_dict(value):
    return {n:as_dict(getattr(value,n)) if isinstance(getattr(value,n),C.Structure) else getattr(value,n) for n,_ in value._fields_}
def freeze(value):
    return MappingProxyType({key:freeze(item) for key,item in value.items()}) if isinstance(value,dict) else value
@dataclass(frozen=True)
class Capture:
    state: object
    memory: bytes
    events: tuple
    session: str
    rom_hash: str
    edit: object = None
    parent_checkpoint: object = None
    def bank_bytes(self,region,bank):
        if region=='wram': start,size,count=65536,4096,8
        elif region=='vram': start,size,count=98304,8192,2
        elif region=='cart': start,size,count=114688,8192,self.state['cart_size']//8192
        else: raise ValueError('Not a captured mutable bank')
        if not 0<=bank<count: raise ValueError('Bank unavailable')
        return self.memory[start+size*bank:start+size*(bank+1)]

class Machine:
    def __init__(self,rom,boot=None,library=None,experiment=False):
        self.rom=Path(rom).resolve();self.rom_bytes=self.rom.read_bytes()
        self.rom_hash=hashlib.sha256(self.rom_bytes).hexdigest()
        if not 32768<=len(self.rom_bytes)<=0x800000 or len(self.rom_bytes)%16384: raise ValueError('Invalid ROM size')
        self.boot=Path(boot or ROOT/'.deps/SameBoy/build/bin/BootROMs/cgb_boot.bin')
        self.boot_bytes=self.boot.read_bytes()
        if len(self.boot_bytes)!=0x900:raise ValueError('CGB-E requires a 2304-byte CGB boot image')
        self.boot_hash=hashlib.sha256(self.boot_bytes).hexdigest()
        self.session=str(uuid.uuid4());self.experiment=experiment;self.parent_checkpoint=None
        self.lock=threading.RLock();self.running=False;self.breakpoints={};self.next_breakpoint_id=1
        self.lib=C.CDLL(str(library or ROOT/('build/libghigbc.dylib' if sys.platform=='darwin' else 'build/libghigbc.so')))
        ptr=C.c_void_p;u=C.c_uint32;b=C.c_char_p
        signatures={
          'ticks':([ptr],C.c_uint64),'create':([b,b],ptr),'create_buffers':([b,u,b,u],ptr),'destroy':([ptr],None),'request_pause':([ptr],None),'prepare_run':([ptr],None),
          'prepare_step':([ptr,u],C.c_int),'run':([ptr,u,u,u],C.c_int),'snapshot':([ptr,C.POINTER(State),C.POINTER(C.c_uint8),u,C.POINTER(Event),u],C.c_int),
          'breakpoint':([ptr,u,Address,u,u,u],C.c_int),'remove_breakpoint':([ptr,u],C.c_int),
          'state_save':([ptr,b],C.c_int),'state_load':([ptr,b],C.c_int),
          'edit_register':([ptr,u,C.c_uint16],C.c_int),'edit_memory':([ptr,C.c_uint16,C.c_uint8],C.c_int),'edit_wram':([ptr,u,u,C.c_uint8],C.c_int),
          'copy_frame':([ptr,C.POINTER(u),u],C.c_int),'key':([ptr,u,u],C.c_int),'key_mask':([ptr],u)}
        for n,(args,result) in signatures.items():
            fn=getattr(self.lib,'gc_'+n);fn.argtypes=args;fn.restype=result
        self.handle=self.lib.gc_create_buffers(self.rom_bytes,len(self.rom_bytes),self.boot_bytes,len(self.boot_bytes))
        if not self.handle: raise RuntimeError('Native ROM/boot load failed or mapper unsupported')
    @property
    def profile(self):return self.rom_hash==PROFILE
    def close(self):
        with self.lock:
            if self.handle:self.lib.gc_destroy(self.handle);self.handle=None
    def __enter__(self):return self
    def __exit__(self,*args):self.close()
    def pause(self):self.lib.gc_request_pause(self.handle)
    def key_mask(self):
        with self.lock:return self.lib.gc_key_mask(self.handle)
    def prepare(self):
        with self.lock:self.lib.gc_prepare_run(self.handle)
    def run_slice(self,step=False):
        with self.lock:return self.lib.gc_run(self.handle,1 if step else 10000,32768,int(step))
    def step(self):
        with self.lock:
            self.prepare();self.run_slice(True);return self.capture()
    def capture(self):
        with self.lock:
            state=State();mem=(C.c_uint8*MEMORY_SIZE)();events=(Event*64)()
            if self.lib.gc_snapshot(self.handle,C.byref(state),mem,MEMORY_SIZE,events,64):raise RuntimeError('Snapshot ABI error')
            if state.abi!=1:raise RuntimeError('Native ABI mismatch')
            # Recursive freeze: mutable ctypes backing is never retained.
            return Capture(freeze(as_dict(state)),bytes(mem),tuple(freeze(as_dict(e)) for e in events[:state.event_count]),self.session,self.rom_hash,parent_checkpoint=self.parent_checkpoint)
    def breakpoint(self,region,bank,offset,kinds=1,length=1,id=None,enabled=True):
        with self.lock:
            bound={'cpu':65536,'rom':16384,'wram':4096,'vram':8192,'cart':8192,'boot':2304,'oam':160,'hram':127,'io':256}[region]
            banks={'cpu':1,'rom':len(self.rom_bytes)//16384,'wram':8,'vram':2,'cart':self.capture().state['cart_size']//8192,'boot':1,'oam':1,'hram':1,'io':1}[region]
            if not (0<=bank<banks and 0<=offset<bound and 0<length<=bound-offset):raise ValueError('Invalid physical breakpoint range')
            id=id or self.next_breakpoint_id
            if self.lib.gc_breakpoint(self.handle,id,Address(REGIONS.index(region),bank,offset),length,kinds,enabled):raise ValueError('Breakpoint rejected')
            self.breakpoints[id]=(region,bank,offset,kinds,length,enabled);self.next_breakpoint_id=max(self.next_breakpoint_id,id+1);return id
    def remove(self,id):
        with self.lock:self.lib.gc_remove_breakpoint(self.handle,id);self.breakpoints.pop(id,None)
    def checkpoint(self,path):
        with self.lock:
            if self.running:raise RuntimeError('Pause before saving a checkpoint')
            path=Path(path);path.mkdir(parents=True,exist_ok=False)
            if self.lib.gc_state_save(self.handle,os.fsencode(path/'state.sbs')):raise RuntimeError('Checkpoint failed')
            c=self.capture()
            meta=dict(schema=2,core=CORE,config=CONFIG,patch=PATCH,rom_hash=self.rom_hash,boot_hash=self.boot_hash,model='CGB-E',clock='accurate-emulated',input='release-on-restore',session=self.session,epoch=c.state['epoch'],ticks=c.state['ticks'],state_sha256=hashlib.sha256((path/'state.sbs').read_bytes()).hexdigest())
            meta['parent_checkpoint']=dict(self.parent_checkpoint) if self.parent_checkpoint else None
            (path/'metadata.json').write_text(json.dumps(meta,indent=2));return path
    def restore(self,path):
        with self.lock:
            if self.running:raise RuntimeError('Pause before restoring')
            path=Path(path).resolve();meta=json.loads((path/'metadata.json').read_text())
            required={'schema':2,'config':CONFIG,'patch':PATCH,'core':CORE,'rom_hash':self.rom_hash,'model':'CGB-E','clock':'accurate-emulated','boot_hash':self.boot_hash}
            if any(meta.get(k)!=v for k,v in required.items()):raise ValueError('Checkpoint metadata mismatch')
            if hashlib.sha256((path/'state.sbs').read_bytes()).hexdigest()!=meta['state_sha256']:raise ValueError('Checkpoint corrupted')
            if self.lib.gc_state_load(self.handle,os.fsencode(path/'state.sbs')):raise RuntimeError('Restore failed')
            self.parent_checkpoint=freeze(dict(path=str(path),state_sha256=meta['state_sha256'],source_session=meta.get('session'),source_epoch=meta.get('epoch'),source_ticks=meta.get('ticks')))
            for key in range(8):self.lib.gc_key(self.handle,key,0)
            return self.capture()
    def edit(self,*,register=None,address=None,value,recovery):
        with self.lock:
            if not self.experiment or self.running:raise RuntimeError('Edits require paused experiment mode')
            if (register is None)==(address is None):raise ValueError('Choose one register or WRAM address')
            if type(value) is not int:raise ValueError('Edit value must be an integer')
            if register is not None:
                register=register.strip().upper()
                if register not in ('AF','BC','DE','HL','SP','PC'):raise ValueError('Register must be AF, BC, DE, HL, SP or PC')
                index=('AF','BC','DE','HL','SP','PC').index(register)
                if not 0<=value<=65535:raise ValueError('Invalid register value')
            else:
                if type(address) is not int or not 0xc000<=address<0xfe00 or not 0<=value<=255:raise ValueError('Only WRAM edits are supported')
            before=self.capture()
            target=None
            if register is not None:
                old=before.state[register.lower()]
            else:
                canonical=address-0x2000 if address>=0xe000 else address
                bank=0 if canonical<0xd000 else before.state['wram']
                offset=canonical&0xfff
                target=dict(region='wram',bank=bank,offset=offset,cpu_address=address)
                old=before.bank_bytes('wram',bank)[offset]
            recovery=self.checkpoint(Path(recovery).resolve())
            metadata=json.loads((recovery/'metadata.json').read_text())
            record=dict(schema=1,id=str(uuid.uuid4()),origin='debugger',kind='register' if register else 'memory',
                        register=register,target=target,before=old,requested=value,recovery=str(recovery),
                        recovery_sha256=metadata['state_sha256'],session=self.session,epoch=before.state['epoch'],status='prepared')
            # Persist intent and recovery before touching emulator state.
            audit=recovery/'edit.json';audit.write_text(json.dumps(record,indent=2))
            result=self.lib.gc_edit_register(self.handle,index,value) if register else self.lib.gc_edit_wram(self.handle,bank,offset,value)
            if result:
                record['status']='failed';audit.write_text(json.dumps(record,indent=2));raise RuntimeError('Edit failed; recovery checkpoint retained')
            after=self.capture()
            record['after']=after.state[register.lower()] if register else after.bank_bytes('wram',bank)[offset]
            record['capture_id']=after.state['capture_id'];record['status']='applied'
            audit.write_text(json.dumps(record,indent=2))
            return replace(after,edit=freeze(record))
