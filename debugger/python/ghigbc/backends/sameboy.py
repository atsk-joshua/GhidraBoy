"""Fixed-width ABI only; no SameBoy structure layouts cross into Python."""
import ctypes as C
import hashlib
import os
import sys
from pathlib import Path
from dataclasses import dataclass

from ..backend import BackendDescriptor, Button, MemoryBank, VideoFrame, UnsupportedFeature, REGIONS, ROOT
from ..session import Session, REGISTERS, freeze
CORE = '208ba4afabffab9edde416f2dbb8ae459e34adb8'
CONFIG = 'ghigbc-abi1-cpu-bus-v1:CGB-E:accurate-rtc:copied-stop'
PATCH = hashlib.sha256((ROOT/'backends/sameboy/native/patches/0001-cpu-bus-provenance.patch').read_bytes()).hexdigest()
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
@dataclass(frozen=True)
class Capture:
    state: object
    memory: bytes
    events: tuple
    session: str
    rom_hash: str
    edit: object = None
    parent_checkpoint: object = None
    descriptor: object = None
    @property
    def cpu_bytes(self):
        return self.memory[:65536]
    @property
    def stop_reason(self):
        return REASONS[self.state['reason']]
    @property
    def unknown_cpu_ranges(self):
        ranges=[(0xfea0,0x60)]
        if self.state['rtc_selected'] or not self.state['cart_enabled']:
            ranges.append((0xa000,0x2000))
        return tuple(ranges)
    def mutable_banks(self):
        for region,count in [('wram',8),('vram',2),('cart',self.state['cart_size']//8192)]:
            for bank in range(count):
                yield MemoryBank(region,bank,self.bank_bytes(region,bank))
    def bank_bytes(self,region,bank):
        if region=='wram': start,size,count=65536,4096,8
        elif region=='vram': start,size,count=98304,8192,2
        elif region=='cart': start,size,count=114688,8192,self.state['cart_size']//8192
        else: raise ValueError('Not a captured mutable bank')
        if not 0<=bank<count: raise ValueError('Bank unavailable')
        return self.memory[start+size*bank:start+size*(bank+1)]

class Machine(Session):
    state_filename = 'state.sbs'
    def __init__(self,rom,boot=None,library=None,experiment=False,model=None):
        if model not in (None,'CGB-E'):
            raise UnsupportedFeature('SameBoy adapter currently supports model CGB-E only')
        self.rom=Path(rom).resolve();self.rom_bytes=self.rom.read_bytes()
        self.rom_hash=hashlib.sha256(self.rom_bytes).hexdigest()
        if not 32768<=len(self.rom_bytes)<=0x800000 or len(self.rom_bytes)%16384: raise ValueError('Invalid ROM size')
        self.boot=Path(boot or ROOT/'.deps/SameBoy/build/bin/BootROMs/cgb_boot.bin')
        self.boot_bytes=self.boot.read_bytes()
        if len(self.boot_bytes)!=0x900:raise ValueError('CGB-E requires a 2304-byte CGB boot image')
        self.boot_hash=hashlib.sha256(self.boot_bytes).hexdigest()
        self.descriptor=BackendDescriptor(
            id='sameboy',name='SameBoy',core=CORE,config=CONFIG,patch=PATCH,
            model='CGB-E',mode='CGB' if self.rom_bytes[0x143]&0x80 else 'DMG-on-CGB',
            ticks_per_second=8388608,
            features=frozenset({'run','step','breakpoints','registers','cpu-memory','physical-capture-v1','physical-watch-v1',
                'checkpoint','register-edit','wram-edit','step-over','step-out','input','video'}),
            models=('CGB-E',),mappers=('ROM-only','MBC1','MBC3','MBC5'),
            observation_coverage='CPU-origin accesses; DMA/HDMA watches excluded',
            memory_semantics='CPU safe inspection; raw physical RAM banks')
        super().__init__(experiment=experiment)
        self.breakpoints={};self.next_breakpoint_id=1
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
    def _close(self):
        if self.handle:self.lib.gc_destroy(self.handle);self.handle=None
    def _request_pause(self):
        self.lib.gc_request_pause(self.handle)
    def ticks(self):
        with self.lock:
            self._require_open()
            return self.lib.gc_ticks(self.handle)
    def _prepare_step(self,mode):
        if self.lib.gc_prepare_step(self.handle,mode):
            raise RuntimeError('No observed ordinary call frame; Step Out unavailable after restore')
    def key(self,key,pressed):
        self.descriptor.require('input')
        if (type(key) is not int and not isinstance(key,Button)) or not 0<=key<8:raise ValueError('Invalid Game Boy key')
        with self.lock:
            self._require_open()
            if self.lib.gc_key(self.handle,key,int(bool(pressed))):raise RuntimeError('Input update failed')
    def frame(self):
        self.descriptor.require('video')
        with self.lock:
            self._require_open()
            pixels=(C.c_uint32*(160*144))()
            if self.lib.gc_copy_frame(self.handle,pixels,len(pixels)):raise RuntimeError('Frame copy failed')
            return VideoFrame(160,144,bytes(pixels))
    def key_mask(self):
        with self.lock:
            self._require_open()
            return self.lib.gc_key_mask(self.handle)
    def _prepare(self):
        self.lib.gc_prepare_run(self.handle)
    def _run_slice(self,step=False):
        return self.lib.gc_run(self.handle,1 if step else 10000,32768,int(step))
    def _capture(self):
        with self.lock:
            self._require_open()
            state=State();mem=(C.c_uint8*MEMORY_SIZE)();events=(Event*64)()
            if self.lib.gc_snapshot(self.handle,C.byref(state),mem,MEMORY_SIZE,events,64):raise RuntimeError('Snapshot ABI error')
            if state.abi!=1:raise RuntimeError('Native ABI mismatch')
            # Recursive freeze: mutable ctypes backing is never retained.
            return Capture(freeze(as_dict(state)),bytes(mem),tuple(freeze(dict(as_dict(e),origin_name='cpu' if e.origin==1 else 'unknown',precision='attempt + final physical byte at instruction boundary')) for e in events[:state.event_count]),self.session,self.rom_hash,parent_checkpoint=self.parent_checkpoint,descriptor=self.descriptor)
    def breakpoint(self,region,bank,offset,kinds=1,length=1,id=None,enabled=True):
        self.descriptor.require('physical-watch-v1' if kinds&14 else 'breakpoints')
        with self.lock:
            bound={'cpu':65536,'rom':16384,'wram':4096,'vram':8192,'cart':8192,'boot':2304,'oam':160,'hram':127,'io':256}[region]
            banks={'cpu':1,'rom':len(self.rom_bytes)//16384,'wram':8,'vram':2,'cart':self.capture().state['cart_size']//8192,'boot':1,'oam':1,'hram':1,'io':1}[region]
            if not (0<=bank<banks and 0<=offset<bound and 0<length<=bound-offset):raise ValueError('Invalid physical breakpoint range')
            id=id or self.next_breakpoint_id
            if self.lib.gc_breakpoint(self.handle,id,Address(REGIONS.index(region),bank,offset),length,kinds,enabled):raise ValueError('Breakpoint rejected')
            self.breakpoints[id]=(region,bank,offset,kinds,length,enabled);self.next_breakpoint_id=max(self.next_breakpoint_id,id+1);return id
    def remove(self,id):
        with self.lock:
            self._require_open()
            self.lib.gc_remove_breakpoint(self.handle,id);self.breakpoints.pop(id,None)
    def _checkpoint_identity(self):
        # Continue reading/writing the existing SameBoy envelope. Generic sessions
        # add identity fields, which historical schema-2 readers safely ignore.
        return dict(schema=2,core=CORE,config=CONFIG,patch=PATCH,model='CGB-E',clock='accurate-emulated')
    def _save_state(self,path):
        if self.lib.gc_state_save(self.handle,os.fsencode(path)):
            raise RuntimeError('Checkpoint failed')
    def _load_state(self,path):
        if self.lib.gc_state_load(self.handle,os.fsencode(path)):
            raise RuntimeError('Restore failed')
    def _write_register(self,register,value):
        if self.lib.gc_edit_register(self.handle,REGISTERS.index(register),value):
            raise RuntimeError('Native register edit failed')
    def _write_wram(self,bank,offset,value):
        if self.lib.gc_edit_wram(self.handle,bank,offset,value):
            raise RuntimeError('Native WRAM edit failed')
