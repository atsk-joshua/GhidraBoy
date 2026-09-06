"""Fixed-width ABI only; no SameBoy structure layouts cross into Python."""
import ctypes as C
import hashlib
import os
import sys
from pathlib import Path
from dataclasses import dataclass, replace

from ..backend import BackendDescriptor, Button, MemoryBank, VideoFrame, UnsupportedFeature, REGIONS, ROOT
from ..session import Session, REGISTERS, freeze
CORE = '208ba4afabffab9edde416f2dbb8ae459e34adb8'
CONFIG = 'ghigbc-abi1-cpu-bus-v1:CGB-E:accurate-rtc:copied-stop'
PATCH = hashlib.sha256((ROOT/'backends/sameboy/native/patches/0001-cpu-bus-provenance.patch').read_bytes()).hexdigest()
LEGACY_CGB_PATCH = 'a352600754f52b4b4d9118b1e17c00396374f0581e6f225508d8056691f27f6d'
REASONS = ('slice','step','pause','breakpoint','watchpoint','halt-wait','stop-wait','interrupt','error')
MEMORY_SIZE = 245760
MODELS = {'CGB-E': (0, 'cgb_boot.bin', 0x900), 'DMG-B': (1, 'dmg_boot.bin', 0x100)}
MAPPERS = {code:name for name,codes in [('ROM-only',(0,)),('MBC1',range(1,4)),
    ('MBC2',(5,6)),('MBC3',range(0xf,0x14)),('MBC5',range(0x19,0x1f))] for code in codes}
class Hardware(C.Structure):
    _fields_ = [(name,C.c_uint32) for name in ('api','model','cgb_mode','wram_size','vram_size','boot_size')]
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
    boot_hash: str = ''
    @property
    def cpu_bytes(self):
        return self.memory[:65536]
    @property
    def stop_reason(self):
        return REASONS[self.state['reason']]
    @property
    def unknown_cpu_ranges(self):
        ranges=[(0xfea0,0x60)]
        if self.state['rtc_selected'] or not self.state['cart_enabled'] or not self.state['cart_size']:
            ranges.append((0xa000,0x2000))
        return tuple(ranges)
    @property
    def boot_ranges(self):
        if not self.state['boot']:return ()
        return ((0,0x100),(0x200,0x900)) if self.state.get('boot_size',0x900)==0x900 else ((0,0x100),)
    def mutable_banks(self):
        for region,count in [('wram',self.state.get('wram_size',32768)//4096),('vram',self.state.get('vram_size',16384)//8192),('cart',(self.state['cart_size']+8191)//8192)]:
            for bank in range(count):
                yield MemoryBank(region,bank,self.bank_bytes(region,bank))
    def bank_bytes(self,region,bank):
        if region=='wram': start,size,count=65536,4096,self.state.get('wram_size',32768)//4096
        elif region=='vram': start,size,count=98304,8192,self.state.get('vram_size',16384)//8192
        elif region=='cart': start,size,count=114688,8192,(self.state['cart_size']+8191)//8192
        else: raise ValueError('Not a captured mutable bank')
        if not 0<=bank<count: raise ValueError('Bank unavailable')
        end=start+size*(bank+1)
        if region=='cart':end=min(end,start+self.state['cart_size'])
        return self.memory[start+size*bank:end]

class Machine(Session):
    state_filename = 'state.sbs'
    def __init__(self,rom,boot=None,library=None,experiment=False,model=None):
        model=model or 'CGB-E'
        if model not in MODELS:raise UnsupportedFeature('Unsupported hardware model: '+model)
        model_code,boot_name,boot_size=MODELS[model]
        self.rom=Path(rom).resolve();self.rom_bytes=self.rom.read_bytes()
        self.rom_hash=hashlib.sha256(self.rom_bytes).hexdigest()
        if not 32768<=len(self.rom_bytes)<=0x800000 or len(self.rom_bytes)%16384: raise ValueError('Invalid ROM size')
        self.boot=Path(boot or ROOT/'.deps/SameBoy/build/bin/BootROMs'/boot_name)
        self.boot_bytes=self.boot.read_bytes()
        if len(self.boot_bytes)!=boot_size:raise ValueError(f'{model} requires a {boot_size}-byte boot image')
        self.boot_hash=hashlib.sha256(self.boot_bytes).hexdigest()
        self.descriptor=BackendDescriptor(
            id='sameboy',name='SameBoy',core=CORE,config=CONFIG.replace('CGB-E',model),patch=PATCH,
            model=model,mode='DMG' if model=='DMG-B' else 'CGB',
            ticks_per_second=8388608,
            features=frozenset({'run','step','breakpoints','registers','cpu-memory','physical-capture-v1','physical-watch-v1',
                'checkpoint','register-edit','wram-edit','step-over','step-out','input','video'}),
            models=tuple(MODELS),mappers=('ROM-only','MBC1','MBC2','MBC3','MBC5'),
            observation_coverage='CPU-origin accesses; DMA/HDMA watches excluded',
            memory_semantics='CPU inspection on private stopped-state copy; physical RAM banks; MBC2 low-nibble cells, CPU reads drive high F',
            boot_policy='image')
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
        if not all(hasattr(self.lib,'gc_'+name) for name in ('get_hardware','create_model_buffers','snapshot_hardware')):
            raise UnsupportedFeature('Selected native library lacks coherent hardware observations; rebuild the SameBoy adapter')
        self.lib.gc_get_hardware.argtypes=[ptr,C.POINTER(Hardware)];self.lib.gc_get_hardware.restype=C.c_int
        self.lib.gc_create_model_buffers.argtypes=[b,u,b,u,u];self.lib.gc_create_model_buffers.restype=ptr
        self.lib.gc_snapshot_hardware.argtypes=signatures['snapshot'][0]+[C.POINTER(Hardware)]
        self.lib.gc_snapshot_hardware.restype=C.c_int
        self.handle=self.lib.gc_create_model_buffers(self.rom_bytes,len(self.rom_bytes),self.boot_bytes,len(self.boot_bytes),model_code)
        if not self.handle: raise RuntimeError('Native ROM/boot load failed or mapper unsupported')
        try:
            self._hardware()
        except Exception:
            self.close();raise
    def _validate_hardware(self,hardware):
        expected=MODELS[self.descriptor.model]
        if hardware.api!=1:raise RuntimeError('Hardware observation ABI mismatch')
        if hardware.model!=expected[0]:raise RuntimeError('Native hardware model differs from requested model')
        if (hardware.wram_size,hardware.vram_size,hardware.boot_size)!=(8192 if hardware.model==1 else 32768,8192 if hardware.model==1 else 16384,expected[2]):
            raise RuntimeError('Unexpected native hardware memory sizes')
        if hardware.cgb_mode not in (0,1) or hardware.model==1 and hardware.cgb_mode:
            raise RuntimeError('Invalid native hardware mode')
        return as_dict(hardware)
    def _hardware(self):
        hardware=Hardware()
        if self.lib.gc_get_hardware(self.handle,C.byref(hardware)):raise RuntimeError('Hardware observation ABI error')
        return self._validate_hardware(hardware)
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
            state=State();mem=(C.c_uint8*MEMORY_SIZE)();events=(Event*64)();hardware=Hardware()
            if self.lib.gc_snapshot_hardware(self.handle,C.byref(state),mem,MEMORY_SIZE,events,64,C.byref(hardware)):raise RuntimeError('Snapshot ABI error')
            if state.abi!=1:raise RuntimeError('Native ABI mismatch')
            if state.event_count>64 or state.cart_size>131072:raise RuntimeError('Native snapshot exceeds buffer capacity')
            # Recursive freeze: mutable ctypes backing is never retained.
            hardware=self._validate_hardware(hardware)
            mode='DMG' if hardware['model']==1 else 'CGB' if hardware['cgb_mode'] else 'DMG-on-CGB'
            self.descriptor=replace(self.descriptor,mode=mode)
            observed=dict(as_dict(state),wram_size=hardware['wram_size'],vram_size=hardware['vram_size'],boot_size=hardware['boot_size'],mapper=MAPPERS[self.rom_bytes[0x147]],cart_nibble=self.rom_bytes[0x147] in (5,6))
            return Capture(freeze(observed),bytes(mem),tuple(freeze(dict(as_dict(e),origin_name='cpu' if e.origin==1 else 'unknown',precision='attempt + final physical byte at instruction boundary')) for e in events[:state.event_count]),self.session,self.rom_hash,parent_checkpoint=self.parent_checkpoint,descriptor=self.descriptor,boot_hash=self.boot_hash)
    def breakpoint(self,region,bank,offset,kinds=1,length=1,id=None,enabled=True):
        self.descriptor.require('physical-watch-v1' if kinds&14 else 'breakpoints')
        with self.lock:
            self._require_open()
            if region not in REGIONS[:-1] or any(type(v) is not int for v in (bank,offset,kinds,length)):
                raise ValueError('Invalid physical breakpoint range')
            state=self.capture().state
            stride={'cpu':65536,'rom':16384,'wram':4096,'vram':8192,'cart':8192,'boot':state['boot_size'],'oam':160,'hram':127,'io':256}[region]
            size={'rom':len(self.rom_bytes),'wram':state['wram_size'],'vram':state['vram_size'],'cart':state['cart_size']}.get(region,stride)
            bound=min(stride,size-bank*stride)
            if not (0<=bank<=0xffffffff and 0<=offset<bound and 0<length<=bound-offset):raise ValueError('Invalid physical breakpoint range')
            if kinds<=0 or kinds&~15 or kinds&8 and not kinds&4:raise ValueError('Invalid breakpoint kinds')
            if region=='boot' and offset<0x200 and offset+length>0x100:raise ValueError('Boot ROM hole is unavailable')
            if region=='io' and offset!=255 and (offset>=128 or offset+length>128):raise ValueError('IO range includes another physical region')
            id=self.next_breakpoint_id if id is None else id
            if type(id) is not int or not 0<id<=0xffffffff:raise ValueError('Invalid breakpoint ID')
            if self.lib.gc_breakpoint(self.handle,id,Address(REGIONS.index(region),bank,offset),length,kinds,enabled):raise ValueError('Breakpoint rejected')
            self.breakpoints[id]=(region,bank,offset,kinds,length,enabled);self.next_breakpoint_id=max(self.next_breakpoint_id,id+1);return id
    def remove(self,id):
        with self.lock:
            self._require_open()
            self.lib.gc_remove_breakpoint(self.handle,id);self.breakpoints.pop(id,None)
    def _checkpoint_identity(self):
        # Continue reading/writing the existing SameBoy envelope. Generic sessions
        # add identity fields, which historical schema-2 readers safely ignore.
        if self.descriptor.model=='CGB-E':return dict(schema=2,core=CORE,config=CONFIG,patch=PATCH,model='CGB-E',clock='accurate-emulated')
        return dict(schema=3,backend='sameboy',core=CORE,config=self.descriptor.config,patch=PATCH,model=self.descriptor.model,clock='accurate-emulated')
    def _checkpoint_identity_matches(self, metadata):
        expected=self._identity()
        # Only this proven CGB schema-2 predecessor lacks the appended paused-
        # fetch marker. The native loader explicitly defaults that marker to 0.
        if expected['schema']==2 and metadata.get('schema')==2 and metadata.get('model')=='CGB-E' and metadata.get('patch')==LEGACY_CGB_PATCH:
            expected['patch']=LEGACY_CGB_PATCH
        return all(metadata.get(key)==value for key,value in expected.items())
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
