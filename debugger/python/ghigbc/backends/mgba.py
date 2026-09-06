"""Experimental pinned mGBA adapter; opaque native ownership and copied ABI only."""
import ctypes as C
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import sys

from ..backend import BackendDescriptor, Button, MemoryBank, ROOT, UnsupportedFeature, VideoFrame
from ..session import Session, freeze
from .identity import build_identity

CORE = '685023e05d90d87050fb357f46f7bd2d907083f5'
PATCH_PATH = ROOT / 'backends/mgba/native/patches/0001-sm83-no-idle.patch'
PATCH = hashlib.sha256(PATCH_PATH.read_bytes()).hexdigest()
MEMORY_SIZE = 245760
STATE_FIELDS = ('abi', 'reason', 'hit_id', 'execution_boundaries', 'ticks', 'mapping_generation',
                'af', 'bc', 'de', 'hl', 'sp', 'pc', 'rom0', 'romx', 'wram', 'vram', 'cart',
                'ime', 'halted', 'stopped', 'double_speed', 'boot', 'cart_enabled', 'rtc_selected',
                'rom_size', 'cart_size', 'wram_size', 'vram_size', 'boot_size', 'dropped', 'event_count',
                'vram_blocked', 'oam_blocked', 'dma_active')
REASONS = ('slice', 'step', 'pause', 'breakpoint', 'halt-wait', 'stop-wait', 'error')


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
        if self.state['dma_active']:
            return ((0,0xff80),(0xffff,1))
        ranges = [(0xfea0, 0xe0), (0xffff, 1)]
        if self.state['vram_blocked']:ranges.append((0x8000,0x2000))
        if self.state['oam_blocked']:ranges.append((0xfe00,0xa0))
        if not self.state['cart_enabled'] or not self.state['cart_size']:
            ranges.append((0xa000, 8192))
        elif self.state['cart_size'] < 8192:
            ranges.append((0xa000 + self.state['cart_size'], 8192 - self.state['cart_size']))
        return tuple(ranges)

    @property
    def boot_ranges(self):
        return ()

    def bank_bytes(self, region, bank):
        if region == 'wram':
            start, stride, size = 65536, 4096, self.state['wram_size']
        elif region == 'vram':
            start, stride, size = 98304, 8192, self.state['vram_size']
        elif region == 'cart':
            start, stride, size = 114688, 8192, self.state['cart_size']
        else:
            raise ValueError('Not a captured mutable bank')
        if type(bank) is not int or bank < 0 or bank * stride >= size:
            raise ValueError('Bank unavailable')
        return self.memory[start + bank * stride:start + min((bank + 1) * stride, size)]

    def mutable_banks(self):
        for region, stride, size in (('wram', 4096, self.state['wram_size']),
                                    ('vram', 8192, self.state['vram_size']),
                                    ('cart', 8192, self.state['cart_size'])):
            for bank in range((size + stride - 1) // stride):
                yield MemoryBank(region, bank, self.bank_bytes(region, bank))


class Machine(Session):
    """One Session owner invokes the native core; pause writes only an atomic flag."""
    def __init__(self, rom, boot=None, library=None, experiment=False, model=None):
        model = model or 'CGB'
        if model != 'CGB':
            raise UnsupportedFeature('Experimental mGBA supports native CGB only; silicon revisions such as CGB-E are unqualified')
        if boot is not None:
            raise UnsupportedFeature('Experimental mGBA requires engine post-boot state without a BIOS')
        self.rom = Path(rom).resolve()
        self.rom_bytes = self.rom.read_bytes()
        if not 32768 <= len(self.rom_bytes) <= 0x800000 or len(self.rom_bytes) % 16384:
            raise ValueError('Invalid ROM size')
        if not self.rom_bytes[0x143] & 0x80 or self.rom_bytes[0x147] not in (0x19, 0x1a, 0x1b):
            raise UnsupportedFeature('Experimental mGBA requires a CGB MBC5 ROM without rumble')
        self.rom_hash = hashlib.sha256(self.rom_bytes).hexdigest()
        self.boot_bytes = b''
        self.boot_hash = hashlib.sha256(b'').hexdigest()
        library = Path(library or ROOT / ('build/libghigbc_mgba.dylib' if sys.platform == 'darwin' else 'build/libghigbc_mgba.so'))
        receipt_path = Path(str(library) + '.json')
        receipt_bytes = receipt_path.read_bytes()
        receipt = json.loads(receipt_bytes)
        if (receipt.get('schema') != 1 or receipt.get('backend') != 'mgba' or receipt.get('status') != 'BUILT' or receipt.get('sourceRevision') != CORE or
                receipt.get('patchSha256') != PATCH or
                receipt.get('binarySha256') != hashlib.sha256(library.read_bytes()).hexdigest()):
            raise RuntimeError('mGBA native build identity mismatch; rebuild the selected adapter')
        self.descriptor = BackendDescriptor(
            id='mgba', name='mGBA (experimental)', core=CORE,
            config='ghigbc-mgba-abi1:native-model=CGB:no-BIOS:build=' + build_identity(receipt),
            patch=PATCH, model=model, mode='CGB', ticks_per_second=8388608,
            features=frozenset({'run', 'step', 'breakpoints', 'registers', 'cpu-memory', 'physical-capture-v1', 'input', 'video'}),
            models=('CGB',), mappers=('MBC5',),
            observation_coverage='Stopped physical ROM/WRAM/VRAM/SRAM/OAM/HRAM; IO/IE unavailable; no watches',
            memory_semantics='Physical bytes projected into CPU windows; PPU/DMA access locks and IO are unknown',
            boot_policy='engine-post-boot')
        super().__init__(experiment=experiment)
        self.breakpoints = {}
        self.next_breakpoint_id = 1
        self.handle = None
        self.lib = C.CDLL(str(library))
        ptr, u32, u64, byte = C.c_void_p, C.c_uint32, C.c_uint64, C.c_uint8
        signatures = {
            'create': ([C.c_char_p, u32], ptr), 'destroy': ([ptr], None),
            'request_pause': ([ptr], None), 'prepare': ([ptr], None), 'run': ([ptr, u32], C.c_int),
            'ticks': ([ptr], u64), 'capture': ([ptr, C.POINTER(u64), u32, C.POINTER(byte), u32], C.c_int),
            'breakpoint': ([ptr, u32, u32, u32, u32, u32, u32], C.c_int), 'remove': ([ptr, u32], None),
            'key': ([ptr, u32, u32], C.c_int), 'key_mask': ([ptr], u32),
            'frame': ([ptr, C.POINTER(u32), u32], C.c_int),
            'state_size': ([ptr], u32), 'state_copy': ([ptr, C.POINTER(byte), u32], C.c_int),
        }
        for name, (arguments, result) in signatures.items():
            function = getattr(self.lib, 'gm_' + name)
            function.argtypes, function.restype = arguments, result
        self.handle = self.lib.gm_create(self.rom_bytes, len(self.rom_bytes))
        if not self.handle:
            raise RuntimeError('mGBA could not load the requested immutable CGB/MBC5 input')
        try:
            self.capture()
        except Exception:
            self.close()
            raise

    def _close(self):
        if self.handle:
            self.lib.gm_destroy(self.handle)
            self.handle = None

    def _request_pause(self):
        self.lib.gm_request_pause(self.handle)

    def _prepare(self):
        self.lib.gm_prepare(self.handle)

    def _run_slice(self, step=False):
        result = self.lib.gm_run(self.handle, int(bool(step)))
        if result < 0:
            raise RuntimeError('mGBA execution left the supported boundary; close and reopen the session')
        return result

    def ticks(self):
        with self.lock:
            self._require_open()
            return self.lib.gm_ticks(self.handle)

    def _capture(self):
        state = (C.c_uint64 * len(STATE_FIELDS))()
        memory = (C.c_uint8 * MEMORY_SIZE)()
        if self.lib.gm_capture(self.handle, state, len(state), memory, len(memory)):
            raise RuntimeError('mGBA coherent capture unavailable at this boundary')
        values = dict(zip(STATE_FIELDS, state))
        if values['abi'] != 1 or values['reason'] >= len(REASONS) or values['cart_size'] > 131072:
            raise RuntimeError('mGBA capture ABI mismatch')
        # IRQ dispatch is an execution boundary, not a retired opcode.
        values.update(mapper='MBC5', cart_nibble=False, cgb_mode=1, instructions=None)
        return Capture(freeze(values), bytes(memory), (), self.session, self.rom_hash, descriptor=self.descriptor,boot_hash=self.boot_hash)

    def breakpoint(self, region, bank, offset, kinds=1, length=1, id=None, enabled=True):
        self.descriptor.require('physical-watch-v1' if kinds & 14 else 'breakpoints')
        if region not in ('cpu', 'rom'):
            raise UnsupportedFeature('Experimental mGBA supports CPU and ROM execution breakpoints only')
        if any(type(value) is not int for value in (bank, offset, kinds, length)) or kinds != 1:
            raise ValueError('Invalid execution breakpoint')
        stride = 65536 if region == 'cpu' else 16384
        count = 1 if region == 'cpu' else len(self.rom_bytes) // stride
        if not (0 <= bank < count and 0 <= offset < stride and 0 < length <= stride - offset):
            raise ValueError('Invalid execution breakpoint range')
        with self.lock:
            self._require_open()
            id = self.next_breakpoint_id if id is None else id
            if type(id) is not int or not 0 < id <= 0xffffffff:
                raise ValueError('Invalid breakpoint ID')
            if self.lib.gm_breakpoint(self.handle, id, int(region == 'rom'), bank, offset, length, bool(enabled)):
                raise ValueError('Native breakpoint capacity exceeded')
            self.breakpoints[id] = (region, bank, offset, kinds, length, bool(enabled))
            self.next_breakpoint_id = max(self.next_breakpoint_id, id + 1)
            return id

    def remove(self, id):
        if type(id) is not int or not 0 < id <= 0xffffffff:
            raise ValueError('Invalid breakpoint ID')
        with self.lock:
            self._require_open()
            self.lib.gm_remove(self.handle, id)
            self.breakpoints.pop(id, None)

    def key(self, key, pressed):
        if (type(key) is not int and not isinstance(key, Button)) or not 0 <= key < 8:
            raise ValueError('Invalid Game Boy key')
        with self.lock:
            self._require_open()
            if self.lib.gm_key(self.handle, key, bool(pressed)):
                raise RuntimeError('Native input update failed')

    def key_mask(self):
        with self.lock:
            self._require_open()
            return self.lib.gm_key_mask(self.handle)

    def frame(self):
        with self.lock:
            self._require_open()
            pixels = (C.c_uint32 * (160 * 144))()
            if self.lib.gm_frame(self.handle, pixels, len(pixels)):
                raise RuntimeError('mGBA frame copy failed')
            return VideoFrame(160, 144, bytes(pixels))

    def _diagnostic_state(self):
        """Private test observation; not a checkpoint or restore capability."""
        with self.lock:
            self._require_open()
            size = self.lib.gm_state_size(self.handle)
            if not 0 < size <= 1024 * 1024:
                raise RuntimeError('Invalid native state size')
            payload = (C.c_uint8 * size)()
            if self.lib.gm_state_copy(self.handle, payload, size):
                raise UnsupportedFeature('Native state serialization requires FETCH; HALT_BUG is unsupported')
            return bytes(payload)
