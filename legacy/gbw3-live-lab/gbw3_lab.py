#!/usr/bin/env python3
"""Game Boy Wars 3 live learning lab, for the ROM embedded in the reviewed GZF.

All emulator calls run on the main thread. Inspection uses public PyBoy APIs.
`step` means one emulated frame; hook events capture instruction-entry state.
"""
from __future__ import annotations

import argparse
from collections import deque
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import io
import json
from pathlib import Path
import re
import shlex
import sys
import time
import zipfile
from importlib.metadata import version

from gbw3_core import SHA256, inspect_rom, verify, Harness

PYBOY_VERSION = '2.7.0'
SCHEMA = 'gbw3-live-lab-v1'
FIELDS = {0: 'packed_type_and_side', 1: 'map_x', 2: 'map_y', 3: 'flags_partial',
          4: 'hp', 5: 'unknown_05', 6: 'unknown_06', 7: 'fuel',
          8: 'ammo_primary', 9: 'ammo_secondary', 10: 'experience_low',
          11: 'experience_high', 12: 'unknown_0c', 13: 'unknown_0d',
          14: 'unknown_0e', 15: 'unknown_0f'}
COMBAT = {'attacker_slot': 0xdbc8, 'defender_slot': 0xdbc9,
          'attacker_original_hp': 0xdbcb, 'defender_original_hp': 0xdbe0,
          'attacker_result_hp': 0xdbcc, 'defender_result_hp': 0xdbe1,
          'attacker_initiative': 0xdbcf, 'defender_initiative': 0xdbe4,
          'attacker_working_hp': 0xdbd3, 'defender_working_hp': 0xdbe8,
          'attacker_attack': 0xdbd4, 'defender_attack': 0xdbe9,
          'attacker_defense': 0xdbd5, 'defender_defense': 0xdbea,
          'attacker_terrain': 0xdbd6, 'defender_terrain': 0xdbeb,
          'attacker_rank_bonus': 0xdbd7, 'defender_rank_bonus': 0xdbec,
          'attacker_flank': 0xdbd8, 'defender_flank': 0xdbed,
          'attacker_support': 0xdbd9, 'defender_support': 0xdbee,
          'distance': 0xdbf6}
# Only confirmed instruction boundaries. No user-supplied arbitrary hooks.
POINTS = {'attack': (12, 0x43cf), 'order': (12, 0x4b0a),
          'attacker_first': (12, 0x4b18), 'defender_first': (12, 0x4b35),
          'simultaneous': (12, 0x4b52), 'commit': (12, 0x4b67),
          'write_byte': (18, 0x40b5), 'write_byte_done': (18, 0x40b6),
          'write_word': (18, 0x40d0), 'write_word_done': (18, 0x40d3),
          'initiative': (12, 0x484a)}
DEFAULT_TRACE = set(POINTS) - {'initiative'}
SYMBOLS = dict(POINTS, unit_address=(18, 0x4029), template_byte=(18, 0x4037),
               template_word=(18, 0x4043), unit_writer=(18, 0x40a1),
               unit_templates=(18, 0x4aad), weapon_templates=(18, 0x5298),
               defender_remaining_hp=(12, 0x4a26), attacker_remaining_hp=(12, 0x4a98),
               far_call=(0, 0x3b06))


def integer(s):
    """Counts/slots are decimal unless prefixed with 0x."""
    return int(s, 16) if str(s).lower().startswith('0x') else int(s)


def bounded(s, lo, hi, what='value'):
    n = integer(s)
    if not lo <= n <= hi:
        raise ValueError(f'{what} must be {lo}..{hi}')
    return n


def check_rom(path):
    data = Path(path).read_bytes()
    actual = hashlib.sha256(data).hexdigest()
    if actual != SHA256:
        raise ValueError(f'Wrong ROM for this lab. Expected SHA256 {SHA256}; got {actual}. '
                         'Use the ROM imported into his Ghidra project, or ExportGBW3ROM.java.')
    return data


def json_write(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')


@dataclass(frozen=True)
class Address:
    space: str
    bank: int | None
    offset: int

    @classmethod
    def parse(cls, text):
        if text in SYMBOLS:
            bank, offset = SYMBOLS[text]
            return cls('rom', bank, offset)
        m = re.fullmatch(r'(rom|wram|vram|xram)(\d+)::(?:0x)?([0-9a-fA-F]+)', text)
        if m:
            space, bank, off = m.groups()
            result = cls(space, int(bank), int(off, 16))
        else:
            result = cls('cpu', None, int(text, 16))
        result.validate(1)
        return result

    def validate(self, count):
        if not 1 <= count <= 65536:
            raise ValueError('Read length must be 1..65536')
        if self.space == 'cpu':
            low, end = 0, 0x10000
        else:
            maxima = {'rom': 63, 'wram': 7, 'vram': 1, 'xram': 15}
            if self.space not in maxima or not 0 <= self.bank <= maxima[self.space]:
                raise ValueError('Bank out of range')
            low, end = {'rom': ((0, 0x4000) if self.bank == 0 else (0x4000, 0x8000)),
                        'wram': ((0xc000, 0xd000) if self.bank == 0 else (0xd000, 0xe000)),
                        'vram': (0x8000, 0xa000), 'xram': (0xa000, 0xc000)}[self.space]
        if not low <= self.offset < end or self.offset + count > end:
            raise ValueError('Read crosses this memory region; split it at the bank boundary')

    def __str__(self):
        return (f'{self.space}{self.bank}::' if self.space != 'cpu' else '') + f'{self.offset:04x}'

    def description(self):
        value = {'address': str(self), 'cpu_address_hex': f'{self.offset:04x}',
                 'bank_decimal': self.bank}
        if self.space == 'rom':
            value['file_offset_hex'] = f'{self.bank * 0x4000 + (self.offset & 0x3fff):06x}'
            value['ghidra'] = f'{self.offset:04x}' if self.bank == 0 else str(self)
            value['emulator_hex_bank_notation'] = f'{self.bank:02X}:{self.offset:04X}'
        elif self.space == 'xram':
            value['note'] = 'Physical SRAM bank; his Ghidra project has one unbanked xram block.'
        return value


def decode_unit(raw, slot, tables):
    b = bytes(raw)
    index = b[0] >> 1
    template = tables['units'][index] if index < len(tables['units']) else None
    return {'slot': slot, 'address': f'wram3::{0xd000 + 16 * slot:04x}',
            'active': b[0] != 0, 'template_index': index, 'side': b[0] & 1,
            'name': template['name'] if template else '<unknown type>',
            'map_x': b[1], 'map_y': b[2], 'flags_partial': b[3], 'hp': b[4],
            'fuel': b[7], 'ammo_primary': b[8], 'ammo_secondary': b[9],
            'experience': int.from_bytes(b[10:12], 'little'), 'raw_hex': b.hex(),
            'plausible': b[0] != 0 and template is not None and 0 < b[4] <= 10}


def compare_snapshots(before, after):
    for value in (before, after):
        if value.get('schema') != SCHEMA or value.get('rom_sha256') != SHA256:
            raise ValueError('Snapshots must use this lab schema and ROM fingerprint')
    units, raw_changes = [], []
    for bank in range(8):
        a, b = (bytes.fromhex(s['wram_hex'][str(bank)]) for s in (before, after))
        if len(a) != 4096 or len(b) != 4096:
            raise ValueError('Snapshot WRAM bank must contain exactly 4096 bytes')
        base = 0xc000 if bank == 0 else 0xd000
        for i, (x, y) in enumerate(zip(a, b)):
            if x != y:
                raw_changes.append({'address': f'wram{bank}::{base+i:04x}', 'before': x, 'after': y})
                if bank == 3 and i < 1600:
                    units.append({'slot': i // 16, 'field': FIELDS[i % 16],
                                  'address': f'wram3::{base+i:04x}', 'before': x, 'after': y})
    return {'before_frame': before['frame'], 'after_frame': after['frame'],
            'changed_bytes': len(raw_changes), 'unit_changes': units, 'memory_changes': raw_changes}


class Lab:
    def __init__(self, rom, window='null', ram=None, pyboy=None):
        if hashlib.sha256(rom).hexdigest() != SHA256:
            raise ValueError('Lab requires the reviewed student ROM')
        self.rom = rom
        self.tables = inspect_rom(rom)
        self.owns_emulator = pyboy is None
        if version('pyboy') != PYBOY_VERSION:
            raise ValueError(f'Use pyboy=={PYBOY_VERSION}; this lab is tested against that API')
        if pyboy is None:
            from pyboy import PyBoy
            kwargs = {}
            if ram:
                data = Path(ram).read_bytes()
                if len(data) != 131072:
                    raise ValueError('--ram expects a raw 128 KiB cartridge-RAM file, not a savestate')
                kwargs['ram_file'] = io.BytesIO(data)
            pyboy = PyBoy(io.BytesIO(rom), window=window, sound_emulated=False, **kwargs)
        self.p = pyboy
        self.p.set_emulation_speed(0)
        self.window = window
        self.frame = 0
        self.events = deque(maxlen=10000)
        self.sequence = 0
        self.dropped = 0
        self.hooks = set()
        self.trace_names = set()
        self.until_target = None
        self.until_hit = None
        self.pending = {}
        self.watch = None
        self.scan = None
        self.alive = True

    def read(self, address, count=1):
        a = Address.parse(address) if isinstance(address, str) else address
        a.validate(count)
        if a.space == 'rom':
            # Immutable ROM bytes: hooks patch the emulator's execution copy.
            off = a.bank * 16384 + (a.offset & 0x3fff)
            return self.rom[off:off + count]
        # PyBoy 2.7.0 bank slices reject a stop exactly at the bank boundary.
        # Read all but the final byte as a slice, then the final byte separately.
        def key(x):
            return x if a.space == 'cpu' else (a.bank, x)
        values = self.p.memory[key(slice(a.offset, a.offset + count - 1))] if count > 1 else []
        return bytes(values + [self.p.memory[key(a.offset + count - 1)]])

    def regs(self, hook=None):
        r = {name: getattr(self.p.register_file, name) for name in ('A', 'F', 'B', 'C', 'D', 'E', 'HL', 'SP', 'PC')}
        r['wram_bank'] = (self.p.memory[0xff70] & 7) or 1
        r['rom_bank_shadow'] = self.p.memory[0xff80]
        r['wram_bank_shadow'] = self.p.memory[0xff82]
        r['flags'] = {name: bool(r['F'] & bit) for name, bit in [('Z', 128), ('N', 64), ('H', 32), ('C', 16)]}
        r['pc_ghidra_hint'] = f"rom{r['rom_bank_shadow']}::{r['PC']:04x}" if 0x4000 <= r['PC'] < 0x8000 else f"{r['PC']:04x}"
        if hook:
            bank, addr = POINTS[hook]
            r['executed_hook'] = str(Address('rom', bank, addr))
        return r

    def units(self, all_slots=False):
        data = self.read('wram3::d000', 1600)
        rows = [decode_unit(data[i*16:i*16+16], i, self.tables) for i in range(100)]
        return rows if all_slots else [x for x in rows if x['active']]

    def combat(self):
        return {name: self.read(Address('wram', 4, addr))[0] for name, addr in COMBAT.items()}

    def snapshot(self):
        return {'schema': SCHEMA, 'rom_sha256': SHA256, 'frame': self.frame,
                'registers': self.regs(), 'units': self.units(True), 'combat': self.combat(),
                'wram_hex': {str(bank): self.read(Address('wram', bank, 0xc000 if bank == 0 else 0xd000), 4096).hex()
                             for bank in range(8)}}

    def event(self, kind, **data):
        self.sequence += 1
        if len(self.events) == self.events.maxlen:
            self.dropped += 1
        row = {'sequence': self.sequence, 'frame': self.frame, 'kind': kind, **data}
        self.events.append(row)
        return row

    def on_hook(self, name):
        regs = self.regs(name)
        # Instruction hook fires before the instruction executes.
        if name == self.until_target and self.until_hit is None:
            self.until_hit = self.event('until_hit', name=name, registers=regs, combat=self.combat())
        if name not in self.trace_names:
            return
        if name in ('write_byte', 'write_word'):
            count = 1 if name == 'write_byte' else 2
            ptr = regs['HL']
            if regs['wram_bank'] == 3 and 0xd000 <= ptr and ptr + count <= 0xd640:
                self.pending[name] = {'address': f'wram3::{ptr:04x}', 'slot': (ptr - 0xd000)//16,
                                      'field': FIELDS[(ptr - 0xd000)%16],
                                      'before': list(self.read(Address('wram', 3, ptr), count)),
                                      'proposed': [regs['B']] if count == 1 else [regs['E'], regs['D']],
                                      'registers_before': regs}
                # At the byte store, PUSH HL/PUSH AF are still on the stack.
                # The word writer also has PUSH BC, so its entry SP is +6.
                entry_sp = regs['SP'] + (4 if count == 1 else 6)
                if entry_sp + 6 <= 0x10000:
                    stack = self.read(Address('cpu', None, entry_sp), 6)
                    ret = int.from_bytes(stack[:2], 'little')
                    origin = {'immediate_return_cpu_hex': f'{ret:04x}'}
                    if ret == 0x3b2f:
                        bank = stack[3]
                        resume = int.from_bytes(stack[4:6], 'little')
                        call = resume - 4
                        if bank < 64 and 0x4000 <= call < 0x7ffd:
                            off = bank*16384 + call-0x4000
                            target = 0x40a1 if count == 1 else 0x40bd
                            expected = bytes([0xef,18,target & 255,target >> 8])
                            if self.rom[off:off+4] == expected:
                                origin['verified_far_call_site'] = f'rom{bank}::{call:04x}'
                    self.pending[name]['caller'] = origin
            return
        if name in ('write_byte_done', 'write_word_done'):
            previous = self.pending.pop(name.removesuffix('_done'), None)
            if previous:
                after = list(self.read(previous['address'], len(previous['before'])))
                self.event('unit_write', **previous, after=after,
                           confirmed=after == previous['proposed'], registers_after=regs)
            return
        self.event('execute', name=name, registers=regs, combat=self.combat())

    def sync_hooks(self):
        wanted = self.trace_names | ({self.until_target} if self.until_target else set())
        for name in sorted(self.hooks - wanted):
            self.p.hook_deregister(*POINTS[name])
            self.hooks.remove(name)
        for name in sorted(wanted - self.hooks):
            self.p.hook_register(*POINTS[name], self.on_hook, name)
            self.hooks.add(name)

    def trace(self, enabled=True):
        self.trace_names = set(DEFAULT_TRACE) if enabled else set()
        self.pending.clear()
        self.sync_hooks()

    @contextmanager
    def suspended_hooks(self):
        for name in list(self.hooks):
            self.p.hook_deregister(*POINTS[name])
        self.hooks.clear()
        self.pending.clear()
        try:
            yield
        finally:
            self.sync_hooks()

    def advance(self, frames=1, realtime=False, until=None):
        if until is not None and until not in POINTS:
            raise ValueError('Known execution points: ' + ', '.join(POINTS))
        self.until_target, self.until_hit = until, None
        self.sync_hooks()
        started = self.frame
        interrupted = False
        try:
            while self.alive and self.frame - started < frames:
                begin = time.monotonic()
                old_frame_count = self.p.frame_count
                self.frame += 1
                self.alive = bool(self.p.tick(1, True, False))
                if self.p.frame_count == old_frame_count:
                    self.frame -= 1
                if self.watch:
                    a, count, previous = self.watch
                    now = self.read(a, count)
                    for i, (x, y) in enumerate(zip(previous, now)):
                        if x != y:
                            self.event('frame_change', address=str(Address(a.space, a.bank, a.offset+i)),
                                       before=x, after=y, note='Sampled at frame end; writer PC is unknown.')
                    self.watch = (a, count, now)
                if self.until_hit:
                    break
                if realtime:
                    time.sleep(max(0, 1/60 - (time.monotonic()-begin)))
        except KeyboardInterrupt:
            interrupted = True
        finally:
            self.until_target = None
            self.sync_hooks()
        return {'frames_run': self.frame-started, 'frame': self.frame, 'interrupted': interrupted,
                'hit': self.until_hit, 'pause_granularity': 'frame_end'}

    def save_state(self, path):
        meta = {'schema': SCHEMA, 'rom_sha256': SHA256, 'pyboy': PYBOY_VERSION, 'frame': self.frame}
        data = io.BytesIO()
        with self.suspended_hooks():
            self.p.save_state(data)
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        # Exclusive create keeps experiments from replacing a useful checkpoint.
        with zipfile.ZipFile(path, 'x', zipfile.ZIP_DEFLATED) as z:
            z.writestr('metadata.json', json.dumps(meta))
            z.writestr('state.bin', data.getvalue())

    def load_state(self, path):
        with zipfile.ZipFile(path) as z:
            if z.getinfo('state.bin').file_size > 4*1024*1024 or z.getinfo('metadata.json').file_size > 16384:
                raise ValueError('Invalid lab state size')
            meta = json.loads(z.read('metadata.json'))
            data = z.read('state.bin')
        if (meta.get('schema'), meta.get('rom_sha256'), meta.get('pyboy')) != (SCHEMA, SHA256, PYBOY_VERSION):
            raise ValueError('State schema, ROM or PyBoy version mismatch')
        with self.suspended_hooks():
            rollback = io.BytesIO()
            self.p.save_state(rollback)
            try:
                self.p.load_state(io.BytesIO(data))
            except Exception:
                rollback.seek(0)
                self.p.load_state(rollback)
                raise
        self.frame = int(meta['frame'])
        self.watch = None
        self.scan = None
        self.event('state_loaded', path=str(path), note='Timeline rewound; watches and scans cleared.')

    def save_events(self, path):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('w', encoding='utf-8') as f:
            f.write(json.dumps({'schema': SCHEMA, 'rom_sha256': SHA256, 'dropped_events': self.dropped})+'\n')
            for row in self.events:
                f.write(json.dumps(row)+'\n')

    def scan_start(self, bank, value=None):
        bank = bounded(bank, 0, 7, 'WRAM bank')
        a = Address('wram', bank, 0xc000 if bank == 0 else 0xd000)
        data = self.read(a, 4096)
        candidates = {i for i, v in enumerate(data) if value is None or value == v}
        self.scan = (a, data, candidates)
        return self.scan_result()

    def scan_filter(self, mode, value=None):
        if not self.scan:
            raise ValueError('Start a scan first: scan start wram3 [byte_value]')
        a, old, candidates = self.scan
        now = self.read(a, 4096)
        predicates = {'changed': lambda x,y: x != y, 'same': lambda x,y: x == y,
                      'increased': lambda x,y: y > x, 'decreased': lambda x,y: y < x,
                      'value': lambda x,y: y == value}
        if mode not in predicates or (mode == 'value' and value is None):
            raise ValueError('scan changed|same|increased|decreased|value N')
        self.scan = (a, now, {i for i in candidates if predicates[mode](old[i], now[i])})
        return self.scan_result()

    def scan_result(self):
        a, data, candidates = self.scan
        return {'candidates': len(candidates), 'first_100': [
            {'address': str(Address(a.space, a.bank, a.offset+i)), 'value': data[i]} for i in sorted(candidates)[:100]]}

    def close(self):
        self.trace_names.clear()
        self.until_target = None
        self.sync_hooks()
        if self.owns_emulator:
            self.p.stop(save=False)


HELP = '''The emulator is paused between commands. Addresses are hex; counts/values are decimal or 0x-prefixed.
  run [frames]                     Advance frames quickly (default 60)
  step [frames]                    Advance frames (default 1), NOT CPU instructions
  play [frames]                    Run at ~60 fps with window controls; Ctrl+C returns to prompt
  press BUTTON [held_frames]        A/B/start/select/up/down/left/right; default 1 frame
  regs | banks                     Registers, flags, WRAM bank, game bank shadows
  units [all] | unit SLOT           Live units (may be meaningless outside an active battle)
  combat                           Current scratch values; can be stale outside combat
  peek ADDRESS [length]             Read bytes, e.g. peek wram3::d000 64
  where ADDRESS_OR_SYMBOL          Translate Ghidra/CPU/file-offset/bank notation
  template INDEX | weapon INDEX    Decode static ROM records
  snapshot FILE.json               Save all WRAM banks and decoded state
  diff BEFORE.json AFTER.json      Show field changes and first 50 raw byte changes
  watch ADDRESS [length] | unwatch  Log changes sampled every frame (one region, up to 4096 bytes)
  scan start wramN [value]          Find byte candidates in a physical WRAM bank
  scan changed|same|increased|decreased|value N   Narrow using observations since previous scan
  trace on|off                     Trace known combat points and confirmed unit-writer stores
  until POINT [max_frames]         Run to frame containing POINT; captures exact hook registers
  points                           List named instruction hooks
  events [count] | events clear     Last events (default 10); ring capacity 10000
  trace save FILE.jsonl             Export retained events with ROM hash and dropped count
  save-state FILE.gbwstate          Save a new, versioned lab checkpoint (no overwrite)
  load-state FILE.gbwstate          Restore lab checkpoint; clears watch/scan baseline
  screenshot FILE.png              Save the rendered screen
  help | quit
Window controls: arrows, A=A key, B=S key, Start=Enter, Select=Backspace.
Use this lab's save-state/load-state commands, not PyBoy's Z/X hotkeys.
Use play to interact with the SDL window. It only processes window events while frames run.
'''


def pretty(value):
    print(json.dumps(value, indent=2))


def execute(lab, line):
    args = shlex.split(line)
    if not args or args[0].startswith('#'):
        return True
    cmd, *a = args
    if cmd in ('quit', 'exit'):
        return False
    if cmd == 'help':
        print(HELP)
    elif cmd in ('run', 'step', 'play'):
        default = 1 if cmd == 'step' else (36000 if cmd == 'play' else 60)
        count = bounded(a[0], 1, 360000, 'frames') if a else default
        pretty(lab.advance(count, realtime=cmd == 'play'))
    elif cmd == 'press':
        key = a[0].lower()
        if key not in ('a','b','start','select','up','down','left','right'):
            raise ValueError('Unknown button')
        count = bounded(a[1], 1, 3600, 'held frames') if len(a) > 1 else 1
        lab.p.button_press(key)
        try:
            result = lab.advance(count)
        finally:
            lab.p.button_release(key)
            lab.advance(1)
        pretty(result)
    elif cmd in ('regs', 'banks'):
        pretty(lab.regs())
    elif cmd == 'units':
        rows = lab.units(bool(a and a[0] == 'all'))
        print('slot side name         x  y HP fuel ammo1 ammo2 exp address')
        for r in rows:
            print(f"{r['slot']:4} {r['side']:4} {r['name'][:12]:12} {r['map_x']:2} {r['map_y']:2} {r['hp']:2} "
                  f"{r['fuel']:4} {r['ammo_primary']:5} {r['ammo_secondary']:5} {r['experience']:3} {r['address']}"
                  + (' [inactive/implausible]' if not r['plausible'] else ''))
        if not rows:
            print('No active unit records. Navigate into a battle first.')
    elif cmd == 'unit':
        slot = bounded(a[0], 0, 99, 'slot')
        row = lab.units(True)[slot]
        row['fields'] = [{'offset_hex': f'{i:02x}', 'field': FIELDS[i], 'value': b,
                          'address': f'wram3::{0xd000+16*slot+i:04x}'}
                         for i,b in enumerate(bytes.fromhex(row['raw_hex']))]
        pretty(row)
    elif cmd == 'combat':
        pretty(lab.combat())
    elif cmd == 'where':
        pretty(Address.parse(a[0]).description())
    elif cmd == 'peek':
        address = Address.parse(a[0]); count = bounded(a[1], 1, 4096, 'length') if len(a)>1 else 64
        data = lab.read(address, count)
        for i in range(0, count, 16):
            print(f'{Address(address.space,address.bank,address.offset+i)}  {data[i:i+16].hex(" ")}')
    elif cmd in ('template','weapon'):
        rows = lab.tables['units' if cmd == 'template' else 'weapons']
        pretty(rows[bounded(a[0], 0, len(rows)-1, 'index')])
    elif cmd == 'snapshot':
        json_write(a[0], lab.snapshot()); print(f'Saved {a[0]}')
    elif cmd == 'diff':
        result = compare_snapshots(*(json.loads(Path(path).read_text()) for path in a[:2]))
        result['memory_changes'] = result['memory_changes'][:50]
        result['note'] = 'Raw byte display capped at 50; changed_bytes counts all.'
        pretty(result)
    elif cmd == 'watch':
        address = Address.parse(a[0]); count = bounded(a[1], 1, 4096, 'length') if len(a)>1 else 1
        if address.space not in ('wram', 'cpu', 'vram', 'xram'):
            raise ValueError('Watch RAM or CPU space, not immutable ROM')
        lab.watch = (address, count, lab.read(address,count)); print('Frame-sampled watch enabled')
    elif cmd == 'unwatch':
        lab.watch = None
    elif cmd == 'scan':
        if a[0] == 'start':
            m = re.fullmatch('wram([0-7])', a[1])
            if not m: raise ValueError('Use wram0 through wram7')
            pretty(lab.scan_start(m[1], bounded(a[2],0,255,'byte') if len(a)>2 else None))
        else:
            pretty(lab.scan_filter(a[0], bounded(a[1],0,255,'byte') if len(a)>1 else None))
    elif cmd == 'trace':
        if a[0] in ('on','off'):
            lab.trace(a[0]=='on'); print(f'Trace {a[0]}')
        elif a[0] == 'save':
            lab.save_events(a[1]); print(f'Saved {a[1]}')
        else: raise ValueError('trace on|off|save FILE.jsonl')
    elif cmd == 'until':
        count = bounded(a[1],1,360000,'max frames') if len(a)>1 else 600
        pretty(lab.advance(count,until=a[0]))
    elif cmd == 'points':
        pretty({k: str(Address('rom',*v)) for k,v in POINTS.items()})
    elif cmd == 'events':
        if a and a[0] == 'clear':
            lab.events.clear(); lab.dropped = 0
        else:
            count = bounded(a[0],1,10000,'event count') if a else 10
            pretty({'dropped': lab.dropped, 'events': list(lab.events)[-count:]})
    elif cmd == 'save-state':
        lab.save_state(a[0]); print(f'Saved {a[0]}')
    elif cmd == 'load-state':
        lab.load_state(a[0]); print(f'Loaded {a[0]}')
    elif cmd == 'screenshot':
        path = Path(a[0]); path.parent.mkdir(parents=True,exist_ok=True)
        lab.p.screen.image.save(path); print(f'Saved {path}')
    else:
        raise ValueError('Unknown command; type help')
    return True


def demo(path, output):
    """Synthetic experiments execute actual ROM routines, without a playable map."""
    output = Path(output)
    rom = check_rom(path)
    h = Harness(path)
    lab = Lab(rom, pyboy=h.p)
    lab.trace(True)
    try:
        base = {0xdbd7:0,0xdbd8:0,0xdbd9:0,0xdbd4:10,0xdbd3:10,
                0xdbec:0,0xdbed:0,0xdbeb:0,0xdbea:10,0xdbe8:10,0xdbe9:10,
                0xdbd5:10,0xdbd6:0,0xdbee:0,0xdbc8:0,0xdbc9:50}
        results = []
        for name, ai, di in [('equal',10,10),('attacker_first',10,1),('defender_first',1,10)]:
            for slot, side in [(0,0),(50,1)]:
                off = 0xd000+16*slot
                h.p.memory[3,off:off+16] = [2|side,3+side,4,0,10,0,0,99,9,0,0,0,0,0,0,0]
            # Initialize every labeled combat byte to prevent stale-case values.
            for addr in COMBAT.values(): h.p.memory[4,addr] = 0
            for addr,value in base.items(): h.p.memory[4,addr] = value
            for addr,value in {0xdbcf:ai,0xdbe4:di,0xdbcb:10,0xdbe0:10,0xdbf6:1}.items(): h.p.memory[4,addr] = value
            before = lab.snapshot()
            lab.frame += 1
            h.call(0x4b0a)
            final = (h.p.memory[4,0xdbd3],h.p.memory[4,0xdbe8])
            # Explicit test-driver commit via the game's real unit writer.
            # This does not pretend that we executed the complete battle pipeline.
            for slot,hp in [(0,final[0]),(50,final[1])]:
                lab.frame += 1
                h.call(0x40a1,{'A':slot,'C':4,'B':hp},bank=18)
            after = lab.snapshot()
            json_write(output/f'{name}-before.json',before)
            json_write(output/f'{name}-after.json',after)
            results.append({'case':name,'attacker_hp':final[0],'defender_hp':final[1],
                            'diff':compare_snapshots(before,after)})
        lab.save_events(output/'events.jsonl')
        report = {'scenario':'Synthetic inputs, actual ROM calculations and unit writes; no map battle or full commit routine.',
                  'rom_sha256':SHA256,'results':results}
        json_write(output/'demo-results.json',report)
        return report
    finally:
        lab.close(); h.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('rom',type=Path)
    sub = parser.add_subparsers(dest='action',required=True)
    sub.add_parser('inspect');sub.add_parser('verify')
    d = sub.add_parser('demo');d.add_argument('--out',type=Path,default=Path('demo-output'))
    s = sub.add_parser('shell');s.add_argument('--window',choices=['null','SDL2'],default='null')
    s.add_argument('--ram',type=Path);s.add_argument('--state',type=Path)
    s.add_argument('--commands',type=Path,help='Run a command file, then exit; errors fail the batch')
    args = parser.parse_args(argv)
    try:
        rom = check_rom(args.rom)
        if args.action == 'inspect': pretty(inspect_rom(rom));return 0
        if args.action == 'verify': pretty(verify(args.rom));return 0
        if args.action == 'demo': pretty(demo(args.rom,args.out));return 0
        lab = Lab(rom,window=args.window,ram=args.ram)
        try:
            if args.state: lab.load_state(args.state)
            if args.commands:
                for line in args.commands.read_text().splitlines():
                    print('gbw3> '+line)
                    if not execute(lab,line) or not lab.alive: break
            else:
                print('GBW3 live lab. Correct student ROM. Type help. Game starts paused; run 180 to boot.')
                while lab.alive:
                    try:
                        line = input('gbw3> ')
                    except (EOFError,KeyboardInterrupt):
                        print();break
                    try:
                        if not execute(lab,line): break
                    except (ValueError,IndexError,KeyError,OSError,zipfile.BadZipFile) as e:
                        print(f'Error: {e}')
        finally:
            lab.close()
        return 0
    except Exception as e:
        print(f'Error: {e}',file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
