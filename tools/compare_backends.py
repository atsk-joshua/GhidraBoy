#!/usr/bin/env python3
"""Compare defined, initialized CGB state through current production adapters.

No downloads or native builds. Workers have independent process watchdogs.
Exit 0 means compared state/timing agree; 2 means classified differences were
retained; 1 means infrastructure, coverage, or unexpected comparison failure.
Neither agreement nor a classified difference establishes hardware accuracy.
"""
import argparse
import dataclasses
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'debugger/python'))
REGISTERS = ('af', 'bc', 'de', 'hl', 'sp', 'pc')
HARDWARE = ('rom0', 'romx', 'wram', 'vram', 'cart', 'ime', 'halted',
            'double_speed', 'boot', 'cart_enabled')
MEMORY = (('wram0', 'wram', 0, 0xc000), ('wram3', 'wram', 3, 0xd000),
          ('cart2', 'cart', 2, 0xa000))
BOUNDARIES = (
    ('initialized', 0, 0x250), ('normal_nop', 0, 0x251),
    ('normal_load', 0, 0x253), ('normal_store', 0, 0x256),
    ('normal_inc', 0, 0x257), ('bank1_entry', 1, 0x4000),
    ('bank2_entry', 2, 0x4000), ('bank2_done', 0, 0x280),
    ('speed_armed', 0, 0x284), ('speed_switch_and_nop', 0, 0x287),
    ('double_speed_inc', 0, 0x288), ('double_speed_nop', 0, 0x289),
)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def fixture(divergent=False):
    """Locally authored executable bytes; no ROM extraction or external assets."""
    rom = bytearray(65536)
    rom[0x100:0x104] = bytes.fromhex('00 c3 50 01')
    rom[0x134:0x13f] = b'CROSSBACK01'
    rom[0x143] = 0x80
    rom[0x147:0x14a] = bytes((0x1b, 1, 3))  # MBC5 + 32 KiB RAM
    # DI, LCD/IE/IF/timer off; select WRAM3, VRAM0, ROM1, enabled SRAM2.
    code = bytearray.fromhex(
        'f3 af e0 40 ea ff ff e0 0f e0 07 '
        '3e 03 e0 70 af e0 4f 3e 01 ea 00 20 '
        '3e 0a ea 00 00 3e 02 ea 00 40 af')
    for base in (0xc000, 0xd000, 0xa000):
        for offset in range(8):
            address = base + offset
            code.extend((0xea, address & 255, address >> 8))
    code.extend(bytes.fromhex('31 f0 df 01 34 12 11 78 56 21 bc 9a 3e 5a c3 50 02'))
    if 0x150 + len(code) > 0x250:
        raise AssertionError('Initializer overlaps synchronized test block')
    rom[0x150:0x150 + len(code)] = code
    normal = bytearray.fromhex('00 3e 42 ea 00 c0 04 3e 01 ea 00 20 c3 00 40')
    if divergent:
        normal[2] = 0x99  # Intentional different input, never hidden as engine error.
    rom[0x250:0x250 + len(normal)] = normal
    bank1 = bytes.fromhex('3e 11 ea 01 c0 3e 02 ea 00 20')
    rom[0x4000:0x4000 + len(bank1)] = bank1
    bank2 = bytes.fromhex('3e 22 ea 02 c0 c3 80 02 00 00 c3 00 40')
    rom[0x8000:0x8000 + len(bank2)] = bank2
    speed = bytes.fromhex('3e 01 e0 4d 10 00 00 04 00 18 fe')
    rom[0x280:0x280 + len(speed)] = speed
    rom[0x14d] = (-sum(rom[0x134:0x14d]) - 25) & 255
    checksum = sum(rom) & 65535
    rom[0x14e:0x150] = checksum.to_bytes(2, 'big')
    return bytes(rom)


def sync(machine, bank, pc, timeout):
    offset = pc if pc < 0x4000 else pc - 0x4000
    point = machine.breakpoint('rom', bank, offset)
    try:
        machine.prepare()
        deadline = time.monotonic() + timeout
        while not machine.run_slice():
            if time.monotonic() >= deadline:
                raise TimeoutError(f'No physical ROM bank {bank} PC {pc:04x} stop')
        captured = machine.capture()
        actual_bank = captured.state['rom0' if pc < 0x4000 else 'romx']
        if (captured.stop_reason, captured.state['pc'], actual_bank) != ('breakpoint', pc, bank):
            raise AssertionError('Unexpected stop: ' + repr(dict(captured.state)))
        return captured
    finally:
        machine.remove(point)


def observation(captured):
    state = {key: captured.state[key] for key in REGISTERS + HARDWARE}
    for name, region, bank, address in MEMORY:
        for start, length in captured.unknown_cpu_ranges:
            if start < address + 8 and address < start + length:
                raise AssertionError(f'Compared CPU memory {name} is unknown')
        cpu = captured.cpu_bytes[address:address + 8]
        physical = captured.bank_bytes(region, bank)[:8]
        if cpu != physical:
            raise AssertionError(f'Defined CPU/physical projection differs for {name}')
        state[name] = cpu.hex()
    return state


def worker(args):
    if args.backend == 'sameboy':
        from ghigbc.backends.sameboy import Machine
        model = 'CGB-E'
    else:
        from ghigbc.backends.mgba import Machine
        model = 'CGB'
    with Machine(args.rom, model=model) as machine:
        if machine.key_mask() != 0:
            raise AssertionError('Fixture requires no input')
        rows = []
        previous = None
        for name, bank, pc in BOUNDARIES:
            captured = sync(machine, bank, pc, args.timeout)
            row = {'name': name, 'physicalBank': bank, 'pc': pc,
                   'ticks': captured.state['ticks'], 'state': observation(captured)}
            if previous is not None:
                row['intervalTicks'] = row['ticks'] - previous
                if row['intervalTicks'] < 0:
                    raise AssertionError('Nonmonotonic backend time')
            previous = row['ticks']
            rows.append(row)
            if args.divergent and name == 'normal_store':
                break
        initialized = rows[0]['state']
        expected = {'af': 0x5a80, 'bc': 0x1234, 'de': 0x5678, 'hl': 0x9abc,
                    'sp': 0xdff0, 'pc': 0x250, 'rom0': 0, 'romx': 1,
                    'wram': 3, 'vram': 0, 'cart': 2, 'ime': 0, 'halted': 0,
                    'double_speed': 0, 'boot': 0, 'cart_enabled': 1,
                    'wram0': '00' * 8, 'wram3': '00' * 8, 'cart2': '00' * 8}
        if initialized != expected:
            raise AssertionError('Initializer oracle failed: ' + repr(initialized))
        descriptor = dataclasses.asdict(machine.descriptor)
        descriptor['features'] = sorted(descriptor['features'])
        library = Path(machine.lib._name)
        result = {'schema': 1, 'status': 'CAPTURED', 'backend': args.backend,
                  'descriptor': descriptor, 'romSha256': machine.rom_hash,
                  'bootSha256': machine.boot_hash, 'bootBytes': len(machine.boot_bytes),
                  'nativePath': str(library), 'nativeSha256': sha(library),
                  'adapterSha256': sha(ROOT / f'debugger/python/ghigbc/backends/{args.backend}.py'),
                  'rows': rows}
        receipt = Path(str(library) + '.json')
        if receipt.exists():
            result['nativeReceiptSha256'] = sha(receipt)
        write_json(args.output, result)


def differences(left, right):
    """Named field comparisons; omitted rows/keys are an error, never agreement."""
    if not left or not right:
        raise ValueError('Comparison needs captured synchronization boundaries')
    if [r['name'] for r in left] != [r['name'] for r in right]:
        raise ValueError('Synchronization boundary sequences differ')
    found = []
    for a, b in zip(left, right):
        if a['state'].keys() != b['state'].keys():
            raise ValueError('Compared state field sets differ')
        for key in a['state']:
            if a['state'][key] != b['state'][key]:
                found.append({'boundary': a['name'], 'field': key,
                              'sameboy': a['state'][key], 'mgba': b['state'][key]})
    return found


def timing_interval(name, at, af, bt, bf):
    # Cross multiplication avoids rounding and never compares startup ticks.
    match = at * bf == bt * af
    row = {'boundary': name, 'matches': match,
           'sameboy': {'ticks': at, 'frequency': af, 'seconds': at / af},
           'mgba': {'ticks': bt, 'frequency': bf, 'seconds': bt / bf},
           'classification': ('equal-defined-interval' if match else
               'speed-switch-device-delay-unresolved' if name == 'speed_switch_and_nop'
               else 'unexpected-defined-interval-disagreement')}
    if not match and name == 'speed_switch_and_nop':
        row['minimalCase'] = {
            'start': {'bank': 0, 'pc': 0x284, 'speed': 1, 'KEY1': 1, 'IME': 0, 'IE': 0, 'IF': 0},
            'romBytes': '100000', 'operations': ['STOP 00', 'NOP'],
            'end': {'bank': 0, 'pc': 0x287, 'speed': 2},
            'input': 'All keys released; fixture initialization disables LCD and timer',
        }
        row['sourceMechanism'] = {
            'sameboy': 'Core/sm83_cpu.c:449 assigns speed_switch_halt_countdown=0x20008',
            'mgba': 'src/gb/gb.c:1095-1100 toggles doubleSpeed/tMultiplier immediately in GBStop',
            'classification': 'Observed pinned implementation difference; no physical hardware adjudication',
        }
    return row


def run(args):
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    (out / 'defined.gbc').write_bytes(fixture())
    (out / 'divergent.gbc').write_bytes(fixture(True))
    reports = {}
    commands = []
    # Sequential native workers avoid changing host load or shared process state.
    for label, backend, divergent in (('sameboy', 'sameboy', False), ('mgba', 'mgba', False),
                                       ('mgba-divergent', 'mgba', True)):
        cmd = [sys.executable, str(Path(__file__).resolve()), '--worker', '--backend', backend,
               '--rom', str(out / ('divergent.gbc' if divergent else 'defined.gbc')),
               '--output', str(out / (label + '.json')), '--timeout', str(args.timeout)]
        if divergent:
            cmd.append('--divergent')
        commands.append(cmd)
        with (out / (label + '.log')).open('w') as log:
            result = subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT, timeout=args.timeout)
        if result.returncode:
            raise RuntimeError(f'{label} worker exited {result.returncode}; see {out / (label + ".log")}')
        reports[label] = json.loads((out / (label + '.json')).read_text())
    left, right = reports['sameboy'], reports['mgba']
    if left['romSha256'] != right['romSha256']:
        raise AssertionError('Positive comparison used different ROM inputs')
    state_differences = differences(left['rows'], right['rows'])
    timing = []
    for a, b in zip(left['rows'][1:], right['rows'][1:]):
        af, bf = left['descriptor']['ticks_per_second'], right['descriptor']['ticks_per_second']
        at, bt = a['intervalTicks'], b['intervalTicks']
        timing.append(timing_interval(a['name'], at, af, bt, bf))
    negative = reports['mgba-divergent']['rows']
    injected = differences(left['rows'][:len(negative)], negative)
    expected_injected = [
        {'boundary': 'normal_load', 'field': 'af', 'sameboy': 0x4280, 'mgba': 0x9980},
        {'boundary': 'normal_store', 'field': 'af', 'sameboy': 0x4280, 'mgba': 0x9980},
        {'boundary': 'normal_store', 'field': 'wram0',
         'sameboy': '42' + '00' * 7, 'mgba': '99' + '00' * 7},
    ]
    if injected != expected_injected:
        raise AssertionError('Intentional divergence detector failed: ' + repr(injected))
    mismatches = [row for row in timing if not row['matches']]
    unexpected = state_differences or any(row['boundary'] != 'speed_switch_and_nop' for row in mismatches)
    report = {'schema': 1, 'status': 'FAIL_UNEXPECTED' if unexpected else 'DIFFERENCES_RECORDED' if mismatches else 'COMPARED_EQUAL',
              'hardwareAccuracyQualified': False, 'host': platform.platform(),
              'scriptSha256': sha(__file__), 'commands': commands,
              'definedState': {'status': 'FAIL' if state_differences else 'PASS',
                               'boundaries': len(left['rows']), 'differences': state_differences},
              'timing': timing,
              'negativeControl': {'status': 'DETECTED', 'classification': 'intentional-different-ROM-input',
                  'romByteOffset': 0x252, 'expectedByte': 0x42, 'divergentByte': 0x99,
                  'minimalSteps': 'At ROM bank 0 PC 0x251, execute LD A,$42 or LD A,$99 once; AF differs at PC 0x253.',
                  'differences': injected},
              'provenance': {key: {k: v for k, v in value.items() if k != 'rows'} for key, value in reports.items()},
              'excluded': ['Startup equality: SameBoy CGB-E boot image versus mGBA CGB engine post-boot',
                           'CGB silicon revision equality', 'PPU/APU startup and complete device accuracy',
                           'Uninitialized registers, RAM, IO and absolute startup ticks',
                           'Instruction counts: mGBA supplies execution-boundary counts only',
                           'Physical hardware truth, exhaustive opcode/model/mapper conformance']}
    write_json(out / 'comparison.json', report)
    print(json.dumps({'status': report['status'], 'definedState': report['definedState']['status'],
                      'timingDifferences': len(mismatches), 'report': str(out / 'comparison.json')}))
    return 1 if unexpected else 2 if mismatches else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True, help='Fresh evidence directory')
    parser.add_argument('--timeout', type=float, default=30, help='Seconds per native worker watchdog')
    parser.add_argument('--worker', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--backend', choices=('sameboy', 'mgba'), help=argparse.SUPPRESS)
    parser.add_argument('--rom', type=Path, help=argparse.SUPPRESS)
    parser.add_argument('--divergent', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if not 0 < args.timeout <= 300:
        parser.error('--timeout must be positive and at most 300 seconds')
    if args.worker:
        if not args.backend or not args.rom:
            parser.error('Worker needs --backend and --rom')
        worker(args)
        return 0
    return run(args)


if __name__ == '__main__':
    raise SystemExit(main())
