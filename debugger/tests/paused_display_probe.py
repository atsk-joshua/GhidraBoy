"""Real-window acceptance probe. UI actions must be performed through CUA or by a user.

The `hold` command seeds guest input through the native ABI only. It is not a
synthetic OS keyboard event. A real desktop focus change must release it.
No dummy/offscreen SDL driver and no emulation while the window is open.
"""
import json
import ctypes
import os
from pathlib import Path
import queue
import sys
import threading
import time

from ghigbc import display
from ghigbc.backend import Button, ROOT, create_backend


def main():
    if os.environ.get('SDL_VIDEODRIVER') in ('dummy', 'offscreen'):
        raise RuntimeError('This probe requires a real desktop video driver')
    output = Path(os.environ.get('GBC_EVIDENCE_DIR', str(ROOT/'build/reports'))) / 'paused-display.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    stop = threading.Event()
    commands = queue.Queue()
    observations = []

    def stdin_reader():
        for line in sys.stdin:
            commands.put(line.strip())

    with create_backend('sameboy', ROOT / 'build/teaching.gbc') as machine:
        machine.breakpoint('rom', 1, 0x29)
        machine.prepare()
        for _ in range(5000):
            if machine.run_slice():
                break
        before = machine.capture()
        assert before.state['reason'] == 3 and before.state['pc'] == 0x4029
        ticks = machine.ticks()
        started = time.monotonic()

        def record(kind, **extra):
            row = dict(kind=kind, seconds=time.monotonic()-started,
                       key_mask=machine.key_mask(), ticks=machine.ticks(), **extra)
            observations.append(row)
            print(json.dumps(row), flush=True)

        def monitor():
            previous = machine.key_mask()
            record('ready', pc=before.state['pc'])
            while not stop.wait(.005):
                try:
                    command = commands.get_nowait()
                except queue.Empty:
                    command = None
                if command == 'hold':
                    machine.key(Button.A, True)
                    record('held_guest_a_seeded')
                elif command == 'snapshot':
                    record('snapshot')
                elif command == 'abort':
                    record('aborted')
                    stop.set()
                current = machine.key_mask()
                if current != previous:
                    record('input_transition', previous=previous)
                    previous = current
                if time.monotonic()-started > 600:
                    record('timed_out')
                    stop.set()

        def close_requested():
            record('window_close_requested')
            stop.set()

        reader = threading.Thread(target=stdin_reader, daemon=True)
        watcher = threading.Thread(target=monitor)
        reader.start()
        watcher.start()
        error = None
        original_loader = display.load_sdl

        def observed_sdl():
            """Passively record real SDL window events; never synthesize input."""
            library = original_loader()
            poll = library.SDL_PollEvent
            poll.argtypes = [ctypes.c_void_p]
            poll.restype = ctypes.c_int

            def observed_poll(pointer):
                result = poll(pointer)
                if result:
                    raw = ctypes.string_at(pointer, 56)
                    if int.from_bytes(raw[:4], sys.byteorder) == 0x200:
                        record('sdl_window_event', event=raw[12])
                return result

            library.SDL_PollEvent = observed_poll
            return library

        display.load_sdl = observed_sdl
        try:
            display.run(machine, stop, on_close=close_requested)
        except BaseException as failure:
            error = repr(failure)
            raise
        finally:
            display.load_sdl = original_loader
            stop.set()
            watcher.join()
            record('display_returned')
            report = dict(scope='macOS real SDL window with paused SameBoy; desktop actions recorded separately',
                          paused_ticks=ticks, all_ticks_unchanged=all(o['ticks']==ticks for o in observations),
                          final_keys_released=machine.key_mask()==0, error=error, observations=observations)
            output.write_text(json.dumps(report, indent=2)+'\n')


if __name__ == '__main__':
    main()
