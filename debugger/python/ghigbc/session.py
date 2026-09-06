"""Backend-independent session identity, execution policy and recoverable edits."""
from dataclasses import is_dataclass, replace
from concurrent.futures import Future, TimeoutError
import hashlib
import json
import os
from pathlib import Path
from queue import Queue, Empty, Full
import shutil
import tempfile
import threading
from types import MappingProxyType
import uuid

from .backend import Button

REGISTERS = ('AF', 'BC', 'DE', 'HL', 'SP', 'PC')


def freeze(value):
    if isinstance(value, (dict, MappingProxyType)):
        return MappingProxyType({key: freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(freeze(item) for item in value)
    return value


def digest(path):
    result = hashlib.sha256()
    with Path(path).open('rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            result.update(block)
    return result.hexdigest()


def write_json(path, value):
    """Publish durable metadata before permitting the associated state mutation."""
    path = Path(path)
    temporary = path.with_name(path.name + '.tmp')
    with temporary.open('w') as output:
        json.dump(value, output, indent=2)
        output.write('\n')
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


class Session:
    """One owner calls execution methods; native/frame/input locking stays explicit.

    Adapters implement underscore-prefixed hardware hooks. Snapshots are frozen
    dataclasses implementing the shared protocol, so stamping metadata is shallow
    and never copies backend buffers or exposes their representation here.
    """
    state_filename = 'state.bin'

    def __init__(self, experiment=False):
        if self.state_filename in ('.', '..') or Path(self.state_filename).name != self.state_filename:
            raise ValueError('Backend state filename must be a simple filename')
        self.session = str(uuid.uuid4())
        self.experiment = experiment
        self.running = False
        self.error = ''
        self.parent_checkpoint = None
        self.lock = threading.RLock()
        self._closed = False
        self._epoch = 0
        self._capture_id = 0

    def _require_open(self):
        if self._closed:
            raise RuntimeError('Backend is closed')

    def _require_ready(self):
        self._require_open()
        if self.error:
            raise RuntimeError('Restore a recovery checkpoint before continuing: ' + self.error)

    def close(self):
        with self.lock:
            if not self._closed:
                # Close is terminal even if native teardown reports a failure.
                self._closed = True
                self.running = False
                self._close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def pause(self):
        # Does not acquire the execution lock. Close occurs after workers stop.
        if not self._closed:
            self._request_pause()

    def prepare(self):
        self.descriptor.require('run')
        with self.lock:
            self._require_ready()
            self._prepare()

    def prepare_step(self, mode):
        if mode not in (2, 3):
            raise ValueError('Expected ordinary step-over or step-out')
        self.descriptor.require('step-over' if mode == 2 else 'step-out')
        with self.lock:
            self._require_ready()
            if self.running:
                raise RuntimeError('Pause before stepping')
            self._prepare_step(mode)

    def run_slice(self, step=False):
        with self.lock:
            self._require_ready()
            try:
                result = self._run_slice(step)
            except Exception as error:
                self.running = False
                self.error = 'Execution failed; target state is uncertain: ' + str(error)
                raise
            if result:
                self.running = False
            return result

    def step(self):
        self.descriptor.require('step')
        with self.lock:
            self._require_ready()
            if self.running:
                raise RuntimeError('Pause before stepping')
            self._prepare()
            self.run_slice(True)
            return self.capture()

    def capture(self):
        with self.lock:
            self._require_open()
            observation = self._capture()
            if not is_dataclass(observation) or not observation.__dataclass_params__.frozen:
                raise TypeError('Backend snapshots must be frozen dataclasses')
            if observation.stop_reason == 'error' and not self.error:
                self.error = 'Backend reported an execution error'
            self._capture_id += 1
            state = dict(observation.state, epoch=self._epoch, capture_id=self._capture_id,
                         session_error=self.error)
            return replace(observation, state=freeze(state), session=self.session,
                           events=freeze(observation.events), parent_checkpoint=self.parent_checkpoint,
                           descriptor=self.descriptor)

    def _checkpoint_identity(self):
        d = self.descriptor
        return dict(schema=3, backend=d.id, core=d.core, config=d.config, patch=d.patch,
                    model=d.model, mode=d.mode, ticks_per_second=d.ticks_per_second)

    def _identity(self):
        return dict(self._checkpoint_identity(), rom_hash=self.rom_hash, boot_hash=self.boot_hash)

    def checkpoint(self, path):
        self.descriptor.require('checkpoint')
        with self.lock:
            self._require_ready()
            if self.running:
                raise RuntimeError('Pause before saving a checkpoint')
            path = Path(path)
            path.mkdir(parents=True, exist_ok=False)
            state_file = path / self.state_filename
            self._save_state(state_file)
            with state_file.open('rb') as saved:
                os.fsync(saved.fileno())
            capture = self.capture()
            metadata = self._identity()
            metadata.update(backend=self.descriptor.id, state_file=self.state_filename,
                ticks_per_second=self.descriptor.ticks_per_second,
                input='release-on-restore' if 'input' in self.descriptor.features else 'backend-defined',
                session=self.session, epoch=capture.state['epoch'], capture=capture.state['capture_id'],
                ticks=capture.state['ticks'], state_sha256=digest(state_file),
                parent_checkpoint=dict(self.parent_checkpoint) if self.parent_checkpoint else None)
            write_json(path / 'metadata.json', metadata)
            return path

    def restore(self, path):
        self.descriptor.require('checkpoint')
        with self.lock:
            self._require_open()
            if self.running:
                raise RuntimeError('Pause before restoring')
            path = Path(path).resolve()
            meta = json.loads((path / 'metadata.json').read_text())
            if not isinstance(meta, dict):
                raise ValueError('Checkpoint metadata must be an object')
            state_hash = meta.get('state_sha256')
            if not isinstance(state_hash, str) or len(state_hash) != 64 or any(c not in '0123456789abcdef' for c in state_hash):
                raise ValueError('Checkpoint metadata lacks a valid state fingerprint')
            if any(meta.get(key) != value for key, value in self._identity().items()):
                raise ValueError('Checkpoint metadata mismatch')
            if (meta.get('backend', self.descriptor.id) != self.descriptor.id
                    or meta.get('state_file', self.state_filename) != self.state_filename
                    or meta.get('ticks_per_second', self.descriptor.ticks_per_second) != self.descriptor.ticks_per_second):
                raise ValueError('Checkpoint metadata mismatch')
            for key in ('epoch', 'capture', 'ticks'):
                if meta.get(key) is not None and (type(meta[key]) is not int or meta[key] < 0):
                    raise ValueError('Invalid checkpoint provenance: ' + key)
            # Restore the verified copy, not a path that can change after hashing.
            with tempfile.TemporaryDirectory(prefix='ghidraboy-restore-') as temporary:
                payload = Path(temporary) / self.state_filename
                shutil.copyfile(path / self.state_filename, payload)
                if digest(payload) != meta['state_sha256']:
                    raise ValueError('Checkpoint corrupted')
                try:
                    self._load_state(payload)
                    if 'input' in self.descriptor.features:
                        for key in Button:
                            self.key(key, False)
                except Exception as error:
                    self.error = 'Restore failed; machine state is uncertain: ' + str(error)
                    raise
            self._epoch += 1
            self.error = ''
            self.parent_checkpoint = freeze(dict(path=str(path), state_sha256=meta['state_sha256'],
                source_session=meta.get('session'), source_epoch=meta.get('epoch'), source_ticks=meta.get('ticks'),
                source_ticks_per_second=meta.get('ticks_per_second', self.descriptor.ticks_per_second)))
            return self.capture()

    def edit(self, *, register=None, address=None, value, recovery):
        self.descriptor.require('register-edit' if register is not None else 'wram-edit', 'checkpoint')
        with self.lock:
            self._require_ready()
            if not self.experiment or self.running:
                raise RuntimeError('Edits require paused experiment mode')
            if (register is None) == (address is None):
                raise ValueError('Choose one register or WRAM address')
            if type(value) is not int:
                raise ValueError('Edit value must be an integer')
            if register is not None:
                register = register.strip().upper()
                if register not in REGISTERS or not 0 <= value <= 65535:
                    raise ValueError('Invalid 16-bit register edit')
            elif type(address) is not int or not 0xc000 <= address < 0xfe00 or not 0 <= value <= 255:
                raise ValueError('Only WRAM byte edits are supported')
            before = self.capture()
            target = None
            if register is not None:
                old = before.state[register.lower()]
            else:
                canonical = address - 0x2000 if address >= 0xe000 else address
                bank = 0 if canonical < 0xd000 else before.state.get('wram')
                if type(bank) is not int:
                    raise ValueError('No resolved WRAM bank at the selected capture')
                offset = canonical & 0xfff
                target = dict(region='wram', bank=bank, offset=offset, cpu_address=address)
                old = before.bank_bytes('wram', bank)[offset]
            recovery = self.checkpoint(Path(recovery).resolve())
            metadata = json.loads((recovery / 'metadata.json').read_text())
            record = dict(schema=1, id=str(uuid.uuid4()), origin='debugger', kind='register' if register else 'memory',
                register=register, target=target, before=old, requested=value, recovery=str(recovery),
                recovery_sha256=metadata['state_sha256'], session=self.session, epoch=before.state['epoch'], status='prepared')
            audit = recovery / 'edit.json'
            write_json(audit, record)
            try:
                if register is not None:
                    self._write_register(register, value)
                else:
                    self._write_wram(bank, offset, value)
                after = self.capture()
                record['after'] = after.state[register.lower()] if register else after.bank_bytes('wram', bank)[offset]
            except Exception as error:
                self.error = 'Edit failed; recovery checkpoint retained at ' + str(recovery)
                record.update(status='failed', error=str(error)[:4096])
                write_json(audit, record)
                raise RuntimeError(self.error) from error
            record.update(capture_id=after.state['capture_id'], status='applied')
            write_json(audit, record)
            return replace(after, edit=freeze(record))


class CommandQueue:
    """Bounded owner-thread commands with execution-time context checks."""
    def __init__(self, current_capture, terminating=lambda: False, capacity=64):
        self.queue = Queue(maxsize=capacity)
        self.current_capture = current_capture
        self.terminating = terminating
        self._closed = False
        self._guard = threading.Lock()

    def enqueue(self, function, expected=None, selected=False, *, bind_context=True):
        from .profile import ActionContext
        with self._guard:
            if self._closed or self.terminating():
                raise RuntimeError('Session is terminating/disconnected')
            current = self.current_capture()
            context = expected or (ActionContext.of(current) if bind_context and current else None)
            def checked():
                if self._closed or self.terminating():
                    raise RuntimeError('Session disconnected')
                if context:
                    context.validate(self.current_capture(), selected)
                return function()
            future = Future()
            try:
                self.queue.put_nowait((checked, future))
            except Full as error:
                raise RuntimeError('Machine command backlog is full') from error
            return future

    def submit(self, function, expected=None, selected=False, timeout=30):
        future = self.enqueue(function, expected, selected)
        try:
            return future.result(timeout=timeout)
        except TimeoutError:
            if not future.cancel():
                raise TimeoutError('Command already executing; its completion was not cancelled')
            raise

    def run_one(self, timeout=0):
        try:
            function, future = self.queue.get(timeout=timeout)
        except Empty:
            return False
        if future.set_running_or_notify_cancel():
            try:
                future.set_result(function())
            except BaseException as error:
                future.set_exception(error)
        return True

    def close(self):
        with self._guard:
            self._closed = True
            pending = []
            while True:
                try:
                    _, future = self.queue.get_nowait()
                    pending.append(future)
                except Empty:
                    break
        # Callbacks may inspect the queue; do not invoke them while holding its guard.
        for future in pending:
            future.cancel()
