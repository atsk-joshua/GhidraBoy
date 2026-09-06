"""Small GB/GBC execution contract. Importing it never loads an emulator library."""
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path
from typing import Mapping, Protocol, Iterable, Optional

ROOT = Path(__file__).resolve().parents[2]
# Stable physical-region vocabulary used by existing trace/event schema 1.
REGIONS = ('cpu', 'rom', 'wram', 'vram', 'cart', 'boot', 'oam', 'hram', 'io', 'unknown')


class Button(IntEnum):
    RIGHT = 0
    LEFT = 1
    UP = 2
    DOWN = 3
    A = 4
    B = 5
    SELECT = 6
    START = 7


class UnsupportedFeature(RuntimeError):
    pass


@dataclass(frozen=True)
class BackendDescriptor:
    id: str
    name: str
    core: str
    config: str
    patch: str
    model: str
    mode: str
    ticks_per_second: Optional[int]
    features: frozenset
    models: tuple
    mappers: tuple
    observation_coverage: str
    memory_semantics: str

    def __post_init__(self):
        object.__setattr__(self, 'features', frozenset(self.features))
        object.__setattr__(self, 'models', tuple(self.models))
        object.__setattr__(self, 'mappers', tuple(self.mappers))
        if self.ticks_per_second is not None and self.ticks_per_second <= 0:
            raise ValueError('Backend timebase must be positive')

    def require(self, *features):
        missing = set(features) - self.features
        if missing:
            raise UnsupportedFeature(self.name + ' does not support: ' + ', '.join(sorted(missing)))

    @property
    def profile_capabilities(self):
        return self.features & {'physical-capture-v1', 'physical-watch-v1'}


@dataclass(frozen=True)
class MemoryBank:
    region: str
    bank: int
    data: bytes

    def __post_init__(self):
        if self.region not in REGIONS or self.bank < 0:
            raise ValueError('Invalid captured physical bank')
        object.__setattr__(self, 'data', bytes(self.data))


@dataclass(frozen=True)
class VideoFrame:
    width: int
    height: int
    data: bytes
    pixel_format: str = 'ARGB8888'

    def __post_init__(self):
        if self.pixel_format != 'ARGB8888' or not 0 < self.width <= 4096 or not 0 < self.height <= 4096:
            raise ValueError('Unsupported video frame format/size')
        object.__setattr__(self, 'data', bytes(self.data))
        if len(self.data) != self.width * self.height * 4:
            raise ValueError('Video frame byte count does not match its dimensions')


class Snapshot(Protocol):
    descriptor: BackendDescriptor
    state: Mapping
    events: tuple
    session: str
    rom_hash: str
    edit: object
    parent_checkpoint: object

    @property
    def cpu_bytes(self) -> bytes: ...
    @property
    def stop_reason(self) -> str: ...
    @property
    def unknown_cpu_ranges(self) -> tuple: ...
    def bank_bytes(self, region: str, bank: int) -> bytes: ...
    def mutable_banks(self) -> Iterable[MemoryBank]: ...


class Backend(Protocol):
    descriptor: BackendDescriptor
    rom: Path
    rom_bytes: bytes
    boot_bytes: bytes
    session: str
    rom_hash: str
    running: bool
    experiment: bool
    breakpoints: Mapping

    def close(self) -> None: ...
    def pause(self) -> None: ...  # Must not queue behind bounded execution work.
    def prepare(self) -> None: ...
    def prepare_step(self, mode: int) -> None: ...
    def run_slice(self, step: bool = False) -> int: ...  # Zero continues, nonzero stops.
    def ticks(self) -> int: ...
    def capture(self) -> Snapshot: ...
    def step(self) -> Snapshot: ...
    def breakpoint(self, region, bank, offset, kinds=1, length=1, id=None, enabled=True) -> int: ...
    def remove(self, id: int) -> None: ...
    def checkpoint(self, path: Path) -> Path: ...
    def restore(self, path: Path) -> Snapshot: ...
    def edit(self, *, register=None, address=None, value, recovery) -> Snapshot: ...
    def key(self, key: int, pressed: bool) -> None: ...
    def key_mask(self) -> int: ...
    def frame(self) -> VideoFrame: ...


def available_backends():
    return ('sameboy',)


def create_backend(name, rom, **options) -> Backend:
    if name != 'sameboy':
        raise UnsupportedFeature('Unknown or uninstalled backend: ' + name)
    from .backends.sameboy import Machine
    return Machine(rom, **options)
