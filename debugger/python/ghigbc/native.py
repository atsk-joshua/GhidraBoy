"""Compatibility imports for existing SameBoy consumers; new code uses ghigbc.backend."""
from .backends.sameboy import (
    Address, C, Capture, CONFIG, CORE, Event, Machine, MEMORY_SIZE, PATCH,
    Path, REGIONS, REASONS, ROOT, State, as_dict, freeze,
)
