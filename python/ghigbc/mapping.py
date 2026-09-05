"""Versioned static envelopes; hardware observations remain independent of static inference."""
import hashlib
import json
from types import MappingProxyType


def accept_envelope(text, rom_hash):
    if len(text.encode('utf-8')) > 8 * 1024 * 1024:
        raise ValueError('Static envelope exceeds 8 MiB')
    data = json.loads(text)
    if data.get('adapterVersion') != 1 or data.get('static', {}).get('schemaVersion') != 2:
        raise ValueError('Unsupported mapping adapter/schema')
    if data['static'].get('language') != 'SM83:LE:16:default':
        raise ValueError('Wrong static language')
    if data.get('currentExportSha256') != rom_hash or data.get('fullMappedCoverage') is not True:
        raise ValueError('Static binding requires current loaded bytes and full verified coverage')
    generation = data.get('generation', '')
    if len(generation) != 64 or any(c not in '0123456789abcdef' for c in generation):
        raise ValueError('Invalid immutable generation')
    # Serialized bytes are immutable; callers never retain a mutable live Program or dictionary.
    return generation, text.encode('utf-8')


def physical(region, bank, offset):
    """Normalize SameBoy observations into facade vocabulary, preserving unknown/device states."""
    names = {'rom': ('ROM', 16384), 'wram': ('WRAM', 4096),
             'vram': ('VRAM', 8192), 'cart': ('SRAM', 8192), 'boot': ('BOOT', 2304)}
    if region not in names or bank is None or bank < 0:
        return MappingProxyType({'status': 'device' if region == 'io' else 'unknown'})
    name, bound = names[region]
    if not 0 <= offset < bound:
        raise ValueError('Physical offset outside bank')
    return MappingProxyType({'status': 'mapped', 'region': name, 'bank': bank, 'offset': offset})


class EnvelopeTransfer:
    """One bounded ordered upload per owner; replacement/epoch changes discard partial uploads."""
    def __init__(self):
        self.key = None
        self.parts = []

    def append(self, generation, index, count, part, session, epoch, rom_hash):
        if not 1 <= count <= 512 or not 0 <= index < count or len(part) > 16000:
            raise ValueError('Invalid static snapshot chunk')
        key = (generation, count, session, epoch)
        if index == 0:
            self.key, self.parts = key, []
        if self.key != key or index != len(self.parts):
            self.key, self.parts = None, []
            raise ValueError('Out-of-order or stale static snapshot chunk')
        self.parts.append(part)
        if len(self.parts) != count:
            return None
        text = ''.join(self.parts)
        self.key, self.parts = None, []
        result = accept_envelope(text, rom_hash)
        if result[0] != generation:
            raise ValueError('Snapshot generation differs from transfer')
        return result
