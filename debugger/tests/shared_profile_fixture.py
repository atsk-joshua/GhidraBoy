"""Installed, bounded profile fixture for the shared real-backend Java contract."""
import hashlib
import os
from ghigbc.backend import ROOT
from ghigbc.profile import ByteRange, Field

MODE = os.environ.get('GBC_SHARED_PROFILE_MODE', 'synthetic')
SOURCE = ByteRange('wram', 1, 0x34, 1)


class Decoder:
    def decode(self, view):
        yield Field('counter', 'integer', view.read(SOURCE)[0], SOURCE,
                    'observed', 'Self-authored teaching ROM counter byte')


class Provider:
    id = 'shared-synthetic-counter'
    version = '1.0.0'
    api_version = 1
    requires = frozenset({'physical-capture-v1'})
    ranges = (SOURCE,)
    fingerprints = frozenset({hashlib.sha256(
        (ROOT / 'build/teaching.gbc').read_bytes() +
        (b'wrong ROM revision' if MODE == 'wrong-revision' else b'')).hexdigest()})

    @staticmethod
    def create(rom):
        if MODE == 'failing':
            raise RuntimeError('deliberate shared profile failure')
        return Decoder()


provider = Provider()
