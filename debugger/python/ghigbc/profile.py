"""Trusted optional profile API v1. Pure decoding receives bounded copied observations only."""
from dataclasses import dataclass, asdict
import hashlib
import importlib
import json
from pathlib import Path
from types import MappingProxyType

API_VERSION = 1
CAPABILITIES = frozenset({'physical-capture-v1', 'physical-watch-v1'})
MAX_CAPTURE = 65536
MAX_FIELDS = 4096


@dataclass(frozen=True)
class ByteRange:
    region: str
    bank: int
    offset: int
    length: int

    def validate(self):
        sizes = {'wram': (8, 4096), 'vram': (2, 8192), 'cart': (16, 8192)}
        if self.region not in sizes:
            raise ValueError('Profiles declare copied mutable physical ranges')
        count, size = sizes[self.region]
        if any(type(x) is not int for x in (self.bank,self.offset,self.length)) or not (0 <= self.bank < count and 0 <= self.offset < size and 0 < self.length <= size-self.offset):
            raise ValueError('Profile range outside physical bank')
        return self

    def contains(self, other):
        return self.region == other.region and self.bank == other.bank and self.offset <= other.offset and other.offset+other.length <= self.offset+self.length


@dataclass(frozen=True)
class Field:
    name: str
    kind: str
    value: object
    source: ByteRange
    validity: str = 'decoded'
    note: str = ''


@dataclass(frozen=True)
class ActionContext:
    session: str
    epoch: int
    capture: int

    @staticmethod
    def of(capture):
        return ActionContext(capture.session,capture.state['epoch'],capture.state['capture_id'])

    def validate(self, current, selected=True):
        actual = ActionContext.of(current)
        if self.session != actual.session or self.epoch != actual.epoch or selected and self.capture != actual.capture:
            raise RuntimeError('Stale action: session, epoch or selected capture changed')


class Observation:
    def __init__(self, capture, ranges):
        self.context = ActionContext.of(capture)
        self.rom_hash = capture.rom_hash
        self._ranges = tuple((r,bytes(capture.bank_bytes(r.region,r.bank)[r.offset:r.offset+r.length])) for r in ranges)
        if any(len(data)!=r.length for r,data in self._ranges):
            raise ValueError('Required capture range unavailable')

    def read(self, source):
        source.validate()
        for declared,data in self._ranges:
            if declared.contains(source):
                start=source.offset-declared.offset
                return data[start:start+source.length]
        raise ValueError('Read outside declared bounded capture')


def installed_providers(root):
    """Explicit local install manifest only. Detection never downloads or imports ROM-specified code."""
    manifest=Path(root)/'profiles.json'
    if not manifest.exists():return (),()
    providers=[];errors=[]
    try:
        data=json.loads(manifest.read_text())
        if data.get('schema')!=1 or len(data.get('modules',[]))>16:raise ValueError('Unsupported provider manifest')
        for name in data['modules']:
            try:
                if not isinstance(name,str) or not all(x.isidentifier() for x in name.split('.')):raise ValueError('Invalid provider module')
                providers.append(importlib.import_module(name).provider)
            except Exception as error:errors.append(f'{name}: {type(error).__name__}: {error}')
    except Exception as error:errors.append(str(error))
    return tuple(providers),tuple(errors)


class ProfileSession:
    def __init__(self, rom, providers=(), errors=(), capabilities=CAPABILITIES):
        self.provider=None;self.decoder=None;self.error='; '.join(errors);self.ranges=()
        self.rom_hash=hashlib.sha256(rom).hexdigest()
        matches=[]
        for provider in providers:
            try:
                if self.rom_hash not in provider.fingerprints:continue
                if provider.api_version!=API_VERSION or not set(provider.requires)<=capabilities:raise ValueError('Unsupported profile API/capability requirements')
                if not all(isinstance(v,str) and 0<len(v)<=128 for v in (provider.id,provider.version)):raise ValueError('Bounded profile ID/version required')
                ranges=tuple(r.validate() for r in provider.ranges)
                if sum(r.length for r in ranges)>MAX_CAPTURE or len(ranges)>64:raise ValueError('Profile capture budget exceeded')
                matches.append((provider,ranges))
            except Exception as error:self.error=f'{type(error).__name__}: {error}'
        if len(matches)>1:self.error='Ambiguous exact profile providers';return
        if not matches:return
        provider,ranges=matches[0]
        try:self.decoder=provider.create(bytes(rom));self.provider=provider;self.ranges=ranges
        except Exception as error:self.error=f'{type(error).__name__}: {error}'

    @property
    def id(self):return self.provider.id if self.provider else 'generic'

    def decode(self, capture):
        if not self.provider:return {'schema':1,'profile':'generic','fields':[],'error':self.error}
        try:
            if capture.rom_hash!=self.rom_hash:raise ValueError('Capture belongs to another image')
            view=Observation(capture,self.ranges);fields=[];names=set()
            for field in self.decoder.decode(view):
                if len(fields)>=MAX_FIELDS:raise ValueError('Profile field budget exceeded')
                if not isinstance(field,Field):raise ValueError('Profile must return typed fields')
                kind={'integer':int,'string':str,'boolean':bool}.get(field.kind)
                if kind is None or type(field.value) is not kind:raise ValueError('Field type mismatch')
                if not field.name or len(field.name)>128 or field.name in names:raise ValueError('Invalid/duplicate field name')
                if len(str(field.value))>1024 or len(field.note)>1024:raise ValueError('Field text budget exceeded')
                if field.validity not in ('observed','decoded','hypothesis','model','uncertain'):raise ValueError('Unknown evidence validity')
                view.read(field.source)
                names.add(field.name);row=asdict(field)
                row.update(profile=self.provider.id,version=self.provider.version,session=view.context.session,epoch=view.context.epoch,capture=view.context.capture)
                fields.append(row)
            result=dict(schema=1,profile=self.provider.id,version=self.provider.version,rom_hash=self.rom_hash,fields=fields,error='')
            if len(json.dumps(result).encode())>2*1024*1024:raise ValueError('Decoded observation budget exceeded')
            return result
        except Exception as error:
            self.error=f'{type(error).__name__}: {error}'
            return dict(schema=1,profile=self.provider.id,version=self.provider.version,fields=[],error=self.error)

    def legacy_attributes(self, decoded):
        if not self.provider or decoded['error']:return {}
        writer=getattr(self.decoder,'legacy_attributes',None)
        if writer is None:return {}
        # Legacy namespaces explicitly declared by the installed provider; never overwrite core state.
        declared=set(getattr(self.provider,'legacy_attributes',()))
        if not declared <= {'UnitsData','CombatData','BattleVerified'}:raise ValueError('Unsupported legacy compatibility namespace')
        values=writer(decoded)
        if not set(values)<=declared:raise ValueError('Undeclared legacy namespace')
        if any(not isinstance(v,(bytes,bool)) or isinstance(v,bytes) and len(v)>65536 for v in values.values()):raise ValueError('Invalid legacy attribute payload')
        return values


def encode_field_batches(fields,limit=48000):
    """Persist every typed field in bounded JSON arrays, avoiding one DB object per field/stop."""
    batches=[];parts=[];size=2
    for field in fields:
        raw=json.dumps(field,separators=(',',':'),sort_keys=True).encode('utf-8')
        if len(raw)+2>limit:raise ValueError('One typed field exceeds the wire budget')
        if parts and size+len(raw)+1>limit:
            batches.append(b'['+b','.join(parts)+b']');parts=[];size=2
        parts.append(raw);size+=len(raw)+1
    if parts:batches.append(b'['+b','.join(parts)+b']')
    return tuple(batches)
