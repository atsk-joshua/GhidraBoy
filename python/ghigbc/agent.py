"""One machine owner and trace writer. Remote dispatch never blocks pause behind run."""
import argparse
from contextlib import contextmanager
from concurrent.futures import Future, ThreadPoolExecutor, TimeoutError
import json
import inspect
import os
from pathlib import Path
from queue import Queue, Empty
import socket
import threading
import time
from ghidratrace.client import Client, MethodRegistry, Address, AddressRange, RegVal, TraceObject
from ghidratrace import sch
from .native import Machine, REASONS, ROOT, CORE, CONFIG, PATCH
from .dispatch import OrderedExecutor

def object_schema(name):
    return type(name,(TraceObject,),{}) if 'extra' in inspect.signature(Client.create_trace).parameters else sch.Schema(name)

THREAD='Machine.Threads[0]'
FRAME=THREAD+'.Stack[0]'
REGISTERS=FRAME+'.Registers'

def space_for(region,bank):return f'{region}{bank}'
def window(region,bank):return {'cpu':0,'rom':0 if bank==0 else 0x4000,'wram':0xc000 if bank==0 else 0xd000,'vram':0x8000,'cart':0xa000,'boot':0,'oam':0xfe00,'hram':0xff80,'io':0xff00}[region]

def physical_writer_address(event):
    writer=event['writer']
    region=('cpu','rom','wram','vram','cart','boot','oam','hram','io','unknown')[writer['region']]
    if region in ('rom','wram','vram','cart','boot'):
        return Address(space_for(region,writer['bank']),window(region,writer['bank'])+writer['offset'])
    return Address('ram',event['writer_pc'])

class Agent:
    def __init__(self,machine):
        from .mapping import EnvelopeTransfer
        self.mapping_transfer=EnvelopeTransfer()
        from .profile import ProfileSession, installed_providers
        providers,errors=installed_providers(ROOT)
        self.profile=ProfileSession(machine.rom_bytes,providers,errors)
        self.machine=machine;self.queue=Queue(maxsize=64);self.executor=OrderedExecutor(self.command_overflow)
        self.registry=MethodRegistry(self.executor);self.trace=None;self.client=None;self.quit=threading.Event();self.last=None;self.exit_at=None;self.static_binding=None;self.last_event_sequence=0;self.objects={};self.remotes()
    def command_overflow(self):
        print('Trace RMI command backlog exceeded; closing this session',flush=True)
        self.quit.set();self.machine.pause()
        if self.client:
            try:self.client.s.shutdown(socket.SHUT_RDWR)
            except OSError:pass

    def remotes(self):
        registry=self.registry
        @registry.method()
        def resume(process:object_schema('Process')):
            self.submit(self.resume)
        @registry.method()
        def interrupt(process:object_schema('Process')):
            self.machine.pause()
        @registry.method()
        def step_into(thread:object_schema('Thread')):
            self.submit(self.step)
        @registry.method()
        def step_over(thread:object_schema('Thread')):
            self.submit(lambda:self.begin_step(2))
        @registry.method()
        def step_out(thread:object_schema('Thread')):
            self.submit(lambda:self.begin_step(3))
        @registry.method(action='break_sw_execute')
        def break_execute(process:object_schema('Process'),address:Address):
            self.submit(lambda:self.add_break(address,1,1))
        @registry.method(action='break_write')
        def break_write(process:object_schema('Process'),range:AddressRange):
            self.submit(lambda:self.add_break(Address(range.space,range.min),4,range.length()))
        @registry.method(action='break_read')
        def break_read(process:object_schema('Process'),range:AddressRange):
            self.submit(lambda:self.add_break(Address(range.space,range.min),2,range.length()))
        @registry.method(action='break_access')
        def break_access(process:object_schema('Process'),range:AddressRange):
            self.submit(lambda:self.add_break(Address(range.space,range.min),6,range.length()))
        @registry.method(action='delete')
        def delete_breakpoint(breakpoint:object_schema('Breakpoint')):
            id=int(breakpoint.path.split('[')[-1][:-1]);self.submit(lambda:self.delete_break(id))
        @registry.method(action='toggle')
        def toggle_breakpoint(breakpoint:object_schema('Breakpoint'),enabled:bool):
            id=int(breakpoint.path.split('[')[-1][:-1])
            def work():
                r,b,o,k,n,_=self.machine.breakpoints[id];self.machine.breakpoint(r,b,o,k,n,id,enabled);self.publish(self.machine.capture())
            self.submit(work)
        @registry.method(action='refresh',display='Read captured registers')
        def refresh_registers(container:object_schema('Registers')):
            # Historical data is already in the trace; never query live hardware for UI refresh.
            pass
        @registry.method()
        def read_mem(process:object_schema('Process'),range:AddressRange):
            # Every supported byte was copied at the stop. Unavailable ranges remain unknown.
            pass
        @registry.method()
        def kill(process:object_schema('Process')):
            self.submit(self.terminate)
        @registry.method(display='Save checkpoint')
        def checkpoint(process:object_schema('Process'),path:str):
            self.submit(lambda:self.machine.checkpoint(path))
        @registry.method(display='Restore checkpoint')
        def restore(process:object_schema('Process'),path:str):
            self.submit(lambda:self.publish(self.machine.restore(path)))
        @registry.method(display='Experiment: edit register')
        def experiment_register(process:object_schema('Process'),register:str,value:int,recovery:str):
            self.submit(lambda:self.publish(self.machine.edit(register=register,value=value,recovery=recovery)))
        @registry.method(display='Experiment: edit WRAM byte')
        def experiment_memory(process:object_schema('Process'),address:int,value:int,recovery:str):
            self.submit(lambda:self.publish(self.machine.edit(address=address,value=value,recovery=recovery)))
        @registry.method(display='Save trace')
        def save_trace(process:object_schema('Process')):
            self.submit(self.save_trace)
        @registry.method(display='Validated physical watch from selected capture')
        def profile_watch(process:object_schema('Process'),region:str,bank:int,offset:int,length:int,expected_session:str,expected_epoch:int,expected_capture:int):
            from .profile import ActionContext
            context=ActionContext(expected_session,expected_epoch,expected_capture)
            def work():
                if self.machine.running:raise RuntimeError('Pause before arming a selected-capture watch')
                self.machine.breakpoint(region,bank,offset,4,length);self.publish(self.machine.capture())
            self.submit(work,context,True)
        @registry.method(display='Receive static mapping snapshot')
        def static_mapping(process:object_schema('Process'),generation:str,index:int,count:int,part:str,expected_session:str,expected_epoch:int):
            def work():
                if self.machine.session!=expected_session or self.last.state['epoch']!=expected_epoch:
                    raise RuntimeError('Stale static binding session/epoch')
                binding=self.mapping_transfer.append(generation,index,count,part,expected_session,expected_epoch,self.machine.rom_hash)
                if binding is not None:self.static_binding=binding
            self.submit(work)
        @registry.method(display='Bank-qualified breakpoint')
        def bank_breakpoint(process:object_schema('Process'),region:str,bank:int,offset:int,kinds:int=1,expected_session:str='',expected_epoch:int=-1,expected_capture:int=-1):
            from .profile import ActionContext
            context=ActionContext(expected_session,expected_epoch,expected_capture) if expected_session else None
            def work():self.machine.breakpoint(region,bank,offset,kinds);self.publish(self.machine.capture())
            self.submit(work,context,context is not None)
    def submit(self,fn,expected=None,selected=False):
        from .profile import ActionContext
        if self.exit_at is not None or self.quit.is_set():raise RuntimeError('Session is terminating/disconnected')
        context=expected or (ActionContext.of(self.last) if self.last else None)
        def checked():
            if self.quit.is_set():raise RuntimeError('Session disconnected')
            if context:context.validate(self.last,selected)
            return fn()
        future=Future();self.queue.put_nowait((checked,future))
        try:return future.result(timeout=30)
        except TimeoutError:
            future.cancel()
            raise

    def obj(self,path,**attrs):
        if path.startswith(('Machine.Events[','Machine.Edits[')):
            # Persistent event history belongs to Ghidra; don't retain unbounded Python proxies.
            o=self.trace.create_object(path);o.insert()
        else:
            if path not in self.objects:
                o=self.trace.create_object(path);o.insert();self.objects[path]=o
            o=self.objects[path]
        for k,v in attrs.items():o.set_value(k,v)
        return o
    def state(self,running):
        value='RUNNING' if running else 'STOPPED'
        self.obj('Machine',_state=value);self.obj(THREAD,_state=value)
    def publish(self,c,removals=()):
        t=self.trace;s=c.state
        with self.transaction('GBC stopped capture'):
            description=f'debugger {c.edit["kind"]} edit' if c.edit else 'running boundary' if self.machine.running else REASONS[s['reason']]
            snap=t.snapshot(f'{description} epoch {s["epoch"]} capture {s["capture_id"]}')
            for removed in removals:removed.remove()
            self.state(self.machine.running)
            self.obj('Machine',ROMHash=c.rom_hash,Session=c.session,Core=CORE,Config=CONFIG,CorePatch=PATCH,Schema=1,TimingUnits='ticks at 8388608 Hz',Profile=self.profile.id,ProfileAPI=1,ProfileVersion=self.profile.provider.version if self.profile.provider else "",Ticks8MHz=s['ticks'],Instructions=s['instructions'],Epoch=s['epoch'],Capture=s['capture_id'],MappingGeneration=s['mapping_generation'],ROM0=s['rom0'],ROMX=s['romx'],WRAM=s['wram'],VRAM=s['vram'],CartBank=s['cart'],CartEnabled=bool(s['cart_enabled']),RTCSelected=bool(s['rtc_selected']),Coverage='CPU-origin accesses; DMA/HDMA watches excluded',MemorySemantics='CPU safe inspection; raw physical RAM banks',Boot=bool(s['boot']),IME=bool(s['ime']),HALT=bool(s['halted']),Speed=2 if s['double_speed'] else 1,StopReason=description,ExperimentMode=self.machine.experiment,ObservationState='RUNNING' if self.machine.running else 'STOPPED',Dropped=s['dropped'])
            if self.static_binding:
                generation,envelope=self.static_binding
                self.obj('Machine',BoundStaticGeneration=generation)
            decoded=self.profile.decode(c)
            # Individual immutable records keep every RMI message below the wire limit.
            self.obj('Machine',ProfileError=decoded['error'],ProfileSchema=1,ProfileEncoding='field-batches-v1',ProfileRecordCount=len(decoded['fields']),MappingSaveBarrier=0)
            from .profile import encode_field_batches
            batches=encode_field_batches(decoded['fields'])
            for index,batch in enumerate(batches):
                self.obj(f'Machine.ProfileFields[{index}]',Data=batch,Snapshot=snap)
            for index in range(len(batches),getattr(self,'field_count',0)):
                stale=self.objects.pop(f'Machine.ProfileFields[{index}]',None)
                if stale:stale.remove()
            self.field_count=len(batches)
            try:
                self.obj('Machine',**self.profile.legacy_attributes(decoded))
            except Exception as error:
                self.obj('Machine',ProfileError=str(error))
            if c.parent_checkpoint:
                parent=c.parent_checkpoint
                self.obj('Machine',ParentCheckpoint=parent['path'],ParentCheckpointSHA256=parent['state_sha256'],CheckpointSourceSession=parent['source_session'],CheckpointSourceEpoch=parent['source_epoch'],CheckpointSourceTicks8MHz=parent['source_ticks'])
            self.obj(FRAME,_pc=Address('ram',s['pc']))
            regvals=[]
            for name in ('AF','BC','DE','HL','SP','PC'):
                value=s[name.lower()];regvals.append(RegVal(name,value.to_bytes(2,'big')))
                self.obj(REGISTERS,**{name:f'0x{value:04x}'})
            missing=t.put_registers(REGISTERS,regvals)
            # Register aliases are also sent to support languages whose pairs are independent.
            aliases={n:s[p.lower()]>>shift&255 for p in ('AF','BC','DE','HL') for n,shift in zip(p,(8,0))}
            t.put_registers(REGISTERS,[RegVal(n,v.to_bytes(1,'big')) for n,v in aliases.items()])
            self.put_bytes(Address('ram',0),c.memory[:65536])
            t.set_memory_state(Address('ram',0xfea0).extend(0x60),'unknown')
            if s['rtc_selected'] or not s['cart_enabled']:t.set_memory_state(Address('ram',0xa000).extend(0x2000),'unknown')
            for region,count in [('wram',8),('vram',2),('cart',s['cart_size']//8192)]:
                for b in range(count):self.put_bank(region,b,c.bank_bytes(region,b))
            for id,(region,b,offset,kinds,length,enabled) in self.machine.breakpoints.items():
                space='ram' if region=='cpu' else space_for(region,b)
                flags=[]
                if kinds&1:flags.append('SW_EXECUTE')
                if kinds&2:flags.append('READ')
                if kinds&4:flags.append('WRITE')
                self.obj(f'Machine.Breakpoints[{id}]',_range=Address(space,window(region,b)+offset).extend(length),_enabled=enabled,_kinds=','.join(flags),_expression=f'{region} bank {b} +0x{offset:x}',Region=region,Bank=b,Offset=offset)
            for e in c.events:
                if e["sequence"]<=self.last_event_sequence:continue
                w=e['writer'];target=e['target']
                region=('cpu','rom','wram','vram','cart','boot','oam','hram','io','unknown')[w['region']]
                writer=physical_writer_address(e)
                self.obj(f'Machine.Events[{e["sequence"]}]',Snapshot=snap,Epoch=s['epoch'],Writer=writer,WriterPC=e['writer_pc'],WriterRegion=region,WriterBank=w['bank'],WriterOffset=w['offset'],TargetRegion=target['region'],TargetBank=target['bank'],TargetOffset=target['offset'],TargetCPU=e['cpu_address'],Bank=target['bank'],Before=e['before'],After=e['after'],Attempt=e['value'],Access=e['access'],Origin='cpu',Precision='attempt + final physical byte at instruction boundary',Valid=bool(e['valid']))
            if c.edit:
                edit=c.edit
                attrs=dict(Snapshot=snap,Epoch=s['epoch'],Capture=s['capture_id'],Origin='debugger',Kind=edit['kind'],
                           Before=edit['before'],After=edit['after'],Requested=edit['requested'],Status=edit['status'],
                           RecoveryCheckpoint=edit['recovery'],RecoverySHA256=edit['recovery_sha256'])
                if edit['register'] is not None:attrs['Register']=edit['register']
                if edit['target'] is not None:
                    target=edit['target']
                    attrs.update(TargetRegion=target['region'],TargetBank=target['bank'],TargetOffset=target['offset'],
                                 TargetCPU=target['cpu_address'],Target=Address(space_for(target['region'],target['bank']),window(target['region'],target['bank'])+target['offset']))
                self.obj(f'Machine.Edits[{edit["id"]}]',**attrs)
            self.obj('Machine',CaptureSnapshot=snap)
            self.objects[''].set_value('_event_thread',self.objects[THREAD]);self.objects[''].set_value('_focus',self.objects[THREAD])
        first_capture=self.last is None
        self.last=c
        self.last_event_sequence=max([self.last_event_sequence]+[e["sequence"] for e in c.events])
        if first_capture:self.objects[THREAD].activate()
    def put_bytes(self,address,data):
        # 12.1 limits an entire protocol message to 65536 bytes; page chunks leave envelope room.
        for offset in range(0,len(data),4096):
            self.trace.put_bytes(Address(address.space,address.offset+offset),data[offset:offset+4096])
    @contextmanager
    def transaction(self,description):
        tx=self.trace.start_tx(description)
        try:
            with self.client.batch():yield
        except BaseException:
            tx.abort();raise
        else:tx.commit()
    def put_bank(self,region,bank,data):
        space=space_for(region,bank);base=window(region,bank)
        self.trace.create_overlay_space('ram',space)
        self.obj(f'Machine.Memory[{space}]',_range=Address(space,base).extend(len(data)),_readable=True,_writable=region!='rom',_executable=region=='rom')
        self.put_bytes(Address(space,base),data)
    def connect(self,address):
        host,port=address.rsplit(':',1)
        if host not in ('127.0.0.1','localhost','::1'):raise ValueError('Only loopback Trace RMI supported')
        sock=socket.create_connection((host,int(port)),timeout=10);sock.settimeout(None)
        self.client=Client(sock,'GBC / SameBoy',self.registry)
        extra={'extra':None} if 'extra' in inspect.signature(self.client.create_trace).parameters else {}
        self.trace=self.client.create_trace('GBC/'+self.machine.rom.stem,'SM83:LE:16:default','default',**extra)
        with self.transaction('Create GBC machine'):
            self.trace.snapshot('initializing')
            root=self.trace.create_root_object(Path(__file__).with_name('schema.xml').read_text(),'Session');self.objects['']=root
            for p in ('Machine','Machine.Threads',THREAD,THREAD+'.Stack',FRAME,REGISTERS,'Machine.Memory','Machine.Breakpoints','Machine.Events','Machine.Edits','Machine.ProfileFields'):self.obj(p)
            self.obj('Machine',_pid=0,_display='GBC / SameBoy');self.obj(THREAD,_tid=0,_display='SM83')
            self.trace.create_overlay_space('register',REGISTERS)
            self.obj('Machine.Memory[cpu]',_range=Address('ram',0).extend(65536),_readable=True,_writable=True,_executable=True)
            for b in range(len(self.machine.rom_bytes)//16384):self.put_bank('rom',b,self.machine.rom_bytes[b*16384:(b+1)*16384])
            self.put_bank('boot',0,self.machine.boot_bytes)
        self.publish(self.machine.capture())
    def resume(self):
        if self.machine.running:return
        self.machine.prepare();self.machine.running=True
        self.play_start=time.monotonic();self.play_ticks=self.machine.lib.gc_ticks(self.machine.handle)
        with self.transaction('Resume GBC'):self.state(True)
    def begin_step(self,mode):
        if self.machine.running:raise RuntimeError('Pause before stepping')
        if self.profile.provider and mode in getattr(self.profile.provider,'unsupported_steps',()):raise RuntimeError('Selected profile does not support this step mode; use Step Into')
        if self.machine.lib.gc_prepare_step(self.machine.handle,mode):raise RuntimeError('No observed ordinary call frame; Step Out unavailable after restore')
        self.machine.running=True;self.play_start=time.monotonic();self.play_ticks=self.machine.lib.gc_ticks(self.machine.handle)
        with self.transaction('Step over/out'):self.state(True)
    def request_terminate(self):
        self.machine.pause()
        future=Future()
        def failed(result):
            if result.exception() is not None:
                print('Session close could not save all evidence:',result.exception(),flush=True)
                self.quit.set()
        future.add_done_callback(failed)
        self.queue.put_nowait((self.terminate,future))
    def save_trace(self):
        # The Java mapping service may briefly hold a transaction after capture publication.
        # Retry only that structured server error, with a finite deadline.
        if getattr(self,'static_binding',None):
            barrier=self.last.state['capture_id']
            with self.transaction('Request completed static mappings before save'):
                self.obj('Machine',MappingSaveBarrier=barrier)
            end=time.monotonic()+10
            while True:
                values=self.trace.get_values('Machine.MappingSaveReady')
                if any(v.value==barrier for v in values):break
                if time.monotonic()>=end:raise RuntimeError('Static mapping save barrier timed out; raw trace remains open')
                time.sleep(.025)
        deadline=time.monotonic()+3
        while True:
            try:return self.trace.save()
            except Exception as error:
                if not any(message in str(error) for message in ('Unable to lock due to active transaction', "Can't save during transaction")) or time.monotonic()>=deadline:raise
                time.sleep(.025)
    def terminate(self):
        self.machine.pause();self.machine.run_slice();self.machine.running=False
        self.publish(self.machine.capture())
        with self.transaction('Terminate GBC session'):
            self.trace.snapshot('Session terminated')
            self.obj('Machine',_state='TERMINATED',Connected=False)
            self.obj(THREAD,_state='TERMINATED')
        self.save_trace()
        # Let the method result reach Ghidra before closing its transport.
        self.exit_at=time.monotonic()+.2
    def step(self):
        if self.machine.running:raise RuntimeError('Pause before stepping')
        self.publish(self.machine.step())
    def translate(self,address):
        if address.space=='ram':
            s=self.last.state;a=address.offset
            if a<0x8000:
                if s['boot'] and (a<0x100 or 0x200<=a<0x900):return 'boot',0,a
                return 'rom',s['rom0'] if a<0x4000 else s['romx'],a%16384
            if 0xc000<=a<0xfe00:
                if a>=0xe000:a-=0x2000
                return 'wram',0 if a<0xd000 else s['wram'],a%4096
            if 0x8000<=a<0xa000:return 'vram',s['vram'],a-0x8000
            if 0xa000<=a<0xc000 and not s['rtc_selected']:return 'cart',s['cart'],a-0xa000
            raise ValueError('Use explicit physical breakpoint for this region')
        for region in ('rom','wram','vram','cart','boot'):
            if address.space.startswith(region):
                b=int(address.space[len(region):]);return region,b,address.offset-window(region,b)
        raise ValueError('Unknown trace address space')
    def add_break(self,address,kinds,length):
        r,b,o=self.translate(address);self.machine.breakpoint(r,b,o,kinds,length);self.publish(self.machine.capture())
    def delete_break(self,id):
        self.machine.remove(id)
        obj=self.objects.pop(f'Machine.Breakpoints[{id}]',None)
        self.publish(self.machine.capture(),removals=[obj] if obj else [])
    def work(self,address):
        try:
            self.connect(address)
            while not self.quit.is_set() and self.client.receiver.is_alive():
                if self.exit_at is not None and time.monotonic()>=self.exit_at:break
                try:
                    fn,future=self.queue.get(timeout=0 if self.machine.running else .02)
                except Empty:pass
                else:
                    if future.set_running_or_notify_cancel():
                        try:future.set_result(fn())
                        except BaseException as e:future.set_exception(e)
                if self.machine.running:
                    reason=self.machine.run_slice()
                    # Keep play close to the emulated 8 MHz clock; at most 4 ms between pause checks.
                    if not reason:
                        ticks=self.machine.lib.gc_ticks(self.machine.handle)
                        delay=(ticks-self.play_ticks)/8388608-(time.monotonic()-self.play_start)
                        if delay>0:time.sleep(min(delay,.004))
                    if reason:
                        self.machine.running=False;self.publish(self.machine.capture())
        except Exception:
            import traceback;traceback.print_exc()
        finally:
            self.machine.pause();self.machine.running=False;self.quit.set()
            if self.client:
                try:self.client.s.shutdown(socket.SHUT_RDWR)
                except OSError:pass
                self.client.close()
            while True:
                try:_,pending=self.queue.get_nowait()
                except Empty:break
                pending.cancel()
            self.executor.shutdown(wait=False,cancel_futures=True)

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--connect',default=os.environ.get('GHIDRA_TRACE_RMI_ADDR'));parser.add_argument('--rom',required=True);parser.add_argument('--display',action='store_true');parser.add_argument('--fixture-ready',action='store_true');parser.add_argument('--experiment',action='store_true')
    args=parser.parse_args()
    with Machine(args.rom,experiment=args.experiment) as m:
        if args.fixture_ready:
            m.breakpoint('rom',1,0x29);m.prepare()
            for _ in range(5000):
                if m.run_slice():break
        agent=Agent(m);worker=threading.Thread(target=agent.work,args=(args.connect,),name='machine-owner');worker.start()
        try:
            if args.display:
                from .display import run
                run(m,agent.quit,on_close=agent.request_terminate)
            else:
                while not agent.quit.wait(.1):pass
        except KeyboardInterrupt:agent.quit.set();m.pause()
        finally:
            agent.quit.set();m.pause()
            # Closing transport unblocks a trace writer before the machine can be destroyed.
            if worker.is_alive() and agent.client:
                try:agent.client.s.shutdown(socket.SHUT_RDWR)
                except OSError:pass
            worker.join(timeout=5)
            if worker.is_alive():
                # Retain the owned machine until its worker exits; never free under native execution.
                worker.join()
if __name__=='__main__':main()
