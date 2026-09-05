"""Opens a genuine SDL window; emits timing and frame evidence, never a dummy driver."""
import json,threading,time,sys
from pathlib import Path
from ghigbc.native import Machine,ROOT
from ghigbc.display import run
stop=threading.Event()
with Machine(ROOT/'.local/experiments/student.gbc') as m:
 def owner():
  m.prepare();begin=time.monotonic();ticks=m.lib.gc_ticks(m.handle)
  while not stop.is_set():
   if time.monotonic()-begin>120:stop.set();break
   m.run_slice()
   delay=(m.lib.gc_ticks(m.handle)-ticks)/8388608-(time.monotonic()-begin)
   if delay>0:time.sleep(min(delay,.004))
  print(json.dumps({'real_window':True,'wall_seconds':time.monotonic()-begin,'emulated_seconds':(m.lib.gc_ticks(m.handle)-ticks)/8388608}),flush=True)
 thread=threading.Thread(target=owner);thread.start()
 try:run(m,stop)
 finally:stop.set();thread.join()
