"""Trace RMI replies have FIFO correlation, so callbacks must complete in request order."""
from concurrent.futures import ThreadPoolExecutor
from threading import BoundedSemaphore


class OrderedExecutor(ThreadPoolExecutor):
    def __init__(self,on_overflow,capacity=64):
        super().__init__(max_workers=1,thread_name_prefix='rmi-ordered')
        self.slots=BoundedSemaphore(capacity)
        self.on_overflow=on_overflow

    def submit(self,fn,*args,**kwargs):
        # Never block the protocol receiver waiting for space: it must continue servicing replies.
        if not self.slots.acquire(blocking=False):
            self.on_overflow()
            raise RuntimeError('Trace RMI command backlog exceeded; disconnecting to preserve reply ordering')
        try:future=super().submit(fn,*args,**kwargs)
        except BaseException:
            self.slots.release();raise
        future.add_done_callback(lambda _:self.slots.release())
        return future
