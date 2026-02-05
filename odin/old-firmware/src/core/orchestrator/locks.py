# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/orchestrator/locks.py
import asyncio
from collections import defaultdict, Callable
from functools import wraps
import time
from typing import Optional
from odin.core.utils.singleton import make_singleton_getter
from odin.core.utils.locks import CountLock
get_execute_lock = make_singleton_getter(CountLock)
get_job_lock = make_singleton_getter(CountLock)
_method_locks = defaultdict(asyncio.Lock)
_method_events = {}
_method_cache = {}

def method_lock(key: Optional[str]=None) -> Callable:

    def wrapper(method):

        @wraps(method)
        async def locked_request(*args, **kwargs):
            global _method_locks
            lock = _method_locks[key] if key else _method_locks[method]
            async with lock:
                return await method(*args, **kwargs)

        return locked_request

    return wrapper


def timed_cache(interval: float) -> Callable:

    def wrapper(method):

        @wraps(method)
        async def async_wrapper(*args, **kwargs):
            global _method_cache
            global _method_events
            event = _method_events.get(method)
            if event:
                await event.wait()
            else:
                event = asyncio.Event()
                _method_events[method] = event
            t, cached_value = _method_cache.get(method, (0, None))
            if time.time() - t < interval:
                return cached_value
            event.clear()
            try:
                new_value = await method(*args, **kwargs)
                _method_cache[method] = (time.time(), new_value)
                return new_value
            finally:
                event.set()

        return async_wrapper

    return wrapper

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/orchestrator/locks.pyc
