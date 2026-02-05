# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/utils/schedule.py
import asyncio, logging
from typing import Callable, Dict, Iterable, Optional
log = logging.getLogger(__name__)

def schedule(func: Callable, args: Optional[Iterable]=None, kwargs: Optional[Dict]=None, interval: float=1.0, initial_sleep: float=0) -> asyncio.Task:
    if args is None:
        args = []
    if kwargs is None:
        kwargs = {}

    async def periodic_func():
        self = asyncio.Task.current_task()
        if self is not None:
            if not self.done():
                if initial_sleep > 0:
                    await asyncio.sleep(initial_sleep)
            while not self.done():
                await func(*args, **kwargs)
                await asyncio.sleep(interval)

    return asyncio.ensure_future(periodic_func())

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/utils/schedule.pyc
