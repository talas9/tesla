# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/utils/context.py
import asyncio, logging
from typing import Any, Callable, Optional, AsyncContextManager
from asyncio_extras import async_contextmanager
from odin.core.utils.schedule import schedule
log = logging.getLogger(__name__)

@async_contextmanager
async def optional_context(condition: bool, context_manager: Callable[([Any], AsyncContextManager)], kw=None):
    if condition:
        if kw is None:
            kw = {}
        async with context_manager(**kw) as ctx:
            yield ctx
    else:
        yield


@async_contextmanager
async def periodic_context(periodic_func: Callable, init_func: Optional[Callable]=None, cleanup_function: Optional[Callable]=None, interval: float=1.0, initial_sleep: float=0):
    if init_func:
        await init_func()
    task = schedule(periodic_func, interval=interval, initial_sleep=initial_sleep)
    try:
        yield task
    finally:
        task.cancelled() or task.cancel()
        await asyncio.sleep(0)
        try:
            task_exc = task.exception()
        except (asyncio.CancelledError, asyncio.InvalidStateError):
            pass
        else:
            raise task_exc
        if cleanup_function:
            await asyncio.sleep(interval)
            await cleanup_function()

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/utils/context.pyc
