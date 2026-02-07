# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/utils/desync.py
import asyncio, concurrent.futures
from typing import Any, Callable
from odin.config import options
executor = None

def get_thread_pool():
    global executor
    if executor is None:
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=(options.get("core", {}).get("max_workers_thread_pool", None)))
    return executor


async def desync(sync_func: Callable, *args) -> Any:
    return await (asyncio.get_event_loop().run_in_executor)(get_thread_pool(), sync_func, *args)

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/utils/desync.pyc
