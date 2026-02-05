# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/orchestrator/scheduler.py
import asyncio, logging
from typing import Optional
from asyncio_extras import async_contextmanager
from odin.core.engine import safety
from . import locks
log = logging.getLogger(__name__)
_MAX_SAFETY_CHECK_FREQUENCY = 1

@async_contextmanager
async def schedule_task(lock: Optional[asyncio.Lock], network_name: str):
    await acquire_locks(network_name, lock)
    try:
        yield
    finally:
        release_locks(lock)


async def acquire_locks(network_name: str, lock: Optional[asyncio.Lock]):
    while True:
        await _acquire_locks(lock)
        try:
            safe_to_execute = await _network_is_safe_to_run(network_name)
        except Exception:
            release_locks(lock)
            raise

        if safe_to_execute:
            break
        release_locks(lock)
        await asyncio.sleep(_MAX_SAFETY_CHECK_FREQUENCY)


def release_locks(lock: Optional[asyncio.Lock]):
    if isinstance(lock, asyncio.Lock):
        if lock.locked():
            lock.release()
        else:
            log.warning("Attempted to release an un-acquired lock")
    locks.get_job_lock().decrement()


async def _acquire_locks(lock: Optional[asyncio.Lock]):
    lock_provided = isinstance(lock, asyncio.Lock)
    if lock_provided:
        await lock.acquire()
    try:
        await locks.get_execute_lock().wait()
        locks.get_job_lock().increment()
    except Exception:
        if lock_provided:
            lock.release()
        log.exception("Error acquiring locks")
        raise


async def network_is_safe_to_run_exception(network_name: str) -> Optional[Exception]:
    safety_context = await safety.make_safety_context({"network_name": network_name})
    exception = safety.vehicle_state_allowed(safety_context)
    return exception


async def _network_is_safe_to_run(network_name: str) -> bool:
    return await network_is_safe_to_run_exception(network_name) is None

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/orchestrator/scheduler.pyc
