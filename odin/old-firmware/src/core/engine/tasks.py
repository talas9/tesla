# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/engine/tasks.py
import asyncio, logging
from typing import List
from odin.core.utils.singleton import make_singleton_getter
from .security_context import make_security_context
from .handlers.utils import get_platform_tasks
from .handlers import commands
from . import security
from . import task_metadata
import odin.languages
task_data_cache = None
lock = make_singleton_getter(asyncio.Lock)
log = logging.getLogger(__name__)

async def filter_tasks(context, vehicle_context, user_context):
    all_task = await get_task_data()
    return await _permitted_tasks(all_task, context, vehicle_context, user_context)


def clear_task_data():
    global task_data_cache
    task_data_cache = None


async def get_task_data(boot: bool=False) -> List[dict]:
    global lock
    global task_data_cache
    if task_data_cache is not None:
        return task_data_cache
    else:
        if lock().locked():
            log.warning("Waiting for task data to be computed")
        async with lock():
            if task_data_cache:
                return task_data_cache
            await odin.languages.init_language()
            await asyncio.sleep(3 if boot else 0)
            log.debug("About to compute task data")
            task_names = await get_platform_tasks()
            task_data_cache = await [await asyncio.ensure_future(task_metadata.get_task_definition(task)) for task in task_names]
            log.debug("Task data is cached")
        return task_data_cache


async def _permitted_tasks(task_data: List[dict], context: dict, vehicle_context: dict, user_context: dict) -> List[dict]:
    permitted = []
    for task in task_data:
        if await _task_is_permitted(context, task["message"]["args"]["name"], vehicle_context, user_context):
            permitted.append(task)
        await asyncio.sleep(0)

    return permitted


async def _task_is_permitted(context, name, vehicle_context=None, user_context=None):
    task_context = {**context, **{"network_name": name}}
    security_context = await make_security_context(task_context,
      (commands.execute), vehicle_context=vehicle_context, user_context=user_context)
    return security.execute_check(security_context) is None

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/engine/tasks.pyc
