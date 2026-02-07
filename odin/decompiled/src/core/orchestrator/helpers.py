# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/orchestrator/helpers.py
import time, logging
from asyncio import gather
from datetime import datetime
from typing import Optional, Set, Tuple
from odin.core.engine.handlers import utils
from odin.core.engine.handlers.message_handler import EngineMessageHandler
from . import memory, runner, scheduler, settings
from odin.core.cid.interface import get_data_value
log = logging.getLogger(__name__)
_message_handler: EngineMessageHandler = None
_KEEP_ALIVE_ACTIVE_DATAVALUE = "VAPI_keepAliveActive"
_KEEP_ALIVE_EXPIRATION_DATAVALUE = "VAPI_keepAliveExpiration"
_last_keep_alive_value = None

def get_message_handler() -> Optional[EngineMessageHandler]:
    if isinstance(_message_handler, EngineMessageHandler):
        return _message_handler
    else:
        return


async def _attempt_execute_task(task_name: str, task_args: dict) -> dict:
    safe_to_run_exception = await scheduler.network_is_safe_to_run_exception(task_name)
    if safe_to_run_exception is not None:
        raise safe_to_run_exception
    execution_options = {"message_handler": (get_message_handler())}
    return await utils.execute_with_reporting(get_message_handler(), execution_options, task_name, task_args)


async def execute_task(task_name: str, task_args: Optional[dict]=None, pause_orchestrator: bool=True) -> Tuple[(bool, dict)]:
    if not isinstance(task_args, dict):
        task_args = {}
    elif pause_orchestrator:
        async with runner.pause_orchestrator():
            task_results = await _attempt_execute_task(task_name, task_args)
    else:
        task_results = await _attempt_execute_task(task_name, task_args)
    successful = utils.reporting.check_successful_results(task_results)
    return (successful, task_results)


async def get_task_result(job_name: str, task_name: str) -> Optional[dict]:
    return await memory.get_task_result(job_name, task_name)


async def get_fused_jobs_tasks(jobs_file: str) -> Set[str]:
    jobs_file = await settings.load_fused_jobs(jobs_file)
    tasks = set()
    for j in jobs_file.values():
        tasks.update({t["task"] for t in j["tasks"]})

    return tasks


async def vehicle_keep_alive_status() -> bool:
    global _last_keep_alive_value
    if _last_keep_alive_value is not None:
        if time.time() < _last_keep_alive_value:
            return True
    active_raw, expiration_raw = await gather(get_data_value(_KEEP_ALIVE_ACTIVE_DATAVALUE), get_data_value(_KEEP_ALIVE_EXPIRATION_DATAVALUE))
    active = active_raw == "true"
    _last_keep_alive_value = datetime.strptime(expiration_raw, "%c").timestamp() if active else None
    return active

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/orchestrator/helpers.pyc
