# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/orchestrator/task.py
import asyncio, datetime
from enum import Enum
import logging
from typing import Dict, List, Optional
from architect.core.exceptions import RERAISE_EXCEPTIONS
from odin.core.gateway.gtw_config import assert_gtw_config_match, GatewayConfigMismatch, GatewayConfigKeyUndefined
from odin.core.engine.handlers import reporting, utils
from odin.core.utils import locks
from . import memory, power, scheduler, tracking
log = logging.getLogger(__name__)

class RerunEnum(Enum):
    ALWAYS = "ALWAYS"
    NEVER = "NEVER"
    ON_SUCCESS = "ON_SUCCESS"
    ON_FAILURE = "ON_FAILURE"


async def execute_task(job_name, context, task):
    task_name = task.get("task")
    task_args = task.get("args", {})
    lock_name = task.get("lock")
    valid_gtw_configs = task.get("gtw_config_qualifiers", {})
    rerun_option = RerunEnum(task.get("rerun", RerunEnum.ON_FAILURE))
    results = await memory.get_task_result(job_name, task_name)
    if not _should_run_task(results, rerun_option):
        task_successful = reporting.check_successful_results(results)
        _mark_task_results(job_name, context, task_name, task_successful)
        return task_successful
    if not await _is_gtw_qualifier_matching(job_name, task_name, valid_gtw_configs):
        return True
    else:
        try:
            results = await _schedule_and_execute(job_name, context, task_name, task_args, lock_name)
        except RERAISE_EXCEPTIONS as e:
            tracking.set_task_status(job_name, task_name, "Re-raise exception: {}".format(e))
            raise
        except Exception as e:
            log.exception("Exception while executing task: {}".format(task_name))
            tracking.set_task_status(job_name, task_name, "Exception: {}".format(e))
            results = {"error": (repr(e))}

        task_successful = reporting.check_successful_results(results)
        task_status = "Success" if task_successful else "Fail"
        tracking.set_task_status(job_name, task_name, task_status)
        asyncio.ensure_future(asyncio.gather(memory.set_task_result(job_name, task_name, results), power.reset_vehicle_keep_alive()))
        return task_successful


def _should_run_task(task_results: Optional[dict], rerun_option: RerunEnum) -> bool:
    if rerun_option == RerunEnum.ALWAYS:
        return True
    else:
        if task_results is None:
            return True
        else:
            if rerun_option == RerunEnum.NEVER:
                return False
            task_succeeded = reporting.check_successful_results(task_results)
            if rerun_option == RerunEnum.ON_SUCCESS:
                return task_succeeded
            if rerun_option == RerunEnum.ON_FAILURE:
                return not task_succeeded
        return True


def _mark_task_results(job_name, context, task_name, mark_success):
    execution_options = context.get("execution_options")
    message_handler = execution_options.get("message_handler") if isinstance(execution_options, dict) else None
    now = datetime.datetime.now()
    history_status = "PASS" if mark_success else "FAIL"
    task_status = "Success (skipped)" if mark_success else "Fail (skipped)"
    tracking.set_task_status(job_name, task_name, task_status)
    reporting.report_history(message_handler, test=task_name,
      started_time=now,
      finished_time=now,
      status=history_status,
      connectors=[])


async def _schedule_and_execute(job_name, context, task_name, task_args, lock_name):
    execution_options = context.get("execution_options")
    message_handler = execution_options.get("message_handler") if isinstance(execution_options, dict) else None
    lock = locks.get_lock(context, lock_name) if lock_name else None
    tracking.set_task_status(job_name, task_name, "Scheduling execution")
    async with scheduler.schedule_task(lock, task_name):
        tracking.set_task_status(job_name, task_name, "Running")
        return await utils.execute_with_reporting(message_handler, execution_options, task_name, task_args)


async def _is_gtw_qualifier_matching(job_name: str, task_name: str, valid_gtw_configs: Dict[(str, List[str])]) -> bool:
    is_match = False
    try:
        await assert_gtw_config_match(valid_gtw_configs)
    except asyncio.TimeoutError:
        tracking.set_task_status(job_name, task_name, "Fail - Get vitals timed out")
    except GatewayConfigKeyUndefined as err:
        tracking.set_task_status(job_name, task_name, "Fail - Gateway config key error")
        tracking.log_task_error(job_name, task_name, repr(err))
    except GatewayConfigMismatch as err:
        tracking.set_task_status(job_name, task_name, "Success (skipped: Gateway config mismatch)")
        tracking.log_task_debug(job_name, task_name, repr(err))
    else:
        is_match = True
    return is_match

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/orchestrator/task.pyc
