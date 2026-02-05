# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/orchestrator/job.py
import asyncio
from . import monitor, task, tracking, triggers

async def wait_for_dependencies(job_name, uds_dependencies, signal_dependencies, trigger_dependencies, forced_triggers):
    futures = {
     asyncio.ensure_future(_wait_for_regular_dependencies(job_name, uds_dependencies, signal_dependencies, trigger_dependencies))}
    if forced_triggers:
        futures |= {asyncio.ensure_future(_wait_for_forced_triggers(job_name, forced_triggers))}
    try:
        done, pending = await asyncio.wait(futures, return_when=(asyncio.FIRST_COMPLETED))
    finally:
        for f in futures:
            if not f.done():
                f.cancel()

    return any([f.result() is True for f in done])


async def _wait_for_regular_dependencies(job_name, uds_dependencies, signal_dependencies, trigger_dependencies):
    all_signals_reached_target, all_uds_routines_reached_target = await asyncio.gather(wait_for_signals(job_name, signal_dependencies), wait_for_uds(job_name, uds_dependencies))
    if all_signals_reached_target:
        if all_uds_routines_reached_target:
            if trigger_dependencies:
                await wait_for_triggers(job_name, trigger_dependencies)
    return all_signals_reached_target and all_uds_routines_reached_target


async def _wait_for_forced_triggers(job_name: str, forced_triggers: list) -> bool:
    if forced_triggers:
        await triggers.wait_for_any_trigger(forced_triggers)
        tracking.set_job_forcedly_triggered(job_name)
    return True


async def wait_for_triggers(job_name: str, triggers_to_wait_for: list):
    triggers_text = ", ".join(triggers_to_wait_for) if triggers_to_wait_for else "--"
    tracking.set_job_status(job_name, trigger_status=("Waiting for {}".format(triggers_text)))
    await triggers.wait_for_triggers(triggers_to_wait_for)
    tracking.set_job_status(job_name, trigger_status="All triggers set")


async def wait_for_signals(job_name: str, signals: list) -> bool:
    tracking.set_job_status(job_name, signal_status="Waiting for signals")
    all_signal_values_reached = False
    try:
        signal_tasks = []
        for signal in signals:
            signal_tasks.append(_wait_for_signal(job_name, signal.get("name"), signal.get("target_values"), signal.get("required_power_state"), signal.get("timeout"), signal.get("minimum_sample_count", 1)))

        await (asyncio.gather)(*signal_tasks)
    except asyncio.TimeoutError:
        tracking.set_job_status(job_name, signal_status="Fail - Signals timed out")
    except asyncio.CancelledError:
        tracking.set_job_status(job_name, signal_status="Fail - Cancelled error")
        raise
    except Exception:
        tracking.set_job_status(job_name, signal_status="Fail - Exception occurred")
        raise
    else:
        tracking.set_job_status(job_name, signal_status="All signal values reached")
        all_signal_values_reached = True
    return all_signal_values_reached


async def wait_for_uds(job_name: str, uds_polls: list) -> bool:
    tracking.set_job_status(job_name, uds_status="Waiting for uds routines")
    uds_returned_connected = False
    uds_tasks = []
    for polls in uds_polls:
        uds_tasks.append(_wait_for_uds(job_name, polls.get("node_name"), polls.get("component_name"), polls.get("required_power_state"), polls.get("timeout")))

    try:
        await (asyncio.gather)(*uds_tasks)
    except asyncio.TimeoutError:
        tracking.set_job_status(job_name, uds_status="Fail - UDS detection timed out")
    except asyncio.CancelledError:
        tracking.set_job_status(job_name, uds_status="Fail - Cancelled error")
        raise
    except Exception:
        tracking.set_job_status(job_name, uds_status="Fail - Exception occurred")
        raise
    else:
        tracking.set_job_status(job_name, uds_status="All UDS routines returned connected")
        uds_returned_connected = True
    return uds_returned_connected


async def execute_tasks(job_name, context, tasks, execute_concurrently):
    tracking.set_job_status(job_name, tasks_status="Running")
    if execute_concurrently:
        run_tasks_coroutine = _execute_tasks_concurrently(job_name, context, tasks)
    else:
        run_tasks_coroutine = _execute_tasks_sequentially(job_name, context, tasks)
    try:
        all_tasks_succeeded = await run_tasks_coroutine
    except Exception:
        tracking.set_job_status(job_name, tasks_status="Fail - Exception occurred")
        raise

    tracking.set_job_status(job_name, tasks_status=("Success" if all_tasks_succeeded else "Fail"))
    return all_tasks_succeeded


async def _execute_tasks_concurrently(job_name, context, tasks):
    execute_coroutines = [task.execute_task(job_name, context, t) for t in tasks]
    results = await (asyncio.gather)(*execute_coroutines)
    return all(results)


async def _execute_tasks_sequentially(job_name, context, tasks):
    all_tasks_succeeded = True
    for t in tasks:
        successful = await task.execute_task(job_name, context, t)
        if not successful:
            all_tasks_succeeded = False
            if not _continue_on_failure(t):
                break

    return all_tasks_succeeded


async def _wait_for_signal(job_name, signal_name, target_values, required_power_state, timeout, minimum_sample_count):
    tracking.set_signal_status(job_name, signal_name, "Waiting")
    try:
        await monitor.wait_for_signal(signal_name=signal_name, target_values=target_values, required_power_state=required_power_state, timeout=timeout,
          minimum_sample_count=minimum_sample_count)
    except asyncio.TimeoutError:
        tracking.set_signal_status(job_name, signal_name, "Timed out")
        raise
    except asyncio.CancelledError:
        tracking.set_signal_status(job_name, signal_name, "Cancelled error")
        raise
    except Exception:
        tracking.set_signal_status(job_name, signal_name, "Exception occurred")
        raise
    else:
        tracking.set_signal_status(job_name, signal_name, "Target value reached")


async def _wait_for_uds(job_name, node_name, component_name, required_power_state, timeout):
    tracking.set_uds_status(job_name, node_name, component_name, "Waiting")
    try:
        await asyncio.wait_for(monitor.wait_for_uds(node_name=node_name, component_name=component_name, required_power_state=required_power_state),
          timeout=timeout)
    except asyncio.TimeoutError:
        tracking.set_uds_status(job_name, node_name, component_name, "Timed out")
        raise
    except asyncio.CancelledError:
        tracking.set_uds_status(job_name, node_name, component_name, "Cancelled error")
        raise
    except Exception:
        tracking.set_uds_status(job_name, node_name, component_name, "Exception occurred")
        raise
    else:
        tracking.set_uds_status(job_name, node_name, component_name, "UDS component connected")


def _continue_on_failure(task: dict) -> bool:
    return task.get("on_failure") == "CONTINUE"

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/orchestrator/job.pyc
