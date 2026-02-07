# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/orchestrator/power.py
import asyncio, logging, time
from asyncio_extras import async_contextmanager
from collections import OrderedDict
from enum import EnumMeta
from typing import Optional
from odin.core import power
from odin.core.can import messagemonitor
from odin.core.cid.interface import request_do_not_sleep
from . import helpers, settings
log = logging.getLogger(__name__)
_LOOP_DEFAULT_SLEEP_TIME = 5.0
_MAX_KEEP_ALIVE_PERIOD = 30.0
_DI_STATUS_SIGNAL = "DI_gear"
_DI_STATUS_VALID_VALUES = [None, 'DI_GEAR_P', 'DI_GEAR_N', 'DI_GEAR_INVALID', 'DI_GEAR_SNA']
_requested_power_state_counter = None
_should_hold_event = asyncio.Event()
_last_sleep_reset_time = None
_power_hold_loop_future = None

@async_contextmanager
async def periodic_power_state_context(power_state: EnumMeta):
    if not _is_managed_active_states(power_state):
        log.debug("Ignoring power state request: Orchestrator not interested in power state {}".format(power_state.value))
        yield
        return
    if not settings.power_management_enabled():
        log.debug("Ignoring power state request: power management is disabled")
        yield
        return
    _start_requesting_power_state(power_state)
    try:
        yield
    finally:
        _stop_requesting_power_state(power_state)


def _dec_power_state_counter(power_state: EnumMeta):
    counter = _get_power_state_counter()
    if power_state in counter:
        counter[power_state] -= 1
        if counter[power_state] < 0:
            counter[power_state] = 0


def _get_power_state_counter() -> OrderedDict:
    global _requested_power_state_counter
    if _requested_power_state_counter is None:
        _requested_power_state_counter = OrderedDict((ps, 0) for ps in power.interface.power_state_active_order)
    return _requested_power_state_counter


def _inc_power_state_counter(power_state: EnumMeta):
    counter = _get_power_state_counter()
    if power_state in counter:
        counter[power_state] += 1


def _is_managed_active_states(power_state: EnumMeta) -> bool:
    return power_state in _get_power_state_counter()


def _start_requesting_power_state(power_state: EnumMeta):
    global _power_hold_loop_future
    global _should_hold_event
    _inc_power_state_counter(power_state)
    _should_hold_event.set()
    if not isinstance(_power_hold_loop_future, asyncio.Task) or _power_hold_loop_future.done():
        _power_hold_loop_future = asyncio.ensure_future(_power_hold_loop())


def _stop_requesting_power_state(power_state: EnumMeta):
    _dec_power_state_counter(power_state)
    if _get_maximum_requested_power_state() is None:
        log.debug("Done holding power state")
        _should_hold_event.clear()


def _get_maximum_requested_power_state() -> Optional[EnumMeta]:
    for power_state, number_of_requesters in _get_power_state_counter().items():
        if number_of_requesters > 0:
            return power_state

    return


async def reset_vehicle_keep_alive():
    global _last_sleep_reset_time
    current_time = time.time()
    if _last_sleep_reset_time is not None:
        if current_time - _last_sleep_reset_time < _MAX_KEEP_ALIVE_PERIOD:
            return
    _last_sleep_reset_time = current_time
    keep_alive_minutes = settings.power_management_keep_alive_minutes()
    log.debug("Resetting sleep timer: requesting {} minutes".format(keep_alive_minutes))
    await request_do_not_sleep(keep_alive_minutes)


async def _temporarily_set_power_state(target_power_state: EnumMeta, seconds_to_hold: float):
    if _is_managed_active_states(target_power_state):
        async with power.power_context(target_power_state):
            log.debug("Holding power state for {} seconds: {}".format(seconds_to_hold, target_power_state.value))
            await asyncio.sleep(seconds_to_hold)
    else:
        log.warning("Hold event was set, but invalid target power state provided: {}".format(target_power_state.value))
        _should_hold_event.clear()


async def _hold_power_state():
    di_monitor = messagemonitor.get_monitor_for_signal(_DI_STATUS_SIGNAL)
    seconds_to_hold = settings.power_management_hold_time()
    seconds_between_holds = settings.power_management_seconds_between_holds()
    await _should_hold_event.wait()
    await di_monitor.wait_for_target(_DI_STATUS_SIGNAL, _DI_STATUS_VALID_VALUES)
    if _should_hold_event.is_set():
        target_power_state = _get_maximum_requested_power_state()
        await _temporarily_set_power_state(target_power_state, seconds_to_hold)
        await asyncio.sleep(seconds_between_holds)


async def _power_hold_loop():
    while True:
        try:
            if await helpers.vehicle_keep_alive_status():
                await _hold_power_state()
            else:
                await asyncio.sleep(_LOOP_DEFAULT_SLEEP_TIME)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("Exception in power hold loop")
            await asyncio.sleep(_LOOP_DEFAULT_SLEEP_TIME)

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/orchestrator/power.pyc
