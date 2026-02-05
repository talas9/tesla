# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/orchestrator/monitor.py
import asyncio, logging
from odin.core import power as core_power
from odin.core.can import messagemonitor
from odin.nodes.odx import OdxStartRoutine
from . import helpers, power
log = logging.getLogger(__name__)
_UDS_POLL_KEEP_ALIVE_CHECK_SLEEP_TIME = 5.0
_UDS_POLL_LOOP_SLEEP_TIME = 1.0
_ODX_POLLABLE_ENDPOINT_ROUTINE_NAME = "CHECK_CONNECTED_ENDPOINTS"

def handle_vehicle_power(func):

    async def wrapper(*args, **kwargs):
        asyncio.ensure_future(power.reset_vehicle_keep_alive())
        try:
            power_state = core_power.interface.power_state_enum()(kwargs.get("required_power_state"))
        except ValueError:
            power_state = None

        if power_state is None:
            await func(*args, **kwargs)
        else:
            async with power.periodic_power_state_context(power_state):
                await func(*args, **kwargs)
        asyncio.ensure_future(power.reset_vehicle_keep_alive())

    return wrapper


@handle_vehicle_power
async def wait_for_signal(*, signal_name, target_values, required_power_state, timeout=0, minimum_sample_count=1):
    signal_monitor = messagemonitor.get_monitor_for_signal(signal_name)
    await signal_monitor.wait_for_target(signal_name, target_values, timeout=timeout, minimum_sample_count=minimum_sample_count)


@handle_vehicle_power
async def wait_for_uds(*, node_name: str, component_name: str, required_power_state: str):

    def component_is_connected(results):
        if results is None:
            return False
        else:
            if results["START_RESULT"] != "SUCCESSFUL":
                log.error(f'STATUS of ODX {_ODX_POLLABLE_ENDPOINT_ROUTINE_NAME} on {node_name} start routine response is {results["STATUS"]}')
                return False
            if component_name not in results:
                raise ValueError(f"{component_name} not found in ODX {_ODX_POLLABLE_ENDPOINT_ROUTINE_NAME} on {node_name} start routine response. Supported components: {results.keys()}")
            else:
                return results[component_name] == "CONNECTED"

    odx_check_endpoint_poll = OdxStartRoutine(node_name=node_name, routine_name=_ODX_POLLABLE_ENDPOINT_ROUTINE_NAME)
    log.debug(f"Start checking component {component_name} on {node_name}")
    while not component_is_connected(odx_check_endpoint_poll.results.value):
        if await helpers.vehicle_keep_alive_status():
            log.debug(f"Check component {component_name} on {node_name}")
            await odx_check_endpoint_poll.run()
            log.debug(f"Check component {component_name} on {node_name}. Result: {odx_check_endpoint_poll.results.value}")
            await asyncio.sleep(_UDS_POLL_LOOP_SLEEP_TIME)
        else:
            log.debug(f"Not polling for {component_name} on {node_name} because keep alive expired")
            await asyncio.sleep(_UDS_POLL_KEEP_ALIVE_CHECK_SLEEP_TIME)

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/orchestrator/monitor.pyc
