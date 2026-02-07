# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/platforms/gen3/nodes/vehiclecontrols.py
import asyncio, logging
from typing import Union
from architect import Node, Input, Output, Signal, slot
from architect.core.exceptions import RERAISE_EXCEPTIONS
from odin.core import odx
from odin.core import power
from odin.core import uds
from odin.exceptions import OdinException
from ..enum import PowerStateEnum
log = logging.getLogger(__name__)
POWER_STATE_ENUM = [(power_state.name, power_state.name) for power_state in PowerStateEnum]

class EnsurePowerState(Node):
    power_state = Input("String", enum=POWER_STATE_ENUM, default="ACCESSORY_PLUS")
    request_retries = Input("Int", default=30)
    timeout = Input("Int", default=100)
    response = Output("Dict")
    done = Signal()

    @slot()
    async def run(self) -> None:
        power_state, timeout, request_retries = await asyncio.gather(self.power_state(), self.timeout(), self.request_retries())
        diagnostic_session = "EXTENDED_DIAGNOSTIC_SESSION"
        uds_node_name = "VCFRONT"
        poll_interval = 0.1
        uds_node = uds.nodes[uds_node_name]
        odx_routine_name = "SELF_TEST_POWER"
        start_parameters = {'SELF_TEST_MODE':power_state,  'TIMEOUT':timeout}
        odx_routine_spec = uds_node.get_odx_routine_spec(odx_routine_name)
        await uds.diagnostic_session(uds_node, uds.SessionType[diagnostic_session])
        await odx.security_access(uds_node, odx_routine_spec["start"])
        start_results, _ = await (odx.start_routine)(odx_routine_spec, **start_parameters)
        start_results = dict(start_results)
        self.response.value = start_results
        if "SELF_TEST_STATE" in odx_routine_spec["results"]["output"]:
            if start_results["START_RESULT"] != "SUCCESSFUL":
                await self.done()
                return
            await asyncio.sleep(poll_interval)
            request_results, _ = await odx.request_results(odx_routine_spec)
            request_results = dict(request_results)
            retries = 0
            while request_results["SELF_TEST_STATE"] != power_state and retries < request_retries:
                request_results, _ = await odx.request_results(odx_routine_spec)
                request_results = dict(request_results)
                await asyncio.sleep(poll_interval)
                retries += 1

            if retries >= request_retries:
                self.response.value = request_results
        if power_state == "CONTACTORS_OPEN":
            power_state_enum = power.interface.power_state_enum()(power_state)
            if not await power.interface.ensure_signal_on_can(power_state_enum):
                self.response.value.update({"CONTACTORS_OPEN": "FALSE"})
        await self.done()


class PowerContext(Node):
    power_state = Input("String", enum=POWER_STATE_ENUM, default="ACCESSORY_PLUS")
    allow_higher = Input("Bool", default=True)
    body = Signal()
    done = Signal()
    failure = Signal()
    results = Output("String")

    @slot()
    async def run(self) -> None:
        power_state_enum = power.interface.power_state_enum()(await self.power_state())
        try:
            async with power.power_context(power_state_enum, await self.allow_higher()):
                await self.body()
        except RERAISE_EXCEPTIONS:
            raise
        except (power.PowerStateTimeout, OdinException) as e:
            await self.set_failure(e)
        except Exception as e:
            log.exception("Unexpected failure in PowerContext")
            await self.set_failure(e)
        else:
            self.results.value = ""
            await self.done()

    async def set_failure(self, value: Union[(Exception, str)]):
        self.results.value = value if value else ""
        await self.failure()


class GetCurrentPowerState(Node):
    power_state = Output("String")
    done = Signal()

    @slot()
    async def get(self):
        curr_state = power.interface.get_current_held_power_state()
        self.power_state.value = curr_state.value if curr_state in PowerStateEnum else ""
        await self.done()

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/platforms/gen3/nodes/vehiclecontrols.pyc
