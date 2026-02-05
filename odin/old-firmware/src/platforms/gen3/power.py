# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/platforms/gen3/power.py
import asyncio, logging
from asyncio_extras import async_contextmanager
from enum import EnumMeta
from typing import Dict
from odin.core import odx
from odin.core import uds
from odin.core.uds.exceptions import TimeoutBs02
from odin.core.power.abstract import AbstractPowerInterface
from odin.exceptions import OdinException
from .enum import PowerStateEnum, POWER_SIGNAL_MAP
log = logging.getLogger(__name__)

class Gen3Power(AbstractPowerInterface):

    def __init__(self):
        super().__init__()
        self.power_state_active_order = [
         PowerStateEnum.ACCESSORY_PLUS,
         PowerStateEnum.ACCESSORY]
        self.power_state_hierarchy = {(PowerStateEnum.ACCESSORY): (PowerStateEnum.ACCESSORY_PLUS)}
        self.power_state_timeout = 6

    def power_signal_map(self, power_state: EnumMeta) -> Dict:
        return POWER_SIGNAL_MAP.get(power_state) or {}

    def power_state_enum(self) -> EnumMeta:
        return PowerStateEnum

    async def start_power_state(self, power_state: EnumMeta):
        start_and_confirm_tries = 4
        request_retries = 4
        diagnostic_session = "EXTENDED_DIAGNOSTIC_SESSION"
        uds_node_name = "VCFRONT"
        interval = 5
        timeout = interval * 2
        uds_node = uds.nodes[uds_node_name]
        odx_routine_name = "SELF_TEST_POWER"
        start_parameters = {'SELF_TEST_MODE':power_state.value,  'TIMEOUT':timeout}
        odx_routine_spec = uds_node.get_odx_routine_spec(odx_routine_name)
        odx_routine_spec["node_name"] = uds_node_name

        async def start_and_confirm():
            await uds.diagnostic_session(uds_node, uds.SessionType[diagnostic_session])
            await odx.security_access(uds_node, odx_routine_spec["start"])
            start_results, _ = await (odx.start_routine)(odx_routine_spec, **start_parameters)
            start_results = dict(start_results)
            if start_results["START_RESULT"] != "SUCCESSFUL":
                raise OdinException("Could not set vehicle power state")
            for retries in range(request_retries):
                request_results, _ = await odx.request_results(odx_routine_spec)
                request_results = dict(request_results)
                if request_results["SELF_TEST_STATE"] == power_state.value:
                    break
                else:
                    await asyncio.sleep(0.1)
            else:
                raise OdinException("Could not get vehicle power state")

            if power_state == PowerStateEnum.CONTACTORS_OPEN:
                if not await self.ensure_signal_on_can(power_state):
                    raise OdinException("Contactors have not opened")

        last_error = None
        seconds_to_sleep = 0.5
        for j in range(start_and_confirm_tries):
            if j > 0:
                await asyncio.sleep(seconds_to_sleep)
            try:
                await start_and_confirm()
            except TimeoutBs02 as e:
                log.debug("Attempt {} - Timed out to set the power state to {}".format(j, power_state))
                last_error = e
                seconds_to_sleep = 0.001
            except (OdinException, uds.UdsException) as e:
                log.debug("Attempt {} - Failed to set the power state to {}".format(j, power_state))
                last_error = e
                seconds_to_sleep = 1.0
            else:
                return

        if last_error:
            self.exceptions.add(str("{}: {}".format(type(last_error).__name__, last_error)))

    async def verify_power_state(self, power_state: EnumMeta):
        uds_node_name = "VCFRONT"
        uds_node = uds.nodes[uds_node_name]
        odx_routine_name = "SELF_TEST_POWER"
        odx_routine_spec = uds_node.get_odx_routine_spec(odx_routine_name)
        try:
            request_results, _ = await odx.request_results(odx_routine_spec)
            request_results = dict(request_results)
            if request_results["SELF_TEST_STATE"] != power_state.value:
                raise OdinException("Lost power state: {}".format(request_results["SELF_TEST_STATE"]))
            if power_state == PowerStateEnum.CONTACTORS_OPEN:
                if not await self.ensure_signal_on_can(power_state):
                    raise OdinException("Contactors have not opened")
        except (OdinException, uds.UdsException) as e:
            log.error("Failed verifying the power state {}".format(power_state))
            self.exceptions.add(str("{}: {}".format(type(e).__name__, e)))

    @async_contextmanager
    async def hold_power_context_mgr(self, *args, **kwargs):
        async with uds.tester_present_context("VCFRONT"):
            yield

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/platforms/gen3/power.pyc
