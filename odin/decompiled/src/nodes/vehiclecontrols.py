# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/nodes/vehiclecontrols.py
import asyncio, logging
from time import time
from architect.core.node import Node
from architect.core.ops.input import Input
from architect.core.ops.output import Output
from architect.core.ops.signal import Signal
from architect.core.ops.slot import slot
from odin.core import cid
from odin.core import uds
from odin.platforms.common.application_state.application_state import get_current_application_state, application_state_context
log = logging.getLogger(__name__)
APPLICATION_STATE_ENUM = [
 ('APPLICATION', 'APPLICATION'), ('BOOTLOADER', 'BOOTLOADER')]

class EnsureApplicationState(Node):
    application_state = Input("String", enum=APPLICATION_STATE_ENUM,
      default="APPLICATION")
    timeout = Input("Float", default=5)
    default_wait = Input("Float", default=0.5)
    initial_backoff = Input("Float", default=0.25)
    bootloader_backoff = Input("Float", default=2)
    done = Signal()
    node_name = Input("String", enum_func=(lambda: [('', '')] + [))

    @slot()
    async def run(self):
        desired_application_state, timeout, node_name, default_wait, initial_backoff, bootloader_backoff = await asyncio.gather(self.application_state(), self.timeout(), self.node_name(), self.default_wait(), self.initial_backoff(), self.bootloader_backoff())
        guid = self.get_network_guid()
        try:
            async with application_state_context(guid, node_name, desired_application_state, initial_backoff, bootloader_backoff, timeout) as state_achieved:
                if not state_achieved:
                    if default_wait:
                        await asyncio.sleep(default_wait)
                await self.done()
        except asyncio.TimeoutError:
            msg = "Timed out waiting for ECU to enter desired {} state".format(desired_application_state)
            current = get_current_application_state(node_name)
            if current is not None:
                msg += ", currently held in {}".format(current)
            raise RuntimeError(msg)

    def get_network_guid(self):
        return self._root().context_vars["run_id"]


class McuScreenOn(Node):
    wait = Input("Bool", default=True)
    on = Output("Bool")
    done = Signal()

    @slot()
    async def turnScreenOn(self):
        wait = await self.wait()
        on = False
        t = int(time()) - 10
        result = await cid.interface.set_data_value("GUI_lastTouchTime", t)
        if not wait:
            if not result:
                raise Exception("Failed to reset touch time")
        loop = asyncio.get_event_loop()
        end_time = loop.time() + 1
        while True:
            if await cid.interface.get_data_value("CD_displayState") != 0:
                on = True
                break
            if loop.time() + 0.1 >= end_time:
                break
            await asyncio.sleep(0.1)

        self.on.value = on
        await self.done()

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/nodes/vehiclecontrols.pyc
