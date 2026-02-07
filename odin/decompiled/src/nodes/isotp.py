# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/nodes/isotp.py
import asyncio
from architect.core.node import Node
from architect.core.ops.input import Input
from architect.core.ops.output import Output
from architect.core.ops.signal import Signal
from architect.core.ops.slot import slot
from odin.core import can
from odin.core import isotp

class Send(Node):
    to_controller = Input("Int")
    from_controller = Input("Int")
    data = Input("Bytes")
    success = Output()
    done = Signal()

    def __init__(self, *args, **kw):
        (super().__init__)(*args, **kw)
        self.to_id = None
        self.from_id = None

    @slot()
    async def transmit(self):
        self.to_id, self.from_id, data = await asyncio.gather(self.to_controller(), self.from_controller(), self.data())
        handle = isotp.get_service_handle(self.to_id, self.from_id, can.Bus.ETH)
        async with handle.listening():
            self.success.value = await handle.tx(data)
        await self.done()


class Listen(Node):
    active = Input("Bool")
    to_controller = Input("Int")
    from_controller = Input("Int")
    timeout = Input("Int")
    data = Output("Bytes")

    def __init__(self, *args, **kw):
        (super().__init__)(*args, **kw)
        self.to_id = None
        self.from_id = None

    @slot()
    async def start(self):
        self.to_id, self.from_id, timeout = await asyncio.gather(self.to_controller(), self.from_controller(), self.timeout())
        handle = isotp.get_service_handle(self.to_id, self.from_id, can.Bus.ETH)
        async with handle.listening():
            try:
                self.data.value = await asyncio.wait_for(handle.wait_for_data(), timeout)
            except asyncio.TimeoutError:
                pass

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/nodes/isotp.pyc
