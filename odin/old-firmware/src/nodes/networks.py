# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/nodes/networks.py
import asyncio
from architect.nodes import Input, Node, Output, Signal, slot
from odin.core.engine.handlers import utils

class DynamicallyReferencedSubnetwork(Node):
    _register_with_name = "networks.DynamicallyReferencedSubnetwork"
    name = Input("String")
    args = Input("Dict", default={})
    results = Output("Dict")
    done = Signal()

    @slot()
    async def run(self):
        name, args = await asyncio.gather(self.name(), self.args())
        execution_options = self._root()._context().get("execution_options")
        message_handler = execution_options.get("message_handler")
        self.results.value = await utils.execute_with_reporting(message_handler, execution_options, name, args)
        await self.done()

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/nodes/networks.pyc
