# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/nodes/apupdater.py
import asyncio, odin.core.cid
from architect.core.node import Node
from architect.core.ops.input import Input
from architect.core.ops.output import Output
from architect.core.ops.signal import Signal
from architect.core.ops.slot import slot
from odin.core.ap import updater

class Command(Node):
    timeout = Input("Int", default=120)
    command = Input("String")
    ap_b = Input("Bool", default=False)
    response = Output("String")
    done = Signal()

    @slot()
    async def send(self):
        timeout, command, ap_b = await asyncio.gather(self.timeout(), self.command(), self.ap_b())
        self.response.value = await updater.run_command(command, timeout=timeout, ap_b=ap_b)
        await self.done()


class ClearCache(Node):
    successful = Output("Bool")
    error = Output("String")
    done = Signal()

    @slot()
    async def run(self):
        result = await odin.core.cid.interface.exec_command([
         "/bin/rm", "-rf", "/home/cid-updater/ape-cache.ssq", "/home/cid-updater/ape.ssq"],
          user="root")
        if result["exit_status"] == 0:
            self.successful.value = True
        else:
            self.successful.value = False
            self.error.value = result["stderr"]
        await self.done()


class ReadDasASignature(Node):
    response = Output("Dict")
    done = Signal()

    @slot()
    async def run(self):
        self.response = await updater.read_signature()
        await self.done()


class ReadTurboBSignature(Node):
    response = Output("Dict")
    done = Signal()

    @slot()
    async def run(self):
        self.response = await updater.read_signature_turbo_b()
        await self.done()

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/nodes/apupdater.pyc
