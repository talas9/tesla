# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/nodes/cidupdater.py
import asyncio
from architect.core.node import Node
from architect.core.ops.input import Input
from architect.core.ops.output import Output
from architect.core.ops.signal import Signal
from architect.core.ops.slot import slot
from odin.core.cid import updater

class Command(Node):
    timeout = Input("Int", default=120)
    command = Input("String")
    response = Output("String")
    done = Signal()

    @slot()
    async def send(self):
        timeout, command = await asyncio.gather(self.timeout(), self.command())
        self.response.value = await updater.run_command(command, timeout=timeout)
        await self.done()


class TerminateUpdateJob(Node):
    report_hammered = Input("Bool", default=False)
    timeout = Input("Int", default=120)
    done = Signal()

    @slot()
    async def terminate(self):
        timeout = await self.timeout()
        results = await asyncio.wait_for(updater.terminate_job(report_hammered=(await self.report_hammered())), timeout=timeout)
        if results.get("exit_status") != 0:
            raise RuntimeError("Failed to terminate ice-updater: {}".format(results))
        else:
            await self.done()


class ReadFirmwareSignature(Node):
    response = Output("Dict")
    done = Signal()

    @slot()
    async def run(self):
        self.response = await updater.read_signature()
        await self.done()

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/nodes/cidupdater.pyc
