# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/nodes/proto.py
import aiofiles, logging, os
from architect.core.node import Node
from architect.core.ops.input import Input
from architect.core.ops.output import Output, output
from architect.core.ops.signal import Signal
from architect.core.ops.slot import slot
import asyncio
from odin.core.utils import png, security
log = logging.getLogger(__name__)

class SplitThree(Node):
    task1 = Signal()
    task2 = Signal()
    task3 = Signal()

    @slot()
    async def start(self):
        await asyncio.gather(self.task1(), self.task2(), self.task3())


class ReadFile(Node):
    filepath = Input("String")
    mode = Input("String")
    contents = Output()
    done = Signal()

    @slot()
    async def read(self):
        filepath, mode = await asyncio.gather(self.filepath(), self.mode())
        if security.file_blacklisted(filepath):
            raise PermissionError("Not allowed to access file {}".format(filepath))
        async with aiofiles.open(filepath, mode) as fp:
            self.contents.value = await fp.read()
        await self.done()


class SaveImage(Node):
    filepath = Input("String")
    raw_bytes = Input("Bytes")
    done = Signal()

    @slot()
    async def save(self):
        filepath, raw_bytes = await asyncio.gather(self.filepath(), self.raw_bytes())
        img = png.uint8ToRGB(raw_bytes, 3840, 2892)
        if security.file_blacklisted(filepath):
            raise PermissionError("Not allowed to access file {}".format(filepath))
        if not os.path.exists(os.path.dirname(filepath)):
            os.makedirs(os.path.dirname(filepath))
        img.save(filepath)
        await self.done()

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/nodes/proto.pyc
