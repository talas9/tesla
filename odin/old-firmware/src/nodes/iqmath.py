# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/nodes/iqmath.py
import asyncio
from odin.core.utils import iqmath
from architect.core.node import Node
from architect.core.ops.input import Input
from architect.core.ops.output import output

class FromIQ(Node):
    number = Input("Int")
    m = Input("Int")
    n = Input("Int")

    @output("Float")
    async def result(self):
        number, m, n = await asyncio.gather(self.number(), self.m(), self.n())
        return iqmath.from_iq(int(number), m, n)


class FromIQ28(Node):
    number = Input("Int")
    base = Input("Float")
    offset = Input("Int", default=0)

    @output("Float")
    async def result(self):
        number, base, offset = await asyncio.gather(self.number(), self.base(), self.offset())
        return iqmath.from_iq28(number, base, offset=offset)


class ToIQ(Node):
    number = Input("Float")
    m = Input("Int")
    n = Input("Int")
    signed = Input("Bool", default=False)

    @output("Int")
    async def result(self):
        number, m, n, signed = await asyncio.gather(self.number(), self.m(), self.n(), self.signed())
        return iqmath.to_iq(number, m, n, signed=signed)


class ToIQ28(Node):
    number = Input("Float")
    base = Input("Float")
    offset = Input("Int", default=0)
    signed = Input("Bool", default=False)

    @output("Int")
    async def result(self):
        number, base, offset, signed = await asyncio.gather(self.number(), self.base(), self.offset(), self.signed())
        return iqmath.to_iq28(number, base, offset, signed=signed)

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/nodes/iqmath.pyc
