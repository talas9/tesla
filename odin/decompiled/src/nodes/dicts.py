# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/nodes/dicts.py
from asyncio import gather
from architect.core.node import Node
from architect.core.ops.input import Input
from architect.core.ops.output import output

class FromInputs(Node):
    a = Input()
    b = Input()
    c = Input()
    d = Input()
    e = Input()
    f = Input()
    g = Input()
    h = Input()
    i = Input()
    j = Input()
    k = Input()

    @output("Dict")
    async def out(self):
        inputs = [self.a, self.b, self.c, self.d, self.e, self.f, self.g,
         self.h, self.i, self.j, self.k]
        results = await gather(self.a(), self.b(), self.c(), self.d(), self.e(), self.f(), self.g(), self.h(), self.i(), self.j(), self.k())
        d = {i.connection._parent._name if i.connection else "unknown_{}".format(x): r for x, (i, r) in enumerate(zip(inputs, results)) if i is not None}
        return d

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/nodes/dicts.pyc
