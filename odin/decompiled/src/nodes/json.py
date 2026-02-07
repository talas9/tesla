# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/nodes/json.py
import json
from architect.core.node import Node
from architect.core.ops.input import Input
from architect.core.ops.output import output

class Loads(Node):
    string = Input("String")

    @output("Dict")
    async def json(self):
        string = await self.string()
        return json.loads(string)


class Dumps(Node):
    json = Input("Dict")
    indent = Input("Int", default=None)
    separators = Input("List", default=None)

    @output("String")
    async def string(self):
        _json = await self.json()
        _indent = await self.indent()
        _separators = await self.separators()
        return json.dumps(_json, indent=_indent, separators=_separators)

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/nodes/json.pyc
