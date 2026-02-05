# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/nodes/testing.py
from architect import Node, Input, output

class PingOutcome(Node):
    outcome = Input("String", enum=[('pass', 'pass'), ('fail', 'fail'), ('error', 'error')])

    @output("Int")
    async def result(self):
        outcome = await self.outcome()
        if outcome == "pass":
            return 0
        if outcome == "fail":
            return 1
        raise RuntimeError("error outcome")

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/nodes/testing.pyc
