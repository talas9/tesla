# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/nodes/rules.py
import logging
from architect.core.node import Node
from architect.core.ops.input import Input
from architect.core.ops.output import output
import asyncio, re
log = logging.getLogger(__name__)

class TestKeyCompatibility(Node):
    rules = Input("List")
    country = Input("String")
    euVehicle = Input("Bool")
    partNumber = Input("String")

    @output("Bool")
    async def Compatability(self):
        rules, country, euVehicle, partNumber = await asyncio.gather(self.rules(), self.country(), self.euVehicle(), self.partNumber())
        for rule in rules:
            country = country.lower()
            if rule["code"] == "country":
                if rule["option"] == country:
                    return re.match(rule["part_number"], partNumber, re.IGNORECASE)
            else:
                if rule["code"] == "euVehicle":
                    if rule["option"] == euVehicle:
                        return re.match(rule["part_number"], partNumber, re.IGNORECASE)

        return False

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/nodes/rules.pyc
