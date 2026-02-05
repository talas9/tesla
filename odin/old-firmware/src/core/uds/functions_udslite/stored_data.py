# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/uds/functions_udslite/stored_data.py
from typing import Dict
from odin.core.uds import Node
from odin.core.uds.utils import node_lock
from .udslite import get_udsclient_with_datalink, translate_udslite_exception

@node_lock
@translate_udslite_exception
async def clear_diagnostic_information(node: Node) -> None:
    client, datalink = get_udsclient_with_datalink(node)
    async with datalink.active():
        await client.clear_dtc(16777215)


@node_lock
@translate_udslite_exception
async def read_dtcs(node: Node, dtc_mask: int=255) -> Dict:
    client, datalink = get_udsclient_with_datalink(node)
    async with datalink.active():
        payload = await client.read_dtc(dtc_mask)
        return {"DTC_{:02X}".format(x.dtc): x.status for x in payload.records}

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/uds/functions_udslite/stored_data.pyc
