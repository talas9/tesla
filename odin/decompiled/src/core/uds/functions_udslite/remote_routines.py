# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/uds/functions_udslite/remote_routines.py
from typing import Optional
from odin.core.uds import Node, RoutineControl
from odin.core.uds.utils import node_lock
from .udslite import get_udsclient_with_datalink, translate_udslite_exception

@node_lock
@translate_udslite_exception
async def routine_control(node: Node, routine_id: int, routine_type: RoutineControl, input_payload: Optional[bytes], output_length: Optional[int]) -> bytes:
    client, datalink = get_udsclient_with_datalink(node)
    async with datalink.active():
        payload = await client.routine_control(routine_id, routine_type, input_payload or bytes())
        if output_length:
            return payload[:output_length]
        else:
            return payload

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/uds/functions_udslite/remote_routines.pyc
