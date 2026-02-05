# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/uds/functions_odin/input_output_control.py
import struct
from typing import Optional
from odin.core.uds import IoControl, Node, UdsServices
from odin.core.uds.utils import node_lock
from .service import uds_request_response

@node_lock
async def io_control(node: Node, control_id: int, control_type: IoControl, input_payload: Optional[bytes], output_length: Optional[int]) -> bytes:
    payload = await uds_request_response(node=node, sid=(UdsServices.IO_CONTROL),
      sfid=(struct.pack("!HB", control_id, control_type)),
      payload=input_payload,
      expected_payload_size=output_length)
    return payload

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/uds/functions_odin/input_output_control.pyc
