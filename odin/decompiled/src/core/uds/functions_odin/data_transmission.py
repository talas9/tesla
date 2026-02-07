# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/uds/functions_odin/data_transmission.py
import struct
from typing import Optional
from odin.core.uds import UdsServices, Node
from odin.core.uds.utils import node_lock
from .service import uds_request_response

@node_lock
async def read_data_by_id(node: Node, data_id: int, output_length: Optional[int]) -> bytes:
    payload = await uds_request_response(node=node, sid=(UdsServices.READ_DATA_BY_ID),
      sfid=(struct.pack("!H", data_id)))
    return payload


@node_lock
async def read_memory_by_address(node, memory_address, memory_size):
    payload = await uds_request_response(node=node, sid=(UdsServices.READ_MEMORY_BY_ADDR),
      sfid=(struct.pack("!H", memory_address)),
      expected_payload_size=memory_size)
    return payload


@node_lock
async def write_data_by_id(node: Node, data_id: int, input_payload: Optional[bytes]) -> None:
    await uds_request_response(node=node, sid=(UdsServices.WRITE_DATA_BY_ID),
      sfid=(struct.pack("!H", data_id)),
      payload=input_payload)


@node_lock
async def write_memory_by_address(node: Node, memory_address: int, input_payload: Optional[bytes]):
    await uds_request_response(node=node, sid=(UdsServices.WRITE_MEMORY_BY_ADDR),
      sfid=(struct.pack("!H", memory_address)),
      payload=input_payload)

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/uds/functions_odin/data_transmission.pyc
