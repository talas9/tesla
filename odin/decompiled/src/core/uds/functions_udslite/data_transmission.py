# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/uds/functions_udslite/data_transmission.py
from typing import Optional
from odin.core.uds import Node
from odin.core.uds.utils import node_lock
from .udslite import get_udsclient_with_datalink, translate_udslite_exception

@node_lock
@translate_udslite_exception
async def read_data_by_id(node: Node, data_id: int, output_length: Optional[int]) -> bytes:
    client, datalink = get_udsclient_with_datalink(node)
    async with datalink.active():
        payload = await client.read_data(data_id)
        if output_length:
            return payload[:output_length]
        else:
            return payload


@node_lock
@translate_udslite_exception
async def read_memory_by_address(node, memory_address, memory_size):
    client, datalink = get_udsclient_with_datalink(node)
    async with datalink.active():
        return await client.read_memory(memory_address, memory_size)


@node_lock
@translate_udslite_exception
async def write_data_by_id(node: Node, data_id: int, input_payload: Optional[bytes]) -> None:
    client, datalink = get_udsclient_with_datalink(node)
    async with datalink.active():
        await client.write_data(data_id, input_payload or bytes())


@node_lock
@translate_udslite_exception
async def write_memory_by_address(node: Node, memory_address: int, input_payload: Optional[bytes]) -> None:
    client, datalink = get_udsclient_with_datalink(node)
    async with datalink.active():
        await client.write_memory(memory_address, input_payload or bytes())

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/uds/functions_udslite/data_transmission.pyc
