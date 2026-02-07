# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/uds/functions_odin/upload_download.py
import asyncio, logging, struct
from typing import Optional
from odin.core.isotp.error import ISOTPTimeoutError
from odin.core.uds import UdsServices, Node
from odin.core.uds.utils import node_lock
from .service import uds_request_response
log = logging.getLogger(__name__)

async def data_upload(node, memory_address, memory_size, data_format_identifier=0, length_memory_size_and_address=68):
    req_resp = await request_data_upload(node, memory_address, memory_size, data_format_identifier, length_memory_size_and_address)

    async def transfer_data_ignore_timeout(block_sequence_counter):
        counter = 0
        while True:
            try:
                response = await transfer_data(node, block_sequence_counter)
                return response
            except ISOTPTimeoutError:
                log.exception("Timed out attempting to transfer data, attempt {}".format(counter))
                counter += 1

    data = bytearray()
    block_sequence_counter = 1
    while len(data) < memory_size:
        resp_block = await asyncio.wait_for((transfer_data_ignore_timeout(block_sequence_counter)), timeout=5)
        data += resp_block
        block_sequence_counter += 1

    await request_transfer_exit(node)
    return data


@node_lock
async def request_data_upload(node, memory_address, memory_size, data_format_identifier=0, length_memory_size_and_address=68):
    payload = struct.pack("!BBII", data_format_identifier, length_memory_size_and_address, memory_address, memory_size)
    resp = await uds_request_response(node=node, sid=(UdsServices.DATA_UPLOAD),
      payload=payload,
      block_size=1)
    return resp


@node_lock
async def transfer_data(node: Node, block_sequence_counter: int, transfer_request_parameter_record: Optional[bytes]=None) -> bytes:
    payload = struct.pack("!B", block_sequence_counter)
    if transfer_request_parameter_record is not None:
        payload += transfer_request_parameter_record
    resp = await uds_request_response(node=node, sid=(UdsServices.TRANSFER_DATA),
      sfid=payload)
    return resp


@node_lock
async def request_transfer_exit(node: Node, transfer_request_parameter_record: Optional[bytes]=b'') -> bytes:
    resp = await uds_request_response(node=node, sid=(UdsServices.TRANSFER_EXIT),
      payload=transfer_request_parameter_record)
    return resp

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/uds/functions_odin/upload_download.pyc
