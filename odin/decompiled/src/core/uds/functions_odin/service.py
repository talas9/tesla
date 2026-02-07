# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/uds/functions_odin/service.py
import logging
from binascii import hexlify
from typing import Optional
from odin.core import isotp
from odin.core.uds import UdsServices, UdsEcuErrorRegistry, UdsException, UdsEcuError, SidMismatch, SubFuncMismatch, RequestCorrectlyReceivedResponsePending
from odin.core.isotp.error import ISOTPError
from ..datatypes.udstypes import UDS_SUPPRESS_POS_RESP_MASK
from ..node import Node
log = logging.getLogger(__name__)

async def uds_request_response(node: Node, sid: UdsServices, sfid: Optional[bytes]=None, payload: Optional[bytes]=None, expected_payload_size: Optional[int]=None, response_required: bool=True, block_size: int=0, separation_time: int=10) -> bytes:

    async def parse_response(resp):
        log.debug("UDS received 0x{}".format(resp.hex()))
        try:
            if resp[0] == 127:
                if resp[1] == sid:
                    raise UdsEcuErrorRegistry.get(256 | resp[2], UdsEcuError)()
            elif resp[0] != sid + 64:
                raise SidMismatch()
            elif sfid is not None:
                pass
            if resp[1:1 + len(sfid)] != sfid:
                raise SubFuncMismatch()
            else:
                if expected_payload_size is not None:
                    if expected_payload_size != len(resp) - response_header_size:
                        log.debug("UDS Response had invalid payload size: Node={}(0x{:x}, 0x{:x}), sid={}:0x{:x}, sfid={} payload={} expected_payload_size:{} response_required:{} response:{}".format(node.name, node.request_message["message_id"], node.response_message["message_id"], sid.name, sid.value, sfid, payload, expected_payload_size, response_required, resp[response_header_size:]))
                        return resp[response_header_size:]
                    else:
                        log.debug("UDS Response: Node={}(0x{:x}, 0x{:x}), sid={}:0x{:x}, sfid={} payload={} expected_payload_size:{} response_required:{} response:{}".format(node.name, node.request_message["message_id"], node.response_message["message_id"], sid.name, sid.value, sfid if sfid is None else hexlify(sfid).upper(), payload if payload is None else hexlify(payload).upper(), expected_payload_size, response_required, resp[response_header_size:]))
                        return resp[response_header_size:]
        except (RequestCorrectlyReceivedResponsePending, SidMismatch, SubFuncMismatch) as err:
            extended_time = isotp.UDS_SERVER_ENHANCED_RESPONSE_TIME
            log.info("Ignoring UDS sequence error: {}, wait {} more seconds".format(err, extended_time))
            resp = await transport.request((bytearray()), response_required, timeout=extended_time)
            return await parse_response(resp)

    log.debug("UDS Request: Node={}(0x{:x}, 0x{:x}), sid={}:0x{:x}, sfid={} payload={} expected_payload_size:{} response_required:{} node_locked:{}".format(node.name, node.request_message["message_id"], node.response_message["message_id"], sid.name, sid.value, sfid if sfid is None else hexlify(sfid).upper(), payload if payload is None else hexlify(payload).upper(), expected_payload_size, response_required, node.lock.locked()))
    transport = isotp.get_service_handle(tx_id=(node.request_message.message_id), rx_id=(node.response_message.message_id),
      padding_byte=85,
      target_bus=(node.bus),
      block_size=block_size,
      separation_time=separation_time)
    buf = bytearray([sid])
    if sfid is not None:
        buf += sfid
        buf[1] = buf[1] | (0 if response_required else UDS_SUPPRESS_POS_RESP_MASK)
    response_header_size = len(buf)
    if payload is not None:
        buf += payload
    async with transport.datalink.active(response_required=response_required):
        try:
            response = await transport.request(buf, response_required)
        except ISOTPError as e:
            e.ecu_name = node.name
            raise e

        if response:
            try:
                parsed_response = await parse_response(response)
            except UdsException as e:
                e.ecu_name = node.name
                raise e

            return parsed_response
        else:
            log.debug("UDS No Response: Node={}(0x{:x}, 0x{:x}), sid={}:0x{:x}, sfid={} payload={} expected_payload_size:{} response_required:{}".format(node.name, node.request_message["message_id"], node.response_message["message_id"], sid.name, sid.value, sfid, payload, expected_payload_size, response_required))
            return bytes()

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/uds/functions_odin/service.pyc
