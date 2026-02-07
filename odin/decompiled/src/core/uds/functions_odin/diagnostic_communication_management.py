# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/uds/functions_odin/diagnostic_communication_management.py
import struct
from typing import Optional
from odin.core.uds import UdsServices, Node, DTCSettingType, SessionType, SecurityLevel, Reset
from odin.core.uds.utils import node_lock
from .service import uds_request_response

@node_lock
async def control_dtc_setting(node: Node, setting_type: DTCSettingType, input_payload: Optional[bytes], response_required: bool=True) -> None:
    await uds_request_response(node=node, sid=(UdsServices.CONTROL_DTC_SETTING),
      sfid=(struct.pack("!B", setting_type)),
      payload=input_payload,
      response_required=response_required)


@node_lock
async def diagnostic_session(node, session_type=SessionType.DEFAULT_SESSION, response_required=True):
    if session_type != SessionType.NO_SESSION:
        await uds_request_response(node=node, sid=(UdsServices.DIAGNOSTIC_SESSION_CONTROL),
          sfid=(struct.pack("!B", session_type)),
          response_required=response_required)


@node_lock
async def ecu_reset(node, reset_type=Reset.HARD_RESET, response_required=False):
    await uds_request_response(node=node, sid=(UdsServices.ECU_RESET),
      sfid=(struct.pack("!B", reset_type)),
      response_required=response_required)


@node_lock
async def security_access(node: Node, security_level: SecurityLevel) -> None:
    payload = await uds_request_response(node=node, sid=(UdsServices.SECURITY_ACCESS),
      sfid=(struct.pack("!B", security_level)))
    if all(b == 0 for b in payload):
        return
    security_key = node.get_key(payload)
    await uds_request_response(node=node, sid=(UdsServices.SECURITY_ACCESS),
      sfid=(struct.pack("!B", security_level + 1)),
      payload=security_key)


@node_lock
async def tester_present(node: Node, response_required: bool=False) -> None:
    await uds_request_response(node=node, sid=(UdsServices.TESTER_PRESENT),
      sfid=b'\x00',
      response_required=response_required)

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/uds/functions_odin/diagnostic_communication_management.pyc
