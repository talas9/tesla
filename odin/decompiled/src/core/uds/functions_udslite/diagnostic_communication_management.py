# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/uds/functions_udslite/diagnostic_communication_management.py
import logging
from typing import Optional
from odin.core.uds import DTCSettingType, Node, Reset, SecurityLevel, SessionType
from odin.core.uds.utils import node_lock
from udslite import UDSDTCControlType, UDSSessionType, UDSECUResetType
from udslite import SecurityLevelAlreadyUnlocked
from .udslite import get_udsclient_with_datalink, translate_udslite_exception
log = logging.getLogger(__name__)

@node_lock
@translate_udslite_exception
async def control_dtc_setting(node: Node, setting_type: DTCSettingType, input_payload: Optional[bytes], response_required: bool=True) -> None:
    client, datalink = get_udsclient_with_datalink(node)
    async with datalink.active():
        await client.control_dtc_setting(UDSDTCControlType(setting_type), input_payload, response_required)


@node_lock
@translate_udslite_exception
async def diagnostic_session(node, session_type=SessionType.DEFAULT_SESSION, response_required=True):
    if session_type != SessionType.NO_SESSION:
        client, datalink = get_udsclient_with_datalink(node)
        async with datalink.active():
            await client.session_control(UDSSessionType(session_type), response_required)


@node_lock
@translate_udslite_exception
async def ecu_reset(node, reset_type=Reset.HARD_RESET, response_required=False):
    client, datalink = get_udsclient_with_datalink(node)
    async with datalink.active():
        await client.ecu_reset(UDSECUResetType(reset_type), response_required)


@node_lock
@translate_udslite_exception
async def security_access(node: Node, security_level: SecurityLevel) -> None:
    client, datalink = get_udsclient_with_datalink(node)
    async with datalink.active():
        try:
            seed = await client.security_access_request_seed(security_level)
        except SecurityLevelAlreadyUnlocked:
            log.info("UDS SecurityLevelAlreadyUnlocked")
        else:
            key = node.get_key(seed)
            await client.security_access_send_key(security_level, key)


@node_lock
@translate_udslite_exception
async def tester_present(node: Node, response_required: bool=False) -> None:
    client, datalink = get_udsclient_with_datalink(node)
    async with datalink.active():
        await client.tester_present(response_required)

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/uds/functions_udslite/diagnostic_communication_management.pyc
