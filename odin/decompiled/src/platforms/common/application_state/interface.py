# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/platforms/common/application_state/interface.py
import asyncio, logging
from odin.core import uds
import odin.core.utils.context
from odin.core.isotp import ISOTPError
log = logging.getLogger(__name__)

async def activate_application_state(node_name, requested_state, initial_backoff=0.25, bootloader_backoff=2, **kw):
    node = uds.nodes[node_name]
    async with odin.core.utils.context.optional_context((True if requested_state == "BOOTLOADER" else False),
      (uds.tester_present_context),
      kw={'uds_node_name':node_name,  'interval':0.01}):
        backoff = initial_backoff
        while 1:
            try:
                try:
                    current_state = await _test_application_state(node)
                except uds.exceptions.SidMismatch:
                    log.error("Received SID mismatch while testing application state. Assuming it was ECU reset response and retrying request.")
                    current_state = await _test_application_state(node)

                log.info("ECU State: {}".format(current_state))
                if current_state == requested_state:
                    return True
                if current_state == "BOOTLOADER":
                    backoff = bootloader_backoff
            except (uds.exceptions.UdsTransportError, ISOTPError):
                log.exception("UDS Transport Error, retrying.")
            except uds.exceptions.UdsEcuError:
                log.exception("UDS read data service not supported, test will proceed after default_wait.")
                return False

            if requested_state == "BOOTLOADER":
                try:
                    await uds.ecu_reset(node, response_required=False)
                except (uds.exceptions.UdsTransportError, ISOTPError):
                    log.exception("ECU reset failed, retrying.")

                await asyncio.sleep(backoff)


async def _test_application_state(node_id: uds.Node) -> str:
    application_state_data = await uds.read_data_by_id(node_id, 257, 3)
    try:
        state_byte = application_state_data[-2]
    except TypeError:
        return "UNKNOWN"
    else:
        if state_byte == 0:
            return "APPLICATION"
        else:
            if state_byte == 1:
                return "BOOTLOADER"
            if state_byte == 2:
                return "BOOTUPDATER"

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/platforms/common/application_state/interface.pyc
