# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/platforms/common/canapi2.py
import asyncio, canapi2, logging
from canbase import CanFrame, utils
from enum import IntEnum
from typing import Optional, Union
from odin.core.gateway.abstract import AbstractGateway
from odin.core.gateway.exceptions import MessageIDOutOfRange
from odin.core.isotp.constants import UDS_SERVER_ENHANCED_RESPONSE_TIME
from odin.core.isotp.constants import N_BS_TIMEOUT
log = logging.getLogger(__name__)

class Canapi2Gateway(AbstractGateway):

    def __init__(self):
        super().__init__()
        link_class = utils.available_links()["canapi2"]
        self.pcanlink = link_class("python")
        self.pcanlink.open()

    async def monitor_message(self, bus: IntEnum, message_id: int, is_uds_message: bool=False, slots: int=1, enabled: bool=True) -> Optional[int]:
        return

    async def read_message_impl(self, bus: IntEnum, message_id: int, timeout: Union[(float, None)]=1.0, is_uds_message: bool=False, uid: Optional[int]=None) -> bytes:

        async def _next_message():
            while 1:
                msg = self.pcanlink._read(N_BS_TIMEOUT)
                if msg.id == message_id:
                    return bytes(msg.data)

        return await asyncio.wait_for((_next_message()), timeout=(timeout or UDS_SERVER_ENHANCED_RESPONSE_TIME))

    async def send_message_impl(self, bus_id, message_id, data):

        async def send_payload(payload):
            msg = CanFrame(ident=message_id, length=(len(payload)),
              data=(list(payload)))
            self.pcanlink._write(msg)
            return True

        if not 0 <= message_id <= 4095:
            raise MessageIDOutOfRange(message_id)
        return await send_payload(data)

    def connections_are_open(self) -> bool:
        return True

    async def open_connections(self):
        return

    def close_connections(self):
        return

    def uds_over_tcp(self) -> bool:
        return False

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/platforms/common/canapi2.pyc
