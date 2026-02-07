# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/platforms/common/dummy_gateway.py
import asyncio, logging
from enum import IntEnum
from typing import Optional, Union
from odin.core.gateway.abstract import AbstractGateway
log = logging.getLogger(__name__)

class DummyGateway(AbstractGateway):

    def __init__(self):
        super().__init__()

    async def monitor_message(self, bus: IntEnum, message_id: int, is_uds_message: bool=False, slots: int=1, enabled: bool=True) -> Optional[int]:
        return

    async def read_message_impl(self, bus: IntEnum, message_id: int, timeout: Union[(float, None)]=1.0, is_uds_message: bool=False, uid: Optional[int]=None) -> bytes:
        raise asyncio.TimeoutError

    async def send_message_impl(self, bus_id, message_id, data):
        return True

    def connections_are_open(self) -> bool:
        return True

    async def open_connections(self):
        return

    def close_connections(self):
        return

    def uds_over_tcp(self) -> bool:
        return False

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/platforms/common/dummy_gateway.pyc
