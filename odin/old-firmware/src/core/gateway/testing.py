# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/gateway/testing.py
from enum import IntEnum
from typing import Optional
from websockets.client import WebSocketClientProtocol
from .abstract import AbstractGateway

class MockGateway(AbstractGateway):

    def __init__(self, read_message=None, send_message=None, **kw):
        super(MockGateway, self).__init__()
        self.IP_ADDRESS = kw.get("ip_address", "127.0.0.1")
        self.PORT = kw.get("port", 7001)
        self._MockGateway__read = read_message
        self._MockGateway__send = send_message

    async def monitor_message(self, bus: IntEnum, message_id: int, **kwargs) -> Optional[int]:
        return

    async def read_message(self, bus, message_id, timeout=3.0, **kwargs):
        if self._MockGateway__read:
            return await self._MockGateway__read(bus, message_id, timeout)
        else:
            return bytes()

    async def send_message(self, bus, message_id, data):
        if self._MockGateway__send:
            return await self._MockGateway__send(bus, message_id, data)
        else:
            return True

    def send_message_blocking(self, bus, message_id, data):
        if self._MockGateway__send:
            return self._MockGateway__send(bus, message_id, data)
        else:
            return True

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/gateway/testing.pyc
