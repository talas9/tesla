# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/isotp/datalink/datalink.py
import asyncio_extras
from abc import ABCMeta, abstractmethod
from odin.core import can

class Datalink(object, metaclass=ABCMeta):

    def __init__(self, target_bus: can.Bus, source_bus: can.Bus, tx_id: int, rx_id: int):
        self.target_bus = target_bus
        self.source_bus = source_bus
        self.tx_id = tx_id
        self.rx_id = rx_id

    @abstractmethod
    @asyncio_extras.async_contextmanager
    async def active(self):
        return

    @abstractmethod
    async def read(self) -> bytearray:
        return

    @abstractmethod
    async def write(self, data: bytearray) -> bool:
        return

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/isotp/datalink/datalink.pyc
