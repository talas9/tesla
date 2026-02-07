# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/isotp/datalink/udslite_gateway.py
import asyncio, asyncio_extras, logging
from collections import deque
from typing import Optional
from udslite.link import LinkEvent, LinkHandle
from odin.core import can, gateway
from .datalink import Datalink
from ..constants import N_BS_TIMEOUT
log = logging.getLogger(__name__)

class UdsliteGatewayDatalink(LinkHandle, Datalink):

    def __init__(self, target_bus, source_bus, tx_id, rx_id):
        super().__init__(target_bus, source_bus, tx_id, rx_id)
        self.tx_id = tx_id
        self.rx_id = rx_id
        self.target_bus = target_bus
        self.source_bus = source_bus
        self._recv_queue = deque()

    @asyncio_extras.async_contextmanager
    async def active(self, response_required: bool=True):
        self._recv_queue.clear()
        if not gateway.interface.uds_over_tcp():
            async with gateway.interface.ensure_connections():
                if response_required:
                    await gateway.interface.monitor_message((can.Bus.ETH), (self.rx_id), is_uds_message=True, enabled=True)
                try:
                    yield
                finally:
                    if response_required:
                        await gateway.interface.monitor_message((can.Bus.ETH), (self.rx_id), enabled=False)

        else:
            gateway.interface.clear_buffer(can.Bus.ETH, self.rx_id)
            yield

    async def read(self) -> bytearray:
        raise NotImplementedError

    async def write(self, data: bytearray) -> bool:
        raise NotImplementedError

    def send(self, data: bytes) -> bool:
        asyncio.ensure_future(gateway.interface.send_message(self.target_bus, self.tx_id, data))
        return True

    def recv(self) -> Optional[bytes]:
        if self._recv_queue:
            data = self._recv_queue.popleft()
            log.info("Receiving {}:0x{:x} payload={}".format(can.Bus.ETH.name, self.rx_id, data.hex()))
            return data
        else:
            return

    def poll(self, events: int, timeout: float):
        raise NotImplementedError

    async def apoll(self, events, timeout: float=N_BS_TIMEOUT):
        if events & LinkEvent.SEND:
            pass
        elif events & LinkEvent.RECV:
            try:
                self._recv_queue.append(await gateway.interface.read_message((can.Bus.ETH),
                  (self.rx_id), timeout=timeout, is_uds_message=True))
            except asyncio.TimeoutError:
                pass

        else:
            await asyncio.sleep(timeout)

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/isotp/datalink/udslite_gateway.pyc
