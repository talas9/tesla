# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/isotp/udslite_service.py
import logging
from typing import AsyncIterator, Optional
import asyncio_extras, udslite.isotp
from odin.core import can
from .. import isotp
from .error import *
log = logging.getLogger(__name__)
service_registry = {}

class Service(object):

    def __init__(self, tx_id: int, rx_id: int, target_bus: can.Bus, source_bus: Optional[can.Bus]=None):
        self.tx_id = tx_id
        self.rx_id = rx_id
        self.target_bus = target_bus
        self.source_bus = source_bus or can.Bus.ETH
        if isotp.datalink_class:
            self.datalink = isotp.datalink_class(self.target_bus, self.source_bus, tx_id, rx_id)
        else:
            raise DatalinkError("No datalink found for ISO-TP service.")
        self.udslite_isotp = udslite.isotp.ISOTPHandle(self.datalink)

    @asyncio_extras.async_contextmanager
    async def listening(self) -> AsyncIterator[None]:
        async with self.datalink.active():
            yield

    async def tx(self, data: bytearray) -> bool:
        log.debug("Transmitting data: {}".format(data))
        try:
            self.udslite_isotp.start_send(data)
            self.udslite_isotp.run()
        except:
            raise
        else:
            return True

    async def wait_for_data(self) -> bytearray:
        if self.udslite_isotp.recv_is_idle():
            self.udslite_isotp.start_recv(udslite.isotp.MAX_LEN)
        while 1:
            await self.udslite_isotp.apoll()
            self.udslite_isotp.run()
            if self.udslite_isotp.recv_did_succeed():
                return self.udslite_isotp.recv_data()


def get_service_handle(tx_id: int, rx_id: int, target_bus: can.Bus, source_bus: Optional[can.Bus]=None) -> Service:
    if (
     tx_id, rx_id) not in service_registry:
        service_registry[(tx_id, rx_id)] = Service(tx_id, rx_id, target_bus, source_bus)
    service_object = service_registry[(tx_id, rx_id)]
    return service_object


def init_isotp_interface():
    isotp.get_service_handle = get_service_handle

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/isotp/udslite_service.pyc
