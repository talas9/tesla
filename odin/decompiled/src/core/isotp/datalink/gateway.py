# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/isotp/datalink/gateway.py
import asyncio, asyncio_extras, logging
from odin.core import can, gateway
from odin.testing.gateway.decorators import get_recorder_instance, get_playback_instance, is_testing_enabled
from .datalink import Datalink
from ..error import DatalinkError
from ..tplinkframe import TPLinkFrame
log = logging.getLogger(__name__)

class GatewayDatalink(Datalink):

    def __init__(self, target_bus, source_bus, tx_id, rx_id):
        super().__init__(target_bus, source_bus, tx_id, rx_id)
        self.tx_id = tx_id
        self.rx_id = rx_id
        self.target_bus = target_bus
        self.source_bus = source_bus

    @asyncio_extras.async_contextmanager
    async def active(self, response_required: bool=True):
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
        recorder = get_recorder_instance()
        if is_testing_enabled():
            player = get_playback_instance()
            if player:
                return player.mock_read(self.source_bus, self.rx_id)
        result = None
        try:
            try:
                data = await gateway.interface.read_message((can.Bus.ETH), (self.rx_id), timeout=None, is_uds_message=True)
                return data
            except asyncio.TimeoutError:
                raise DatalinkError("ISO-TP datalink timed out attempting to read from gateawy.")

        except BaseException as e:
            exception = e

        if recorder:
            recorder.log_read(self.source_bus, self.rx_id, result, exception)
        if exception:
            raise exception
        return result

    async def write(self, frame: TPLinkFrame) -> bool:
        return await gateway.interface.send_message(self.target_bus, self.tx_id, bytes(frame.data))

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/isotp/datalink/gateway.pyc
