# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/gateway/abstract.py
import asyncio, asyncio_extras, logging, socket, odin
from abc import ABCMeta, abstractmethod
from enum import IntEnum
from typing import Optional
from odin.core import cid
from odin.enumutils import flags_to_string
from odin.testing.gateway.decorators import gateway_send_hook_async, gateway_read_hook_async
from .enum import VehicleState
log = logging.getLogger(__name__)

class AbstractGateway(object):
    __metaclass__ = ABCMeta
    IP_ADDRESS = "192.168.90.102"
    PORT = 0
    MESSAGE_BUFFER_SIZE = 32
    CONNECTIONS_COOL_DOWN_SECS = 10

    def __init__(self):
        super().__init__()
        self._AbstractGateway__socket = socket
        self.message_buffer = {}
        self.active_requests_counter = 0
        self.close_connections_task = None
        self.connection_lock = asyncio.Lock()

    @staticmethod
    def create_and_bind_udp_socket(local_address: str, port: int) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if hasattr(socket, "SO_REUSEADDR"):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sock.setblocking(False)
        sock.bind((local_address, port))
        return sock

    def clear_buffer(self, bus: IntEnum, message_id: int):
        try:
            del self.message_buffer[(bus, message_id)]
        except KeyError:
            pass

    @gateway_read_hook_async
    async def read_message(self, bus: IntEnum, message_id: int, timeout: Optional[float]=1.0, is_uds_message: bool=False, uid: Optional[int]=None) -> bytes:
        return await self.read_message_impl(bus, message_id, timeout=timeout, is_uds_message=is_uds_message, uid=uid)

    @abstractmethod
    async def read_message_impl(self, bus: IntEnum, message_id: int, timeout: Optional[float]=1.0, is_uds_message: bool=False, uid: Optional[int]=None) -> bytes:
        return

    @gateway_send_hook_async
    async def send_message(self, bus, message_id, data):
        return await self.send_message_impl(bus, message_id, data)

    @abstractmethod
    async def send_message_impl(self, bus, message_id, data):
        return

    @asyncio_extras.async_contextmanager
    async def ensure_connections(self):
        if self.close_connections_task:
            if not self.close_connections_task.done():
                self.close_connections_task.cancel()
        self.active_requests_counter += 1
        try:
            if not self.connections_are_open():
                async with self.connection_lock:
                    if not self.connections_are_open():
                        await self.open_connections()
            yield
        finally:
            self.active_requests_counter -= 1
            if self.active_requests_counter <= 0:
                self.active_requests_counter = 0
                self._schedule_close_connections()

    def _schedule_close_connections(self):
        if isinstance(self.close_connections_task, asyncio.Task):
            if not self.close_connections_task.done():
                return

        async def close_connections_after_delay(delay):
            await asyncio.sleep(delay)
            if self.active_requests_counter <= 0:
                self.close_connections()

        self.close_connections_task = asyncio.ensure_future(close_connections_after_delay(self.CONNECTIONS_COOL_DOWN_SECS))

    @abstractmethod
    async def connections_are_open(self) -> bool:
        return False

    @abstractmethod
    async def open_connections(self):
        return

    @abstractmethod
    def close_connections(self):
        return

    @asyncio_extras.async_contextmanager
    async def monitor(self, bus, message_id, is_uds_message=False):
        await self.monitor_message(bus, message_id, is_uds_message=is_uds_message, enabled=True)
        try:
            yield
        finally:
            await self.monitor_message(bus, message_id, is_uds_message=is_uds_message, enabled=False)

    @abstractmethod
    async def monitor_message(self, bus: IntEnum, message_id: int, is_uds_message: bool=False, slots: int=1, enabled: bool=True) -> Optional[int]:
        return

    @abstractmethod
    def uds_over_tcp(self) -> bool:
        return

    @staticmethod
    async def vehicle_state() -> VehicleState:
        if not odin.options["core"]["onboard"]:
            return VehicleState.Parked | VehicleState.StandStill
        else:
            try:
                gear = await cid.interface.get_data_value("VAPI_shiftState")
                gear = "P" if gear == "<invalid>" else gear
            except (RuntimeError, asyncio.TimeoutError) as err:
                log.error("Reading Gear info failed: {}".format(err))
                log.warning("Vehicle does not provide gear info.")
                gear = "P"

            try:
                speed = await cid.interface.get_data_value("VAPI_vehicleSpeed")
                speed = 0.0 if speed == "<invalid>" else float(speed)
            except (RuntimeError, asyncio.TimeoutError) as err:
                log.error("Reading speed info failed: {}".format(err))
                log.warning("Vehicle does not provide speed")
                speed = 0

            if gear == "P":
                state = VehicleState.Parked
            elif gear == "R":
                state = VehicleState.Reverse
            elif gear == "N":
                state = VehicleState.Neutral
            elif gear == "D":
                state = VehicleState.Drive
            else:
                state = VehicleState.Invalid
            if abs(speed) <= 0.05:
                state = state | VehicleState.StandStill
            else:
                state = state | VehicleState.Moving
            return state

    async def get_vehicle_state_str(self) -> str:
        state = await self.vehicle_state()
        return flags_to_string(state)

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/gateway/abstract.pyc
