# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/platforms/gen3/gateway.py
import asyncio, logging, socket, struct, time
from collections import defaultdict
from enum import IntEnum
from functools import partial
from typing import Optional, Tuple, Union
from odin.config import options
from odin.core import can
from odin.core.gateway import GatewaySocketManager
from odin.core.gateway.abstract import AbstractGateway
from odin.core.gateway.exceptions import MessageIDOutOfRange
log = logging.getLogger(__name__)

class CANMessageData:

    def __init__(self):
        self.data = None
        self.timestamp = None
        self.counter = 0


class Gen3Gateway(AbstractGateway, asyncio.DatagramProtocol):
    TCP_PORT = 10001
    MAX_TCP_PACKET_SIZE = 65536
    UDP_PORT = 1234
    PAYLOAD_SIZE = 8
    MESSAGE_ID_SIZE = 2
    CONNECT_TIMEOUT = 3.0
    RETRY_SLEEP = 0.025
    RETRY_TIMEOUT = 6.0

    def __init__(self):
        super().__init__()
        gtw_options = options.get("core", {}).get("gateway", {})
        self.RETRY_SLEEP = gtw_options.get("send_retry_sleep", self.RETRY_SLEEP)
        self.RETRY_TIMEOUT = gtw_options.get("send_retry_timeout", self.RETRY_TIMEOUT)
        self.CONNECT_TIMEOUT = gtw_options.get("socket_connect_timeout", self.CONNECT_TIMEOUT)
        self.tcp_socket_manager = GatewaySocketManager(socket.AF_INET, socket.SOCK_STREAM, (
         self.IP_ADDRESS, self.TCP_PORT), self.read_from_tcp_socket)
        self.udp_transport = None
        self.udp_protocol = None
        self.message_buffer = defaultdict((lambda: asyncio.Queue(maxsize=(self.MESSAGE_BUFFER_SIZE))))
        self.message_data = {}

    def _start_listening(self, message_id: int):
        can_message_data = self.message_data.get(message_id)
        if can_message_data is None:
            can_message_data = CANMessageData()
            self.message_data[message_id] = can_message_data
        can_message_data.counter += 1

    def _stop_listening(self, message_id: int):
        can_message_data = self.message_data.get(message_id)
        if can_message_data is None:
            return
        can_message_data.counter -= 1
        if can_message_data.counter <= 0:
            del self.message_data[message_id]

    def _should_process(self, message_id: int):
        can_message_data = self.message_data.get(message_id)
        return isinstance(can_message_data, CANMessageData) and can_message_data.counter > 0

    def datagram_received(self, data: bytes, addr: Tuple[(str, int)]):
        chunk_size = self.MESSAGE_ID_SIZE + self.PAYLOAD_SIZE
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i + chunk_size]
            message_id = (chunk[0] & 7) << 8 | chunk[1]
            if not self._should_process(message_id):
                continue
            message_data = self.message_data[message_id]
            message_data.data = chunk[self.MESSAGE_ID_SIZE:]
            message_data.timestamp = time.time()

    async def read_from_tcp_socket(self):
        loop = asyncio.get_event_loop()
        chunk_size = self.MESSAGE_ID_SIZE + self.PAYLOAD_SIZE
        while True:
            data = await loop.sock_recv(self.tcp_socket_manager.socket, self.MAX_TCP_PACKET_SIZE)
            log.debug("Read from TCP socket: {}".format(data.hex()))
            for i in range(0, len(data), chunk_size):
                chunk = data[i:i + chunk_size]
                message_id = (chunk[0] & 7) << 8 | chunk[1]
                payload = chunk[self.MESSAGE_ID_SIZE:]
                if self.message_buffer[(can.Bus.ETH, message_id)].full():
                    self.message_buffer[(can.Bus.ETH, message_id)].get_nowait()
                self.message_buffer[(can.Bus.ETH, message_id)].put_nowait((payload, time.time()))

    async def monitor_message(self, bus: IntEnum, message_id: int, is_uds_message: bool=False, slots: int=1, enabled: bool=True) -> Optional[int]:
        return

    async def read_message_impl(self, bus: IntEnum, message_id: int, timeout: Union[(float, None)]=1.0, is_uds_message: bool=False, uid: Optional[int]=None) -> bytes:
        time_of_call = time.time()
        check_frequency = 0.01

        async def _next_fresh_message():
            can_message_data = self.message_data[message_id]
            while can_message_data.timestamp is not None:
                if can_message_data.timestamp > time_of_call:
                    return can_message_data.data
                await asyncio.sleep(check_frequency)

        async def _next_uds_message():
            message, _ = await self.message_buffer[(bus, message_id)].get()
            return message

        async def _get_message():
            async with self.tcp_socket_manager.open_socket("read", timeout=(self.CONNECT_TIMEOUT)):
                if is_uds_message:
                    if timeout is not None:
                        return await asyncio.wait_for((_next_uds_message()), timeout=timeout)
                    else:
                        return await _next_uds_message()
                else:
                    async with self.ensure_connections():
                        if timeout is not None:
                            return await asyncio.wait_for((_next_fresh_message()), timeout=timeout)
                        else:
                            return await _next_fresh_message()

        self._start_listening(message_id)
        try:
            return await self.run_until_with_retries((partial(_get_message)), interval=(self.RETRY_SLEEP))
        finally:
            self._stop_listening(message_id)

    async def send_message_impl(self, bus_id, message_id, data):
        if not 0 <= message_id <= 4095:
            raise MessageIDOutOfRange(message_id)
        else:
            length = len(data)
            payload = struct.pack(">H", (length << 11) + message_id) + data.ljust(8, b'\x00')

        async def send_payload(sock_payload):
            async with self.tcp_socket_manager.open_socket("send", timeout=(self.CONNECT_TIMEOUT)) as sock:
                log.debug("TCP Socket Send: {}".format(payload.hex()))
                await asyncio.get_event_loop().sock_sendall(sock, sock_payload)
            return True

        return await self.run_until_with_retries((partial(send_payload, payload)),
          interval=(self.RETRY_SLEEP))

    def connections_are_open(self) -> bool:
        return self.udp_transport is not None and not self.udp_transport.is_closing()

    async def open_connections(self):
        loop = asyncio.get_event_loop()
        self.udp_transport, self.udp_protocol = await loop.create_datagram_endpoint((lambda: self),
          sock=(AbstractGateway.create_and_bind_udp_socket("0.0.0.0", self.UDP_PORT)))

    def close_connections(self):
        self.udp_protocol = None
        if self.udp_transport:
            self.udp_transport.close()
            self.udp_transport = None

    async def run_until_with_retries(self, socket_call: callable, interval: float=0):
        start = time.time()
        while True:
            try:
                return await socket_call()
            except (BrokenPipeError, ConnectionResetError, AttributeError, OSError, socket.error) as err:
                log.error("Failed on socket call with: {}".format(repr(err)))
                if time.time() - start > self.RETRY_TIMEOUT:
                    raise asyncio.TimeoutError("Reached max retry timeout for {}".format(socket_call.func.__name__))

            log.debug("Retrying to send or read on TCP connection to Gateway")
            await asyncio.sleep(interval)

    def uds_over_tcp(self) -> bool:
        return True

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/platforms/gen3/gateway.pyc
