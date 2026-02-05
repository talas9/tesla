# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/isotp/service.py
import logging
from typing import AsyncIterator, Callable, Optional, Union
import asyncio_extras, time
from .. import isotp
from odin.core import can
from odin.core.utils.dispatch import Dispatch
from .constants import *
from .error import *
from .tplinkframe import *
log = logging.getLogger(__name__)
service_registry = {}

class Service(object):

    def __init__(self, tx_id: int, rx_id: int, target_bus: can.Bus, source_bus: Optional[can.Bus]=None, padding_byte: Optional[int]=None, block_size: int=0, separation_time: int=10):
        self.tx_id = tx_id
        self.rx_id = rx_id
        self.target_bus = target_bus
        self.source_bus = source_bus or can.Bus.ETH
        self.padding_byte = padding_byte
        self._block_size = block_size
        self._separation_time = separation_time
        self.last_frame = None
        self.data_events = []
        self.frame_events = {ft: [] for ft in FrameType}
        self.active = True
        self.listen_callbacks = {}
        self.listeners = 0
        self.listener_task = None
        if isotp.datalink_class:
            self.datalink = isotp.datalink_class(self.target_bus, self.source_bus, tx_id, rx_id)
        else:
            raise DatalinkError("No datalink found for ISO-TP service.")

    @property
    def block_size(self) -> int:
        return self._block_size

    @block_size.setter
    def block_size(self, size: int):
        if 0 <= size <= 255:
            self._block_size = size
        else:
            raise ValueError("ISOTP block size cannot be set to {}, it must be 1 byte.".format(size))

    async def communicate_data(self, data: Union[(bytearray, Exception)]):
        for dispatch in self.data_events:
            dispatch.set(data)

        self.data_events.clear()
        for callback in self.listen_callbacks.values():
            asyncio.ensure_future(callback(data))

    async def listen(self) -> None:
        while self.active:
            frame = await self.recv()
            if frame:
                try:
                    recv_buf = await self.recv_sequence(frame)
                except ISOTPError as e:
                    recv_buf = e

                if recv_buf is not None:
                    await self.communicate_data(recv_buf)

    async def recv_sequence(self, frame: TPLinkFrame, timeout: float=N_BS_TIMEOUT) -> Optional[bytearray]:
        recv_type = frame.frame_type()
        if recv_type == FrameType.SINGLE_FRAME:
            return await self.recv_single_frame(frame)
        if recv_type == FrameType.FIRST_FRAME:
            return await self.recv_multi_frame(frame, timeout=timeout)
        if recv_type == FrameType.CONSECUTIVE_FRAME:
            raise UnexpPdu(frame)

    @asyncio_extras.async_contextmanager
    async def listening(self) -> AsyncIterator[None]:
        async with self.datalink.active():
            if self.listeners == 0:
                self.listener_task = asyncio.ensure_future(self.listen())
            self.listeners += 1
            try:
                yield
            finally:
                self.listeners -= 1
                if self.listeners == 0:
                    self.listener_task.cancel()

    async def recv(self) -> Optional[TPLinkFrame]:
        raw_data = await self.datalink.read()
        if raw_data:
            frame = TPLinkFrame(raw_data)
            if frame:
                recv_type = frame.frame_type()
                for dispatch in self.frame_events[recv_type]:
                    dispatch.set(frame)

                self.frame_events[recv_type].clear()
                return frame

    async def recv_flow_control(self) -> (
 bool, int, int):
        if self.listener_task:
            if not self.listener_task.cancelled():
                frame = await self.wait_for_frame(FrameType.FLOW_CONTROL_FRAME)
            else:
                frame = await self.recv()
        else:
            if frame:
                if frame.frame_type() == FrameType.FLOW_CONTROL_FRAME:
                    if frame.length < FLOW_CONTROL_FRAME_HEADER_LEN:
                        return (False, -1, -1)
                    else:
                        fc_type = frame.flow_control_frame_type()
                        if fc_type == FlowControl.FLOW_WAIT:
                            return await self.recv_flow_control()
                        if fc_type != FlowControl.FLOW_CONTINUE:
                            return (False, -1, -1)
                        send_frame_count = frame.flow_control_frame_block_size()
                        if send_frame_count == 0:
                            send_frame_count = SIZE_MAX
                        send_separation_time_ms = frame.flow_control_frame_separation_time_ms()
                        return (
                         True, send_frame_count, send_separation_time_ms)
        raise UnexpPdu(frame)

    async def recv_multi_frame(self, frame: TPLinkFrame, timeout: float=N_BS_TIMEOUT) -> Optional[bytearray]:
        if frame.length != TP_LINK_MAX_LEN:
            raise ISOTPError("Received invalid ISO-TP first frame: {}".format(frame.data))
        else:
            payload_len = frame.first_frame_len()
            if payload_len <= SINGLE_FRAME_MAX_LEN:
                raise ISOTPError("Received invalid dwarf ISO-TP first frame: {}".format(frame.data))
            recv_buf = frame.get_first_frame_data()[:FIRST_FRAME_DATA_LEN]
            recv_consecutive_index = 1
            recv_so_far = FIRST_FRAME_DATA_LEN
            recv_len = payload_len
            send_fc = await self.send_flow_control(FlowControl.FLOW_CONTINUE)
            raise send_fc or ISOTPError("Unable to send flow control frame.")
        recv_frame_count = self.block_size
        while self.active:
            try:
                frame = await asyncio.wait_for((self.recv()), timeout=timeout)
            except asyncio.TimeoutError:
                raise TimeoutBs(timeout) from None

            if not frame:
                return
            recv_type = frame.frame_type()
            if recv_type != FrameType.CONSECUTIVE_FRAME:
                log.error("Received {} frame after first frame, skipping frame.".format(recv_type.name))
                continue
            if frame.consecutive_frame_index() != recv_consecutive_index:
                log.error("Received ISO-TP multi-frame out of order: was {}, expecting {}/ Data: {}".format(frame.consecutive_frame_index(), recv_consecutive_index, frame.data))
                continue
            cf_len = CONSECUTIVE_FRAME_DATA_LEN
            remaining = recv_len - recv_so_far
            if cf_len > remaining:
                cf_len = remaining
            if frame.length < CONSECUTIVE_FRAME_HEADER_LEN + cf_len:
                raise ISOTPError("Received dwarf ISO-TP multi-frame: length was {}, expected {}. Data: {}".format(frame.length, CONSECUTIVE_FRAME_HEADER_LEN + cf_len, frame.data))
            recv_buf += frame.get_consecutive_frame_data()[:cf_len]
            recv_so_far += cf_len
            recv_consecutive_index = self.next_consecutive_index(recv_consecutive_index)
            recv_frame_count -= 1
            if recv_so_far == recv_len:
                return recv_buf
            if recv_frame_count == 0:
                send_fc = await self.send_flow_control(FlowControl.FLOW_CONTINUE)
                if not send_fc:
                    return
                recv_frame_count = self.block_size

    async def recv_single_frame(self, frame: TPLinkFrame) -> Optional[bytearray]:
        sf_size = frame.single_frame_len()
        if frame.length >= SINGLE_FRAME_HEADER_LEN + sf_size:
            recv_buf = frame.get_single_frame_data()[:sf_size]
            return recv_buf
        else:
            return

    def register_listen_callback(self, name: str, callback: Callable) -> None:
        self.listen_callbacks[name] = callback

    async def request(self, buffer: bytearray, response_required: bool=True, timeout: float=N_BS_TIMEOUT) -> Optional[bytearray]:
        await self.tx(buffer)
        if response_required:
            try:
                if self.listener_task and not self.listener_task.cancelled():
                    frame = await asyncio.wait_for((self.wait_for_data()), timeout=timeout)
                else:
                    frame = await asyncio.wait_for((self.recv()), timeout=timeout)
            except asyncio.TimeoutError:
                raise TimeoutBs(timeout)

            data = await self.recv_sequence(frame, timeout=timeout)
            return data

    async def send_flow_control(self, fc: FlowControl) -> bool:
        frame = TPLinkFrame(data=(bytearray([FrameType.FLOW_CONTROL_FRAME.value << 4 | fc.value,
         self.block_size,
         self.separation_time])))
        return await self.send_frame(frame)

    async def send_frame(self, frame: TPLinkFrame) -> bool:
        if self.padding_byte is not None:
            if frame.length < TP_LINK_MAX_LEN:
                frame.data.extend([0] * (TP_LINK_MAX_LEN - frame.length))
            for x in range(frame.length, frame.length + (TP_LINK_MAX_LEN - frame.length)):
                frame.data[x] = self.padding_byte

        return await self.transmit_frame(frame)

    @property
    def separation_time(self) -> int:
        return self._separation_time

    @separation_time.setter
    def separation_time(self, time_ms: int):
        if time_ms < 0:
            raise ValueError("ISOTP separation time cannot be negative.")
        self._separation_time = time_ms

    async def transmit_frame(self, frame: TPLinkFrame) -> bool:
        log.debug("Transmitting frame: {}".format(frame))
        return await self.datalink.write(frame)

    async def tx(self, data: bytearray) -> bool:
        log.debug("Transmitting data: {}".format(data))
        if data is None or len(data) == 0:
            return True
        send_buf = data
        send_buf_len = len(data)
        frame = TPLinkFrame()
        if send_buf_len <= SINGLE_FRAME_MAX_LEN:
            frame.length = SINGLE_FRAME_HEADER_LEN + send_buf_len
            frame.data[0] = FrameType.SINGLE_FRAME.value << 4 | send_buf_len
            frame.set_single_frame_data(send_buf[:send_buf_len])
            return await self.send_frame(frame)
        else:
            frame.length = TP_LINK_MAX_LEN
            frame.data[0] = FrameType.FIRST_FRAME.value << 4 | send_buf_len >> 8
            frame.data[1] = send_buf_len & 255
            frame.set_first_frame_data(send_buf[:FIRST_FRAME_DATA_LEN])
            if not await self.send_frame(frame):
                return False
            time_stamp_last_sent = time.time()
            send_so_far = FIRST_FRAME_DATA_LEN
            send_consecutive_index = 1
            while send_so_far < send_buf_len:
                try:
                    valid, send_frame_count, send_separation_time_ms = await asyncio.wait_for((self.recv_flow_control()),
                      timeout=N_CR_TIMEOUT)
                except asyncio.TimeoutError:
                    raise TimeoutCr(N_CR_TIMEOUT)
                else:
                    if not valid:
                        raise ISOTPError("Invalid frame received while waiting for flow control in multi-frame send.")
                    while send_so_far < send_buf_len:
                        if send_frame_count > 0:
                            to_send = send_buf_len - send_so_far
                            if to_send > CONSECUTIVE_FRAME_DATA_LEN:
                                to_send = CONSECUTIVE_FRAME_DATA_LEN
                            frame.length = CONSECUTIVE_FRAME_HEADER_LEN + to_send
                            frame.data[0] = FrameType.CONSECUTIVE_FRAME.value << 4 | send_consecutive_index
                            frame.set_consecutive_frame_data(send_buf[send_so_far:send_so_far + to_send])
                            if send_separation_time_ms > 0:
                                time_remaining = send_separation_time_ms * 0.001 - (time.time() - time_stamp_last_sent)
                                if time_remaining >= 0.001:
                                    await asyncio.sleep(time_remaining)
                            if await self.send_frame(frame):
                                time_stamp_last_sent = time.time()
                                send_so_far += to_send
                                send_consecutive_index = self.next_consecutive_index(send_consecutive_index)
                                send_frame_count -= 1
                        else:
                            raise ISOTPError("Could not send consecutive frame in multi-frame send.")

            return True

    def unregister_listen_callback(self, name) -> None:
        self.listen_callbacks.pop(name)

    async def wait_for_data(self) -> bytearray:
        dispatch = Dispatch()
        self.data_events.append(dispatch)
        return await dispatch.wait()

    async def wait_for_frame(self, frame_type: FrameType) -> TPLinkFrame:
        dispatch = Dispatch()
        self.frame_events[frame_type].append(dispatch)
        return await dispatch.wait()

    @staticmethod
    def next_consecutive_index(i: int) -> int:
        return i + 1 & 15


def get_service_handle(tx_id: int, rx_id: int, target_bus: can.Bus, source_bus: Optional[can.Bus]=None, padding_byte: Optional[int]=None, block_size: int=0, separation_time: int=10) -> Service:
    if (
     tx_id, rx_id) not in service_registry:
        service_registry[(tx_id, rx_id)] = Service(tx_id, rx_id, target_bus, source_bus, padding_byte)
    service_object = service_registry[(tx_id, rx_id)]
    service_object.separation_time = separation_time
    service_object.block_size = block_size
    return service_object


def init_isotp_interface():
    isotp.get_service_handle = get_service_handle

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/isotp/service.pyc
