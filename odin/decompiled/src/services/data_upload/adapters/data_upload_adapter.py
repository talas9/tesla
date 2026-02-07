# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/services/data_upload/adapters/data_upload_adapter.py
import asyncio, logging
from enum import IntEnum
from typing import Tuple, Optional, Dict
from odin.core import can, uds, isotp
from odin.services.data_upload.adapters import AbstractDataUploadAdapter
from ..adapters import TransferStatus, UploadPriority
log = logging.getLogger(__name__)
PRIORITY_SIGNAL_SUFFIX = "_ecuLogUploadRequest"
DESCRIPTOR_DATA_ID = "GET_ECULOG_DESCRIPTOR"
TRANSFER_STATUS_DATA_ID = "SET_ECULOG_TRANSFER_STATUS"
PROTO_ID = "PROTOCOL_ID"
LOG_ID = "LOG_IDENTIFIER"
TRANSFER_STATE = "TRANSFER_STATE"
SIZE = "SIZE"
SHIFT_REQUIRED = "RQUL"
CAN_PREFIX_MAP = {"HVBMS": "BMS"}

class DataUploadAdapter(AbstractDataUploadAdapter):

    async def get_data(self, descriptor: dict) -> Tuple[(bool, bytes)]:
        if not self.is_log_id_defined(descriptor):
            return (
             False, bytes())
        await uds.diagnostic_session(self.get_node(), uds.SessionType.EXTENDED_DIAGNOSTIC_SESSION)
        await uds.security_access(self.get_node(), uds.SecurityLevel.LEVEL_5)
        memory_address = self.get_memory_address_from_descriptor(descriptor)
        memory_size = descriptor.get(SIZE, 0)
        log.debug("Request data upload for memory address: {} , and memory size: {}".format(memory_address, memory_size))
        try:
            return (
             True,
             await uds.data_upload(node=(self.get_node()),
               memory_address=memory_address,
               memory_size=memory_size))
        except (uds.UdsException, isotp.ISOTPError, asyncio.TimeoutError) as err:
            log.error("Failed data_upload for {}: {}".format(self.get_node_name(), str(err)))
            return (False, bytes())

    def get_memory_address_from_descriptor(self, descriptor: dict):
        return self.shift_address(descriptor.get(LOG_ID, 0), descriptor.get(PROTO_ID, "INVALID"))

    async def get_descriptor(self) -> dict:
        return await self.read_data_by_name(DESCRIPTOR_DATA_ID)

    async def get_priority_and_descriptor(self) -> Tuple[(IntEnum, Dict)]:
        descriptor = await self.get_descriptor()
        if not (descriptor and descriptor.get("PRIORITY")):
            return (UploadPriority.PRIORITY_NONE, {})
        else:
            priority = self.map_priority_value(descriptor.get("PRIORITY", "NONE"))
            return (priority, descriptor)

    @staticmethod
    def map_priority_value(value) -> IntEnum:
        if isinstance(value, str):
            if value == "NONE":
                return UploadPriority.PRIORITY_NONE
            striped_value = value.replace("REQUEST_", "")
            return UploadPriority[striped_value]
        else:
            if isinstance(value, int):
                return UploadPriority(value)
            return UploadPriority.PRIORITY_NONE

    @staticmethod
    def is_log_id_defined(descriptor: dict) -> bool:
        return LOG_ID in descriptor

    async def set_received(self, data_upload_success: bool, descriptor: dict):
        descriptor_id = self.shift_address(descriptor.get(LOG_ID, 0), descriptor.get(PROTO_ID, "INVALID"))
        data = {LOG_ID: descriptor_id, 
         TRANSFER_STATE: (TransferStatus.TRANSFER_COMPLETED.value if data_upload_success else TransferStatus.TRANSFER_ABORTED.value)}
        log.debug("Set transfer status to {}".format(data))
        await self.write_data_by_name(TRANSFER_STATUS_DATA_ID, data)

    @staticmethod
    def shift_address(memory_address: int, protocol_id: str) -> int:
        if protocol_id == SHIFT_REQUIRED:
            memory_address <<= 24
        return memory_address

    def verify_binary_data_length(self, descriptor: dict, binary_data: bytes) -> bool:
        success = descriptor["SIZE"] == len(binary_data)
        log.debug("Length of binary data is {}".format("correct" if success else "incorrect"))
        return success


class LegacyTeslaDataUploadAdapter(DataUploadAdapter):
    protocol_type = "legacy_tesla_protocol"

    async def get_priority_and_descriptor(self) -> Tuple[(IntEnum, Dict)]:
        signal_name = self.format_priority_signal_name()
        try:
            signal_value = await can.signal.read_by_name(signal_name)
        except (asyncio.TimeoutError, RuntimeError) as err:
            log.error("Failed reading {}, err: {}".format(signal_name, repr(err)))
            return (UploadPriority.PRIORITY_NONE, {})
        else:
            return (
             self.map_priority_value(signal_value), {})

    def format_priority_signal_name(self) -> str:
        node_name = self.get_node_name().upper()
        prefix = CAN_PREFIX_MAP.get(node_name, node_name)
        return prefix + PRIORITY_SIGNAL_SUFFIX


class TeslaDataUploadAdapter(DataUploadAdapter):
    protocol_type = "tesla_protocol"

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/services/data_upload/adapters/data_upload_adapter.pyc
