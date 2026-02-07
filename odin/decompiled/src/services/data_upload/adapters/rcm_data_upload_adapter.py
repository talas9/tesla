# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/services/data_upload/adapters/rcm_data_upload_adapter.py
import asyncio
from binascii import hexlify
import logging, os
from enum import IntEnum
from typing import Tuple, Dict
from odin.core import cid
from odin.core.cid.interface import filesystem
from odin.services.data_upload import ROOT
from ..adapters import UploadPriority
from ..adapters import AbstractDataUploadAdapter
log = logging.getLogger(__name__)
_READING_RETRIES = 3
_COUNT_FILE = "rcm_life_event_count"
_COUNTER_ID = "LIFETIME_EVENT_COUNT"
_SHARED_DATA_IDS = [
 'EVENT_DATA_RECORDER_1', 
 'EVENT_DATA_RECORDER_2', 
 'PACKAGE_PART_NUMBER', 
 'PACKAGE_SERIAL_NUMBER', 
 'VIN', 
 'LIFETIME_EVENT_COUNT', 
 'SATELLITE_SENSOR_FAULT_STATUS', 
 'DRIVE_POWER_KEY_ON_CYCLE_COUNTER_STATUS', 
 'IMPACT_SENSOR_UPFRONT_LEFT_VERIFICATION_UFSL', 
 'IMPACT_SENSOR_UPFRONT_RIGHT_VERIFICATION_UFSR', 
 'IMPACT_SENSOR_B_PILLAR_LEFT_VERIFICATION_PASML', 
 'IMPACT_SENSOR_B_PILLAR_RIGHT_VERIFICATION_PASMR', 
 'IMPACT_SENSOR_DOOR_PRESSURE_FRONT_LEFT_VERIFICATION_PPFSL', 
 'IMPACT_SENSOR_DOOR_PRESSURE_FRONT_RIGHT_VERIFICATION_PPFSR']
_PLATFORM_SPECIFIC_IDS = {'model_3':[
  "IMPACT_SENSOR_UPFRONT_CENTER_VERIFICATION_UFSC",
  "IMPACT_SENSOR_C_PILLAR_LEFT_VERIFICATION_PASRL",
  "IMPACT_SENSOR_C_PILLAR_RIGHT_VERIFICATION_PASRR"], 
 'model_y':[
  "IMPACT_SENSOR_UPFRONT_MID_LEFT_VERIFICATION_UFSML",
  "IMPACT_SENSOR_UPFRONT_MID_RIGHT_VERIFICATION_UFSMR",
  "IMPACT_SENSOR_DOOR_PRESSURE_REAR_LEFT_VERIFICATION_PPRSL",
  "IMPACT_SENSOR_DOOR_PRESSURE_REAR_RIGHT_VERIFICATION_PPRSR"]}

class RCMDataUploadAdapter(AbstractDataUploadAdapter):
    protocol_type = "rcm_protocol"

    async def get_data(self, *args, **kwargs) -> Tuple[(bool, dict)]:
        from odin import __platform__
        await asyncio.sleep(6)
        data_ids = _SHARED_DATA_IDS
        data_ids.extend(_PLATFORM_SPECIFIC_IDS.get(__platform__, []))
        data_values = {}
        success = True
        for data_name in data_ids:
            log.debug("Read Data for RCM: {}".format(data_name))
            data_value = await self.read_data_by_name_with_retries(data_name)
            data_values[data_name] = data_value
            if data_name in ('EVENT_DATA_RECORDER_1', 'EVENT_DATA_RECORDER_2') and not data_value:
                success = False

        return (
         success, data_values)

    async def read_data_by_name_with_retries(self, data_name: str) -> dict:
        data_value = {}
        for retry in range(_READING_RETRIES):
            data_value = await self.read_data_by_name(data_name)
            if data_value:
                self.format_bytes_to_hex(data_value)
                break
            await asyncio.sleep(retry * 0.25)

        return data_value

    @staticmethod
    def format_bytes_to_hex(data: dict):
        for name, value in data.items():
            if isinstance(value, bytes):
                data[name] = hexlify(value)

    async def get_descriptor(self) -> dict:
        return {}

    async def get_priority_and_descriptor(self) -> Tuple[(IntEnum, Dict)]:
        log_descriptor = await self.get_descriptor_if_increased_crash_count()
        if not log_descriptor:
            return (UploadPriority.PRIORITY_NONE, {})
        else:
            return (
             UploadPriority.PRIORITY_4, log_descriptor)

    async def get_descriptor_if_increased_crash_count(self) -> dict:
        crash_count = await self.get_current_crash_count()
        if not crash_count:
            return {}
        stored_descriptor = await self.get_stored_descriptor()
        serial_number = await self.get_serial_number()
        previous_crash_count = stored_descriptor.get(serial_number, 0)
        if crash_count <= previous_crash_count:
            return {}
        else:
            log.info("Crash occured with crash count {}".format(crash_count))
            if serial_number:
                stored_descriptor[serial_number] = crash_count
            return stored_descriptor

    async def get_current_crash_count(self) -> int:
        data_value = await self.read_data_by_name(_COUNTER_ID)
        value = data_value.get(_COUNTER_ID, 0)
        log.debug("Current RCM count: {}".format(value))
        return value

    @staticmethod
    async def get_stored_descriptor() -> dict:
        file_name = os.path.join(ROOT, _COUNT_FILE)
        if not await filesystem.exists(file_name):
            return {}
        else:
            try:
                counts = await asyncio.wait_for((cid.interface.load_data(file_name)), timeout=1)
            except (RuntimeError, FileNotFoundError, SyntaxError, asyncio.TimeoutError) as exc:
                log.error("Failed to read RCM life count: {}".format(repr(exc)))
                counts = {}

            log.debug("Previous counts: {}".format(counts))
            return counts

    async def get_serial_number(self) -> str:
        value = await self.read_data_by_name("PACKAGE_SERIAL_NUMBER")
        if value:
            return str(value.get("PACKAGE_SERIAL_NUMBER"))
        else:
            return ""

    async def set_received(self, data_upload_success: bool, descriptor: dict):
        if data_upload_success:
            await self.store_current_descriptor(descriptor)

    @staticmethod
    async def store_current_descriptor(descriptor: dict):
        if not await filesystem.exists(ROOT):
            await filesystem.mkdir(ROOT, parents=True)
        file_name = os.path.join(ROOT, _COUNT_FILE)
        try:
            await asyncio.wait_for((cid.interface.save_data(file_name, descriptor)), timeout=1)
        except (RuntimeError, asyncio.TimeoutError) as exc:
            log.error("Failed to store RCM life count of {}: {}".format(descriptor, repr(exc)))

    def verify_binary_data_length(*args, **kwargs) -> bool:
        return True

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/services/data_upload/adapters/rcm_data_upload_adapter.pyc
