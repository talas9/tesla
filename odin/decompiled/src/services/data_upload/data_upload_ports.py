# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/services/data_upload/data_upload_ports.py
import time
from enum import IntEnum
from typing import Tuple, Dict
from odin.core import uds

class DataUploadPort(object):

    def __init__(self, adapter):
        self.adapter = adapter
        self._time = time.time()

    def __lt__(self, other) -> bool:
        return self.get_time() < other.get_time()

    async def get_descriptor(self) -> dict:
        return await self.adapter.get_descriptor()

    async def get_data(self, *args, **kwargs):
        return await (self.adapter.get_data)(*args, **kwargs)

    def get_node(self) -> uds.Node:
        return self.adapter.get_node()

    def get_node_name(self) -> str:
        return self.adapter.get_node_name()

    async def get_priority_and_descriptor(self) -> Tuple[(IntEnum, Dict)]:
        return await self.adapter.get_priority_and_descriptor()

    def get_time(self) -> float:
        return self._time

    async def set_received(self, *args, **kwargs):
        return await (self.adapter.set_received)(*args, **kwargs)

    def verify_binary_data_length(self, *args, **kwargs) -> bool:
        return (self.adapter.verify_binary_data_length)(*args, **kwargs)

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/services/data_upload/data_upload_ports.pyc
