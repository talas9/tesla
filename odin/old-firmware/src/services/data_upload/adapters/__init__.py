# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/services/data_upload/adapters/__init__.py
import asyncio, logging
from abc import ABCMeta, abstractmethod
from enum import IntEnum
from typing import Tuple, Optional, Dict
from odin.adapter import Adapter
from odin.core import odx, uds, isotp
from ..data_upload_ports import DataUploadPort
log = logging.getLogger(__name__)

class UploadPriority(IntEnum):
    PRIORITY_NONE = 0
    PRIORITY_1 = 1
    PRIORITY_2 = 2
    PRIORITY_3 = 3
    PRIORITY_4 = 4


class TransferStatus(IntEnum):
    TRANSFER_COMPLETED = 0
    TRANSFER_SUSPENDED = 1
    TRANSFER_ABORTED = 2


class AbstractDataUploadAdapter(Adapter, metaclass=ABCMeta):
    port_class = DataUploadPort
    protocol_type = ""

    def __init__(self, node_name, node):
        super().__init__()
        self._node_name = node_name
        self._node = node

    def get_node(self) -> uds.Node:
        return self._node

    def get_node_name(self) -> str:
        return self._node_name

    async def read_data_by_name(self, data_name: str, diagnostic_session: str=None) -> dict:
        try:
            odx_data_spec = self.get_data_spec(data_name)
            odx_data_spec["node_name"] = self._node_name
            if diagnostic_session:
                await uds.diagnostic_session(self._node, uds.SessionType[diagnostic_session])
            await odx.security_access(self._node, odx_data_spec["read"])
            value = await odx.read_data(odx_data_spec)
        except (uds.UdsException, isotp.ISOTPError, asyncio.TimeoutError, OSError, KeyError, RuntimeError) as exc:
            log.error("Failed to read DID {} for node {} with: {}".format(data_name, self._node_name, repr(exc)))
            return {}
        else:
            return dict(value)

    def get_data_spec(self, data_name: str) -> Dict:
        odx_data_spec = self._node.get_odx_data_spec(data_name)
        if odx_data_spec is not None:
            return odx_data_spec
        else:
            log.error("Missing Odx declaration for: {} for node {}".format(data_name, self._node_name))
            return {}

    async def write_data_by_name(self, data_name: str, data: dict):
        try:
            odx_data_spec = self.get_data_spec(data_name)
            odx_data_spec["node_name"] = self._node_name
            await odx.security_access(self._node, odx_data_spec["write"])
            await odx.write_data(odx_data_spec, data)
        except (uds.UdsException, isotp.ISOTPError, asyncio.TimeoutError, OSError, KeyError, RuntimeError) as exc:
            log.error("Failed to write DID {} for {} with: {}".format(data_name, self._node_name, str(exc)))

    @abstractmethod
    async def get_descriptor(self) -> Tuple[(bool, dict)]:
        return

    @abstractmethod
    async def get_data(self, *args, **kwargs) -> bytes:
        return

    @abstractmethod
    async def get_priority_and_descriptor(self) -> Tuple[(IntEnum, Dict)]:
        return

    @abstractmethod
    async def set_received(self, *args, **kwargs):
        return

    @abstractmethod
    def verify_binary_data_length(self, *args, **kwargs):
        return

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/services/data_upload/adapters/__init__.pyc
