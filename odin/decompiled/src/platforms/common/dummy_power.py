# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/platforms/common/dummy_power.py
import logging
from asyncio_extras import async_contextmanager
from enum import Enum, EnumMeta
from typing import Dict
from odin.core.power.abstract import AbstractPowerInterface
log = logging.getLogger(__name__)

class PowerStateEnum(Enum):
    return


class DummyPower(AbstractPowerInterface):

    def __init__(self):
        super().__init__()

    def power_signal_map(self, power_state: EnumMeta) -> Dict:
        return {}

    def power_state_enum(self) -> EnumMeta:
        return PowerStateEnum

    async def start_power_state(self, power_state: EnumMeta):
        return

    async def verify_power_state(self, power_state: EnumMeta):
        return

    @async_contextmanager
    async def hold_power_context_mgr(self, *args, **kwargs):
        yield

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/platforms/common/dummy_power.pyc
