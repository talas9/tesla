# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/gateway/protocols/gateway_udp.py
import asyncio
from abc import ABCMeta
from typing import Callable, Tuple
from odin.core.can import Bus

class GatewayUDPProtocol(asyncio.DatagramProtocol, metaclass=ABCMeta):

    def __init__(self, communicate_data: Callable[([Tuple[(Bus, int)], bytes], None)]):
        self.communicate_data_method = communicate_data

    def communicate_data(self, message: Tuple[(Bus, int)], data: bytes):
        self.communicate_data_method(message, data)

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/gateway/protocols/gateway_udp.pyc
