# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/platforms/platform_metadata_ports.py
from attrdict import AttrDict
from typing import Dict

class PlatformMetadataPort(object):

    def __init__(self, adapter):
        self.adapter = adapter

    def init_can_library(self) -> AttrDict:
        return self.adapter.init_can_library()

    def init_iris_data(self) -> Dict:
        return self.adapter.init_iris_data()

    def init_connector_info(self):
        return self.adapter.init_connector_info()

    def init_nodes(self) -> AttrDict:
        return self.adapter.init_nodes()

    def init_odjs(self) -> AttrDict:
        return self.adapter.init_odjs()

    def init_power_map(self) -> AttrDict:
        return self.adapter.init_power_map()

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/platforms/platform_metadata_ports.pyc
