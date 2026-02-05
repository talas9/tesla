# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/platforms/gen3/__init__.py
import logging
from . import power
from . import nodes
from .config_options import Gen3ConfigOptions
from .gateway import Gen3Gateway
from .power import Gen3Power
from odin.core.can import Bus
from odin.platforms import common
log = logging.getLogger(__name__)

def configure(platform: str, bus: Bus) -> bool:
    log.debug("Configuring as {}".format(platform))
    return common.configure(platform, gateway_interface=Gen3Gateway, power_interface=Gen3Power, bus=bus, config_options_interface=Gen3ConfigOptions)

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/platforms/gen3/__init__.pyc
