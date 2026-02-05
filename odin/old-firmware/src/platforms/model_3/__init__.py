# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/platforms/model_3/__init__.py
from odin.platforms import gen3
from .bus import Bus

def configure() -> bool:
    return gen3.configure(platform="model_3", bus=Bus)

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/platforms/model_3/__init__.pyc
