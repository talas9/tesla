# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/gateway/enum.py
from aenum import IntFlag, auto

class VehicleState(IntFlag):
    Invalid = auto()
    Parked = auto()
    Reverse = auto()
    Neutral = auto()
    Drive = auto()
    Moving = auto()
    StandStill = auto()

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/gateway/enum.pyc
