# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/engine/messages.py
from odin_server.messages import Message

class SignalsChanged(Message):
    message_type = "signals_changed"

    def __init__(self, values):
        super().__init__(values=values)


class StopThermalFillDrain(Message):
    message_type = "stop_thermal_fill_drain"

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/engine/messages.pyc
