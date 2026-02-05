# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/isotp/tplinkframe.py
from enum import Enum
from .constants import *

class FrameType(Enum):
    SINGLE_FRAME = 0
    FIRST_FRAME = 1
    CONSECUTIVE_FRAME = 2
    FLOW_CONTROL_FRAME = 3


class FlowControl(Enum):
    FLOW_CONTINUE = 0
    FLOW_WAIT = 1
    FLOW_ABORT = 2


class TPLinkFrame(object):

    def __init__(self, data=None):
        if data is not None:
            self.data = bytearray(data)
            self.length = len(data)
        else:
            self.data = bytearray([0] * TP_LINK_MAX_LEN)
            self.length = 0

    def __str__(self):
        return "{}: {}".format(self.frame_type(), self.data)

    def frame_type(self) -> FrameType:
        return FrameType((self.data[0] & 240) >> 4)

    def single_frame_len(self) -> int:
        return self.data[0] & 15

    def first_frame_len(self) -> int:
        return (self.data[0] & 15) << 8 | self.data[1] & 255

    def consecutive_frame_index(self) -> int:
        return self.data[0] & 15

    def get_single_frame_data(self) -> bytearray:
        return self.data[SINGLE_FRAME_HEADER_LEN:]

    def get_first_frame_data(self) -> bytearray:
        return self.data[FIRST_FRAME_HEADER_LEN:]

    def get_consecutive_frame_data(self) -> bytearray:
        return self.data[CONSECUTIVE_FRAME_HEADER_LEN:]

    def set_single_frame_data(self, data):
        self.data[SINGLE_FRAME_HEADER_LEN:] = data

    def set_first_frame_data(self, data):
        self.data[FIRST_FRAME_HEADER_LEN:] = data

    def set_consecutive_frame_data(self, data):
        self.data[CONSECUTIVE_FRAME_HEADER_LEN:] = data

    def flow_control_frame_type(self) -> FlowControl:
        return FlowControl(self.data[0] & 15)

    def flow_control_frame_block_size(self) -> int:
        return self.data[1]

    def flow_control_frame_separation_time_ms(self) -> int:
        st = self.data[2] & 255
        if st <= 127:
            return st
        else:
            if 241 <= st <= 249:
                return 1
            return 127

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/isotp/tplinkframe.pyc
