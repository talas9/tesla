# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/cid/hrl_parser.py
import math, struct

class HrlHeader:

    def __init__(self, version, raw):
        self.version = version
        if self.version in (0, 1):
            self.S = struct.Struct(">B5I17BHBI")
        elif self.version >= 2:
            self.S = struct.Struct(">B5I17BHBIH")
        else:
            raise Exception("Invalid Header Version {}".format(self.version))
        d = self.S.unpack(raw[0:self.S.size])
        self.maxNumTriggerIds = None
        self.triggers = None
        if self.version >= 2:
            self.maxNumTriggerIds = d[26]
            numBytes = math.ceil(self.maxNumTriggerIds / 32) * 4
            triggerIdsBitmask = struct.unpack(">{}B".format(numBytes), raw[self.S.size:self.S.size + numBytes])
            self.triggers = []
            for i, data in enumerate(triggerIdsBitmask):
                for bit in range(0, 8):
                    if data & 1 << bit:
                        self.triggers.append(i * 8 + bit)


class HrlReader:

    def __init__(self, file):
        with open(file, "rb+") as f:
            self.hrlVersion, = struct.unpack(">B", f.read(1))
            if self.hrlVersion < 3:
                self.page_size = 16384
                self.pool_page_qty = 20
            else:
                self.page_size = 32768
                self.pool_page_qty = 10
            f.seek(-1, 1)
            self.header = HrlHeader(self.hrlVersion, f.read(self.page_size))

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/cid/hrl_parser.pyc
