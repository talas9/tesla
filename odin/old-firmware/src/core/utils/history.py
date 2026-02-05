# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/utils/history.py
from collections import OrderedDict
from typing import Optional

class History(OrderedDict):

    def __init__(self, maxsize=None):
        super().__init__()
        self.maxsize = maxsize

    def __setitem__(self, key, value):
        if self.maxsize:
            if len(self) >= self.maxsize:
                self.popitem(last=False)
        if key in self:
            del self[key]
        OrderedDict.__setitem__(self, key, value)

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/utils/history.pyc
