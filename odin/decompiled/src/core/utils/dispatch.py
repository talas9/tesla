# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/utils/dispatch.py
import asyncio, copy
from typing import Any

class Dispatch(asyncio.Event):

    def __init__(self, loop=None):
        super().__init__(loop=loop)
        self.data = None
        self.listeners = 0

    def clear(self):
        self.data = None
        super().clear()

    def set(self, data):
        self.data = data
        super().set()

    async def wait(self):
        if self.listeners <= 0:
            self.listeners = 1
        else:
            self.listeners += 1
        try:
            await super().wait()
            if isinstance(self.data, Exception):
                raise self.data
        finally:
            self.listeners -= 1

        return self.data


class AutoDispatch(Dispatch):

    async def wait(self) -> Any:
        if self.listeners <= 0:
            self.listeners = 1
        else:
            self.listeners += 1
        try:
            await asyncio.Event.wait(self)
            if isinstance(self.data, Exception):
                raise self.data
        finally:
            self.listeners -= 1

        data = copy.copy(self.data)
        if self.listeners <= 0:
            self.clear()
        return data

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/utils/dispatch.pyc
