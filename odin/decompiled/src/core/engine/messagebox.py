# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/engine/messagebox.py
import asyncio, asyncio_extras
from collections import defaultdict
from odin.core.utils.dispatch import Dispatch

class MessageInbox(defaultdict):

    def __init__(self):
        super().__init__(Dispatch)
        self.event_references = {}

    @asyncio_extras.async_contextmanager
    async def listening(self, message_type):
        if message_type in self.event_references:
            self.event_references[message_type] += 1
        else:
            self.event_references[message_type] = 1
        event = self[message_type]
        try:
            yield event
        finally:
            self.event_references[message_type] -= 1
            if self.event_references[message_type] == 0:
                self.event_references.pop(message_type)
                self.pop(message_type)


inbox = MessageInbox()
outbox = asyncio.Queue()

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/engine/messagebox.pyc
