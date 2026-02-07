# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/resources/subscription.py
import asyncio
from abc import ABCMeta, abstractmethod
import logging
from typing import Optional
log = logging.getLogger(__name__)

class Subscription:
    __metaclass__ = ABCMeta

    def __init__(self):
        self.request_lock = asyncio.Lock()
        self.subscriber_removed_event = asyncio.Event()

    async def subscribe(self, *args, **kw) -> bool:
        while True:
            async with self.request_lock:
                log.debug("Request lock acquired for {}".format((self.get_requested_state)(*args, **kw)))
                if (self.should_set_requested_state)(*args, **kw):
                    if not await (self.set_requested_state)(*args, **kw):
                        return False
                    break
                else:
                    if (self.should_run_in_current_state)(*args, **kw):
                        break
            log.info("Request for {} is waiting for next subscriber to be removed".format((self.get_requested_state)(*args, **kw)))
            await self.subscriber_removed_event.wait()
            self.subscriber_removed_event.clear()

        (self.add_subscriber)(*args, **kw)
        return True

    def unsubscribe(self, **kw):
        (self.remove_subscriber)(**kw)
        self.subscriber_removed_event.set()

    @abstractmethod
    def should_run_in_current_state(self, *args, **kw) -> bool:
        return

    @abstractmethod
    def should_set_requested_state(self, *args, **kw) -> bool:
        return

    @abstractmethod
    def add_subscriber(self, *args, **kw):
        return

    @abstractmethod
    def remove_subscriber(self, *args, **kw):
        return

    @abstractmethod
    def get_requested_state(self, *args, **kw) -> str:
        return

    @abstractmethod
    def get_current_state(self, *args, **kw) -> Optional[str]:
        return

    @abstractmethod
    async def set_requested_state(self, *args, **kw) -> bool:
        return

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/resources/subscription.pyc
