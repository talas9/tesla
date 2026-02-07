# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/power/abstract.py
import asyncio, logging
from abc import ABCMeta, abstractmethod
from asyncio_extras import async_contextmanager
from enum import EnumMeta
from typing import AsyncGenerator, Dict, Optional
from odin.core import uds
from odin.core.can import messagemonitor
from odin.core.gateway.socket import GatewaySocketConnectionTimeout
from odin.exceptions import OdinException
log = logging.getLogger(__name__)

class AbstractPowerInterface(object):
    __metaclass__ = ABCMeta

    def __init__(self):
        super().__init__()
        self.exceptions = set()
        self.current_held_power_state = None
        self.holder_task = None
        self.power_state_hierarchy = {}
        self.power_state_timeout = 6

    def cancel_holder_task(self):
        self.set_current_held_power_state(None)
        if self.holder_task:
            if not self.holder_task.done():
                self.holder_task.cancel()

    def get_current_held_power_state(self) -> Optional[str]:
        return self.current_held_power_state

    def raise_for_exceptions(self):
        if self.exceptions:
            raise OdinException("\n".join(self.exceptions))

    def set_current_held_power_state(self, power_state: Optional[EnumMeta]):
        self.current_held_power_state = power_state

    async def set_power_state(self, power_state: EnumMeta) -> bool:
        self.cancel_holder_task()
        event = asyncio.Event()
        self.holder_task = asyncio.ensure_future(self.hold_power(power_state, event))
        log.info("Waiting for power state to be set to {}".format(power_state))
        await event.wait()
        if not self.exceptions:
            log.info("Successfully set power state to {}".format(power_state))
            self.set_current_held_power_state(power_state)
            return True
        else:
            log.info("Failing to set power state to {}".format(power_state))
            return False

    async def hold_power(self, power_state: EnumMeta, event: asyncio.Event):
        self.exceptions.clear()
        try:
            try:
                async with self.hold_power_context_mgr(power_state=power_state):
                    await self.start_power_state(power_state)
                    while not self.exceptions:
                        event.set()
                        await asyncio.sleep(5)
                        await self.verify_power_state(power_state)

            except (uds.UdsException, GatewaySocketConnectionTimeout) as e:
                self.exceptions.add(str("{}: {}".format(type(e).__name__, e)))
                log.error("Failure occurred for {}: {}".format(power_state, repr(e)))
            except asyncio.CancelledError:
                log.info("Holding power for {} got cancelled".format(power_state))
            except Exception as e:
                self.exceptions.add(str("{}: {}".format(type(e).__name__, e)))
                log.error("Unknown error for {}: {}".format(power_state, repr(e)))
                raise

        finally:
            event.set()

    async def ensure_signal_on_can(self, power_state: EnumMeta, timeout_sec: float=5) -> bool:
        try:
            signal = self.power_signal_map(power_state).get("signal")
            target = self.power_signal_map(power_state).get("target")
            signal_monitor = messagemonitor.get_monitor_for_signal(signal)
            await signal_monitor.wait_for_target(signal, target, timeout=timeout_sec)
        except asyncio.TimeoutError:
            log.info("Timeout waiting for the expected CAN signal of power state {}".format(power_state))
        except Exception as e:
            log.error("Error on waiting for the expected CAN signal of power state {}: {}".format(power_state, repr(e)))
        else:
            return True
        return False

    @abstractmethod
    @async_contextmanager
    async def hold_power_context_mgr(self, *args, **kwargs) -> AsyncGenerator[(asyncio.Future, None)]:
        yield

    @abstractmethod
    def power_signal_map(self, power_state: EnumMeta) -> Dict:
        return

    @abstractmethod
    def power_state_enum(self) -> EnumMeta:
        return

    @abstractmethod
    async def start_power_state(self, power_state: EnumMeta):
        return

    @abstractmethod
    async def verify_power_state(self, power_state: EnumMeta):
        return

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/power/abstract.pyc
