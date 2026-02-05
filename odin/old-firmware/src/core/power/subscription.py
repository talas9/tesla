# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/power/subscription.py
import asyncio, logging
from asyncio_extras import async_contextmanager
from enum import EnumMeta
from typing import Optional
from odin.exceptions import OdinException
from odin.core.resources.subscription import Subscription
from odin.core.utils.singleton import make_singleton_getter
from odin.core import power
log = logging.getLogger(__name__)

class PowerStateTimeout(OdinException):
    return


class PowerStateSubscriber:

    def __init__(self, power_state: EnumMeta, allow_higher: bool=True):
        self.power_state = power_state
        self.allow_higher = allow_higher


class PowerState(Subscription):

    def __init__(self):
        super().__init__()
        self._subscribers = set()

    def _get_subscribers(self) -> list:
        return [subscriber.power_state for subscriber in self._subscribers]

    @staticmethod
    def get_requested_state(**kw) -> Optional[EnumMeta]:
        subscriber = kw.get("subscriber")
        if isinstance(subscriber, PowerStateSubscriber):
            return subscriber.power_state

    @staticmethod
    def get_current_state(**kw) -> Optional[EnumMeta]:
        current = power.interface.get_current_held_power_state()
        if current in power.interface.power_state_enum():
            return current

    def add_subscriber(self, subscriber: PowerStateSubscriber):
        log.info("Adding subscriber to {} to current set of subscribers {}".format(subscriber.power_state, self._get_subscribers()))
        self._subscribers.add(subscriber)

    def remove_subscriber(self, subscriber: PowerStateSubscriber):
        log.info("Removing: {} with allowed_higher: {} from current subscribers: {}".format(subscriber.power_state, subscriber.allow_higher, str(self._get_subscribers())))
        self._subscribers.discard(subscriber)
        if not self._subscribers:
            power.interface.cancel_holder_task()

    @staticmethod
    async def set_requested_state(subscriber: PowerStateSubscriber) -> bool:
        return await power.interface.set_power_state(subscriber.power_state)

    @staticmethod
    def should_run_in_current_state(subscriber: PowerStateSubscriber) -> bool:
        if power.interface.get_current_held_power_state() is None:
            log.error("Current state is None")
            return False
        else:
            if power.interface.get_current_held_power_state() == subscriber.power_state:
                log.debug("Requested state matches with current: {}".format(subscriber.power_state))
                return True
            if power.interface.get_current_held_power_state() == power.interface.power_state_hierarchy.get(subscriber.power_state):
                if subscriber.allow_higher:
                    log.debug("Requested state {} is allowed to run in the current held higher state: {}".format(subscriber.power_state, power.interface.get_current_held_power_state()))
                    return True
            return False

    def should_set_requested_state(self, subscriber: PowerStateSubscriber) -> bool:
        if not self._subscribers:
            log.debug("Any subscribers")
            return True
        else:
            if power.interface.get_current_held_power_state() is None:
                log.debug("Current power state is undefined")
                return True
            if self._can_switch_higher(subscriber.power_state):
                log.debug("Allowed to switch to higher. Requested {}, subscribed: {}".format(subscriber.power_state, self._get_subscribers()))
                return True
            return False

    def _can_switch_higher(self, power_state: EnumMeta) -> bool:
        return self._is_request_higher_than_current(power_state) and self._all_subscribers_allow_higher()

    @staticmethod
    def _is_request_higher_than_current(requested_power_state: EnumMeta) -> bool:
        current = power.interface.get_current_held_power_state()
        if current is None:
            log.error("Current power state is falsely undefined")
            return True
        else:
            if power.interface.power_state_hierarchy.get(power.interface.get_current_held_power_state()) == requested_power_state:
                log.debug("Requested state: {} is higher than current power state {}".format(requested_power_state, power.interface.get_current_held_power_state()))
                return True
            return False

    def _all_subscribers_allow_higher(self) -> bool:
        return all([subscriber.allow_higher for subscriber in self._subscribers])


power_state_subscription = make_singleton_getter(PowerState)

@async_contextmanager
async def power_context(power_state: EnumMeta, allow_higher: bool=True, timeout: Optional[float]=None):
    log.debug("Try entering power context of: {}".format(power_state))
    subscriber = PowerStateSubscriber(power_state, allow_higher)
    if timeout is None:
        timeout = power.interface.power_state_timeout
    try:
        try:
            await asyncio.wait_for(power_state_subscription().subscribe(subscriber=subscriber), timeout=timeout)
            power.interface.raise_for_exceptions()
            yield
        except asyncio.TimeoutError:
            raise PowerStateTimeout("Power state {} can not be set in {} seconds. Active state: {}".format(power_state, timeout, power.interface.get_current_held_power_state()))

    finally:
        power_state_subscription().unsubscribe(subscriber=subscriber)

    power.interface.raise_for_exceptions()

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/power/subscription.pyc
