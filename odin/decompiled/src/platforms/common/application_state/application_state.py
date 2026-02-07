# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/platforms/common/application_state/application_state.py
import asyncio, logging
from asyncio_extras import async_contextmanager
from typing import Optional, Set
from odin.core.resources.subscription import Subscription
from odin.platforms.common.application_state.interface import activate_application_state
from odin.core.utils.singleton import make_singleton_getter
log = logging.getLogger(__name__)

class ApplicationState(Subscription):

    def __init__(self):
        super().__init__()
        self._subscribers = dict()

    def _get_subscribed_guids(self, node_name: str) -> Set[str]:
        return self._subscribers.get(node_name, {}).get("subscribed_guids", set())

    @staticmethod
    def get_requested_state(**kw) -> str:
        return kw.get("requested_state")

    def get_current_state(self, node_name: str, **kw) -> Optional[str]:
        return self._subscribers.get(node_name, {}).get("current_state")

    def add_subscriber(self, request_guid: str, node_name: str, requested_state: str, **kw):
        log.info("Adding subscriber with guid {} for {} of node {} to {}".format(request_guid, requested_state, node_name, self._subscribers))
        self._subscribers.setdefault(node_name, {})["current_state"] = requested_state
        self._subscribers[node_name].setdefault("subscribed_guids", set()).add(request_guid)

    def remove_subscriber(self, request_guid: str, node_name: str, **kw):
        log.info("Unsubscribe node {} with guid {} from subscribers: {}".format(node_name, request_guid, self._subscribers))
        subscribed_guids = self._get_subscribed_guids(node_name)
        subscribed_guids.discard(request_guid)
        if not subscribed_guids:
            if node_name in self._subscribers:
                del self._subscribers[node_name]

    @staticmethod
    def should_run_in_current_state(**kw) -> bool:
        return False

    def should_set_requested_state(self, request_guid, node_name, requested_state, **kw):
        current_state = self._subscribers.get(node_name, {}).get("current_state")
        current_guids = self._get_subscribed_guids(node_name)
        if current_state is None:
            return True
        if current_state == requested_state:
            return True
        else:
            if len(current_guids) == 1:
                if request_guid in current_guids:
                    return True
            return False

    @staticmethod
    async def set_requested_state(**kw) -> bool:
        success = await activate_application_state(**kw)
        log.info("{} activating {} for {} with guid {}".format("Success" if success else "Failure", kw.get("requested_state"), kw.get("node_name"), kw.get("request_guid")))
        return success


application_state_subscription = make_singleton_getter(ApplicationState)

@async_contextmanager
async def application_state_context(request_guid, node_name, requested_state, initial_backoff, bootloader_backoff, timeout=5):
    try:
        state_achieved = await asyncio.wait_for(application_state_subscription().subscribe(request_guid=request_guid, node_name=node_name,
          requested_state=requested_state,
          initial_backoff=initial_backoff,
          bootloader_backoff=bootloader_backoff), timeout)
        yield state_achieved
    finally:
        application_state_subscription().unsubscribe(request_guid=request_guid, node_name=node_name)


def get_current_application_state(node_name: str) -> Optional[str]:
    return application_state_subscription().get_current_state(node_name=node_name)

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/platforms/common/application_state/application_state.pyc
