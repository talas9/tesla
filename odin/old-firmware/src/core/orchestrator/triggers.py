# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/orchestrator/triggers.py
import asyncio
from collections import defaultdict
import logging, os
from odin.core.cid.interface import filesystem
from . import settings
log = logging.getLogger(__name__)
_TRIGGERS_DIR = os.path.join(settings._ORCHESTRATOR_ROOT_SETTINGS_DIR, "triggers")
_loaded_triggers = defaultdict(asyncio.Event)
_did_load_triggers = False

async def wait_for_any_trigger(triggers: list):
    futures = [asyncio.ensure_future(wait_for_trigger(t)) for t in triggers]
    done, pending = await asyncio.wait(futures, return_when=(asyncio.FIRST_COMPLETED))
    for f in pending:
        f.cancel()


async def wait_for_triggers(triggers: list):
    await (asyncio.gather)(*[wait_for_trigger(t) for t in triggers])


async def wait_for_trigger(trigger: str):
    trigger_event = await get_trigger_event(trigger)
    await trigger_event.wait()


async def set_triggers(triggers: list):
    await (asyncio.gather)(*[set_trigger(t, sync_filesystem=False) for t in triggers])
    await filesystem.sync()


async def set_trigger(trigger: str, sync_filesystem: bool=True):
    if len(trigger) < 1:
        raise ValueError("Invalid trigger provided: trigger name is empty")
    else:
        if os.path.basename(trigger) != trigger:
            raise ValueError("Invalid trigger provided: {}".format(trigger))
    trigger_path = os.path.join(_TRIGGERS_DIR, trigger)
    await filesystem.mkdir(_TRIGGERS_DIR, parents=True, exist_ok=True)
    await filesystem.touch(trigger_path)
    if sync_filesystem:
        await filesystem.sync()
    _loaded_triggers[trigger].set()
    log.info("Trigger was set: {}".format(trigger))


async def get_trigger_event(trigger: str) -> asyncio.Event:
    global _did_load_triggers
    if not _did_load_triggers:
        _did_load_triggers = True
        await _load_triggers()
    return _loaded_triggers[trigger]


async def _load_triggers():
    try:
        triggers_paths = await filesystem.list_dir(_TRIGGERS_DIR)
    except FileNotFoundError:
        log.debug("Triggers directory does not exist, defaulting to no set triggers")
        triggers_paths = []

    triggers = [t.name for t in triggers_paths]
    for trigger in triggers:
        _loaded_triggers[trigger].set()

    log.info("Loaded triggers: {}".format(", ".join(triggers)))

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/orchestrator/triggers.pyc
