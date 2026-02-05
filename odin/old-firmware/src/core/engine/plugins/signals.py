# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/engine/plugins/signals.py
import asyncio, logging, time
from typing import Dict, Optional, Union
from aiohttp import web
from odin.core import can
from odin.core.engine.messages import SignalsChanged
log = logging.getLogger(__name__)
KEEP_ALIVE_PERIOD = 120
LAST_SENT = 0
buffer = {}
added_queue = asyncio.Queue()

async def add_signals(signals: Dict[(str, Dict[(str, Union[(float, bool)])])]) -> Dict[(str, Optional[object])]:
    await keep_alive()
    values = {}
    added = False
    for name, config in signals.items():
        signal = valid_signal(name)
        if not signal:
            values[name] = None
        else:
            info = buffer.setdefault(name, {'value':None, 
             'counter':0, 
             'last_sent':time.time()})
            default_frequency = get_cycle_time(signal)
            info["frequency"] = config.get("frequency", default_frequency)
            info["on_change"] = config.get("on_change", True)
            info["counter"] += 1
            added = info["counter"] == 1
            values[name] = info["value"]

    if added:
        await added_queue.put(1)
    return values


def get_cycle_time(signal) -> int:
    message = {}
    try:
        try:
            message = can.message.find(signal["message_name"])[0]
        except KeyError:
            log.debug("Unable to get cycle time of signal")

    finally:
        return

    return message.get("cycle_time", 100)


async def keep_alive():
    global LAST_SENT
    LAST_SENT = time.time()
    await asyncio.sleep(0)


async def monitor_signals(app: web.Application):
    handler = app["odin_server.message_handler"]
    try:
        while True:
            while not (buffer and added_queue.empty()):
                await added_queue.get()

            changed = {}
            curr_time = time.time()
            values = await signal_values_from_buffer()
            for signal_name, info in list(buffer.items()):
                value = values.get(signal_name)
                frequency = info["frequency"]
                last_sent = info["last_sent"]
                if (curr_time - last_sent) * 1000 < frequency:
                    continue
                else:
                    if not info["on_change"] or info["value"] != value:
                        info["last_sent"] = curr_time
                        info["value"] = value
                        changed[signal_name] = value

            if changed:
                await handler.broadcast((SignalsChanged(changed)),
                  product_id="current",
                  ws_topic="signals")
            if curr_time - LAST_SENT > KEEP_ALIVE_PERIOD:
                log.debug("Disable signal remote monitoring - keep alive period exceeded")
                remove_signals()
            await asyncio.sleep(0.05)

    except asyncio.CancelledError:
        pass


def remove_signals(signal_names: Optional[list]=None):
    if not signal_names:
        log.debug("Clear buffer")
        buffer.clear()
    else:
        log.debug("Remove signals: {}".format(signal_names))
        for signal_name in signal_names:
            try:
                info = buffer[signal_name]
            except KeyError:
                pass
            else:
                info["counter"] -= 1
                if info["counter"] == 0:
                    del buffer[signal_name]


async def signal_values_from_buffer() -> dict:
    signal_names = list(buffer.keys())
    values = {}
    for signal in signal_names:
        try:
            try:
                value = await can.signal.read_by_name(signal)
            except (RuntimeError, asyncio.TimeoutError) as exc:
                log.error("Failed reading {}: {}".format(signal, exc))
                value = None

        finally:
            values[signal] = value

    return values


async def start_monitoring(app: web.Application) -> None:
    app["odin_server.signal_monitor"] = app.loop.create_task(monitor_signals(app))


async def stop_monitoring(app: web.Application) -> None:
    task = app["odin_server.signal_monitor"]
    task.cancel()
    await task


def valid_signal(signal_name) -> dict:
    try:
        signal, _ = can.signal.find(signal_name)
    except RuntimeError as err:
        log.debug("Unable to find signal {} with err: {}".format(signal_name, err))
    else:
        return signal


def includeme(app: web.Application) -> None:
    app.on_startup.append(start_monitoring)
    app.on_cleanup.append(stop_monitoring)

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/engine/plugins/signals.pyc
