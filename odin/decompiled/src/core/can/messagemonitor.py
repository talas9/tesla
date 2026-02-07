# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/can/messagemonitor.py
import asyncio
from collections import defaultdict
import logging
from typing import Callable, Dict, Optional, Set
from odin.core import can
MsgSpec = Dict[(str, can.signal.CanSignalValue)]
log = logging.getLogger(__name__)
_monitors = {}

class CANMessageMonitor:

    def __init__(self, can_message: str):
        self.enabled = False
        self.monitor_event = asyncio.Event()
        self.subscribers = defaultdict(list)
        self.can_message = can_message

    async def wait_for_target(self, signal_name: str, target_values: list, read_interval: Optional[float]=None, timeout: float=0, minimum_sample_count: int=1):
        event = asyncio.Event()
        consec_sample_count = 0
        intervals = [i for i in target_values if self._is_interval(i)]

        def callback(state=None):
            nonlocal consec_sample_count
            if state in target_values:
                consec_sample_count += 1
            elif self._is_numeric(state):
                if any([i[0] <= state <= i[1] for i in intervals]):
                    consec_sample_count += 1
                else:
                    if consec_sample_count > 0:
                        log.debug("Count reset. Reason=state not in value. state={}, target={}".format(state, target_values))
                    consec_sample_count = 0
            if consec_sample_count >= minimum_sample_count:
                event.set()

        self.subscribe(signal_name, callback, read_interval)
        try:
            await asyncio.wait_for((event.wait()), timeout=(None if timeout == 0 else timeout))
        finally:
            self.unsubscribe(signal_name, callback)

    def available_signals(self) -> Set[str]:
        try:
            message, bus = can.message.find(self.can_message)
        except RuntimeError as err:
            log.debug("Failed determining valid signals: {}".format(err))
            return set()
        else:
            available_signals = message.get("signals", {})
            return set(available_signals.keys())

    def subscribe(self, signal_name: str, callback: Callable, read_interval: Optional[float]=None):
        if not self.enabled:
            asyncio.ensure_future(self._monitor_message(read_interval))
            self.enabled = True
        self.subscribers[signal_name].append(callback)
        self.monitor_event.set()

    def unsubscribe(self, signal_name: str, callback: Callable):
        if signal_name in self.subscribers:
            try:
                self.subscribers[signal_name].remove(callback)
            except ValueError:
                pass

        else:
            if not len(self.subscribers[signal_name]):
                del self.subscribers[signal_name]
            if not len(self.subscribers):
                self.monitor_event.clear()

    async def _monitor_message(self, read_interval: Optional[float]=None):
        cycle_time = read_interval if read_interval is not None else self._get_cycle_time()
        try:
            while True:
                await self.monitor_event.wait()
                values = await self._read_can_message(cycle_time)
                self._notify_subscribers(values)
                await asyncio.sleep(cycle_time)

        except asyncio.CancelledError:
            pass

    def _notify_subscribers(self, values: MsgSpec):
        for signal_name, callbacks in self.subscribers.items():
            value = values.get(signal_name)
            for callback in callbacks:
                callback(state=value)

    def _get_cycle_time(self) -> float:
        try:
            message_spec = can.message.find(self.can_message)
            return message_spec[0]["cycle_time"] / 1000
        except (IndexError, KeyError, RuntimeError):
            return 1.0

    async def _read_can_message(self, cycle_time: float) -> MsgSpec:
        try:
            message_spec = can.message.find(self.can_message)
            return await (can.message.read)(*message_spec, **{"timeout": (2 * cycle_time)})
        except asyncio.TimeoutError as e:
            log.debug('Timed out reading CAN message "{}": {}'.format(self.can_message, e))
        except RuntimeError as e:
            log.error('Error reading CAN message "{}": {}'.format(self.can_message, e))

        return {}

    @staticmethod
    def _is_numeric(obj: object):
        return isinstance(obj, (int, float))

    def _is_interval(self, obj: object):
        if not isinstance(obj, (list, tuple)) or len(obj) != 2:
            return False
        else:
            if not self._is_numeric(obj[0]) or not self._is_numeric(obj[1]):
                return False
            return obj[0] <= obj[1]


def get_monitor(can_message: str) -> CANMessageMonitor:
    global _monitors
    return _monitors.setdefault(can_message, CANMessageMonitor(can_message))


def get_monitor_for_signal(can_signal: str) -> CANMessageMonitor:
    signal, _ = can.signal.find(can_signal)
    return get_monitor(signal["message_name"])

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/can/messagemonitor.pyc
