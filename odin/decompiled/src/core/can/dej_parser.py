# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/can/dej_parser.py
import logging
from typing import Dict, Optional
from odin.core.can.exceptions import DuplicateMessageFound, DuplicateSignalFound
log = logging.getLogger(__name__)

def add_to_library(data: Dict, library: Dict) -> Dict:
    buses = library.setdefault("buses", {})
    bus_meta = data["busMetadata"]
    bus_name = bus_meta["name"].lower()
    bus_id = bus_meta["id"]
    buses[bus_name] = bus_id
    messages = library.setdefault("messages", {})
    signals = library.setdefault("signals", {})
    for message_name, message in data["messages"].items():
        message_signals = message.get("signals", {})
        curr_message = messages.setdefault(message_name, {})
        if bus_name in curr_message:
            raise DuplicateMessageFound(message_name, bus_name)
        else:
            curr_message[bus_name] = message
        multiplexer = has_multiplexer(message)
        if multiplexer:
            data["messages"][message_name]["muxer"] = multiplexer
        for signal_name, signal in message_signals.items():
            signal["message_name"] = message_name
            curr_signal = signals.setdefault(signal_name, {})
            if bus_name in curr_signal:
                raise DuplicateSignalFound(message_name, bus_name)
            else:
                curr_signal[bus_name] = signal

    return library


def has_multiplexer(message: Dict) -> Optional[str]:
    signals = message.get("signals")
    for signal_name in signals:
        if signals[signal_name].get("is_muxer", False):
            return signal_name

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/can/dej_parser.pyc
