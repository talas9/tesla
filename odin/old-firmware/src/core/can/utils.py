# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/can/utils.py
import logging, struct
from functools import wraps
from typing import Any, Callable, Optional, Tuple
from odin.core import can
from odin.core.can.exceptions import MessageOrSignalNotInWhitelist
log = logging.getLogger(__name__)

def best_bus(obj: dict) -> Optional[can.Bus]:
    if "eth" in obj:
        return can.Bus.ETH
    for bus in can.Bus.__members__.values():
        if bus == can.Bus.ETH:
            continue
        else:
            if bus.name.lower() in obj:
                return bus
    else:
        return


def decode(data, start_position, width, signed=False, big_endian=False):
    if not data:
        return 0
    else:
        if len(data) < 8:
            data = data.ljust(8, b'\x00')
        else:
            frame = struct.unpack("{0}Q".format(">" if big_endian else "<"), data)[0]
            if big_endian:
                bits_per_byte = 8
                bits_per_can_frame = 8
                byte_num, bit_num = divmod(start_position, bits_per_byte)
                bit_offset = bits_per_byte * byte_num
                bit_offset += bits_per_byte - bit_num - 1
                bit_offset += width
                bit_index = bits_per_byte * bits_per_can_frame
                bit_index -= bit_offset
                shifted = frame >> bit_index
            else:
                shifted = frame >> start_position
        mask = 2 ** width - 1
        result = shifted & mask
        if signed:
            if result >> width - 1:
                mask = 2 ** width - 1
                return ((result ^ mask) + 1) * -1
        return result


def get_active_mux_id(message_values: dict, message_info: dict, muxer: str) -> Optional[int]:
    active_mux_id = message_values.get(muxer)
    if isinstance(active_mux_id, int):
        return active_mux_id
    else:
        return message_info.get("signals", {}).get(muxer, {}).get("value_description", {}).get(active_mux_id)


def whitelist_check(signal_or_message_name: str, signal_or_message_info: Tuple[(dict, can.Bus)]):
    signal_msg_dict, bus = signal_or_message_info
    if signal_msg_dict.get("not_in_whitelist", False):
        raise MessageOrSignalNotInWhitelist(signal_or_message_name, bus.name if bus else "None")

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/can/utils.pyc
