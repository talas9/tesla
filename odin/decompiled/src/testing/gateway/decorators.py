# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/testing/gateway/decorators.py
from . import is_testing_enabled, get_playback_instance, get_recorder_instance
from functools import wraps

def gateway_send_hook(send_message: callable) -> callable:

    @wraps(send_message)
    def wrapper(*args, **kwargs):
        bus_id = args[1]
        message_id = args[2]
        data = args[3]
        player = None
        recorder = get_recorder_instance()
        if is_testing_enabled():
            player = get_playback_instance()
        if player:
            ex = player.mock_send(bus_id, message_id, data)
            if ex is not None:
                raise ex
            return True
        else:
            exception = None
            result = False
            try:
                result = send_message(*args, **kwargs)
            except Exception as ex:
                exception = ex

            if recorder is not None:
                recorder.log_send(bus_id, message_id, data, exception)
            if exception is not None:
                raise exception
            return result

    return wrapper


def gateway_send_hook_async(send_message: callable) -> callable:

    @wraps(send_message)
    async def wrapper(*args, **kwargs):
        bus_id = args[1]
        message_id = args[2]
        data = args[3]
        player = None
        recorder = get_recorder_instance()
        if is_testing_enabled():
            player = get_playback_instance()
        if player:
            ex = player.mock_send(bus_id, message_id, data)
            if ex is not None:
                raise ex
            return True
        else:
            exception = None
            result = False
            try:
                result = await send_message(*args, **kwargs)
            except Exception as ex:
                exception = ex

            if recorder is not None:
                recorder.log_send(bus_id, message_id, data, exception)
            if exception is not None:
                raise exception
            return result

    return wrapper


def gateway_read_hook_async(read_message: callable) -> callable:

    @wraps(read_message)
    async def wrapper(*args, **kwargs):
        bus_id = args[1]
        message_id = args[2]
        player = None
        recorder = get_recorder_instance()
        if is_testing_enabled():
            player = get_playback_instance()
        if player:
            return player.mock_read(bus_id, message_id)
        else:
            result = None
            exception = None
            try:
                result = await read_message(*args, **kwargs)
            except Exception as ex:
                exception = ex

            if recorder is not None:
                recorder.log_read(bus_id, message_id, result, exception)
            if exception is not None:
                raise exception
            return result

    return wrapper


def gateway_read_hook(read_message: callable) -> callable:

    @wraps(read_message)
    def wrapper(*args, **kwargs):
        bus_id = args[1]
        message_id = args[2]
        player = None
        recorder = get_recorder_instance()
        if is_testing_enabled():
            player = get_playback_instance()
        if player:
            return player.mock_read(bus_id, message_id)
        else:
            result = None
            exception = None
            try:
                result = read_message(*args, **kwargs)
            except Exception as ex:
                exception = ex

            if recorder is not None:
                recorder.log_read(bus_id, message_id, result, exception)
            if exception is not None:
                raise exception
            return result

    return wrapper

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/testing/gateway/decorators.pyc
