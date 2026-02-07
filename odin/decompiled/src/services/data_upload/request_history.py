# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/services/data_upload/request_history.py
from datetime import datetime
from odin.core.utils.history import History
from odin.core.utils.singleton import make_singleton_getter
from .request_lock import get_lock
get_history = make_singleton_getter(History, maxsize=20)

def make_request_info(started: float) -> dict:
    return {'started':started, 
     'finished':None, 
     'success':None, 
     'data_collector':{}}


def get_most_recent_from_history() -> dict:
    history = get_history()
    if not len(history):
        return {}
    else:
        return history.get(next(reversed(history)))


def clear_history() -> bool:
    if get_lock().locked():
        return False
    else:
        get_history().clear()
        return True


def init_request_info(guid: str):
    history = get_history()
    history[guid] = make_request_info(datetime.now().timestamp())


def get_data_collector(guid: str) -> dict:
    return get_request_info(guid).get("data_collector", {})


def set_data_collector(guid: str, data_collector: dict):
    get_request_info(guid)["data_collector"] = data_collector


def get_request_info(guid: str) -> dict:
    return get_history().get(guid, {})


def set_request_info_result(guid: str, success=False):
    request_info = get_history().get(guid)
    if request_info:
        request_info["finished"] = datetime.now().timestamp()
        request_info["success"] = success

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/services/data_upload/request_history.pyc
