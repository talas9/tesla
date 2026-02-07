# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/testing/gateway/playback/__init__.py
import logging, importlib
from abc import ABCMeta, abstractmethod
log = logging.getLogger(__name__)

class AbstractGatewayPlayback(object):
    __metaclass__ = ABCMeta
    TRANSMIT_KEY = "TX"
    RECV_KEY = "RX"

    def __init__(self):
        return

    @abstractmethod
    def mock_read(self, bus_id: int, message_id: int) -> bytes:
        return

    @abstractmethod
    def mock_send(self, bus_id: int, message_id: int, payload: bytes):
        return

    @staticmethod
    def _deserialize_to_exception(exception: dict) -> Exception:
        if exception:
            exception_class = getattr(importlib.import_module(exception.get("module")), exception.get("class"))
            return exception_class(exception.get("message"))
        else:
            return

    @staticmethod
    def _record_object_to_string(fixtureObject: dict) -> str:
        return "type={0}, bus_id={1}, message_id={2}, data={3}, exception={4}".format(fixtureObject.get("type"), fixtureObject.get("bus_id"), fixtureObject.get("message_id"), fixtureObject.get("data"), fixtureObject.get("exception"))

    @classmethod
    def factory(cls, playback_type: str, **kwargs) -> "AbstractGatewayPlayback":
        from .linear_playback import LinearGatewayPlayback
        type_map = {"linear": LinearGatewayPlayback}
        if playback_type in type_map:
            return (type_map[playback_type])(**kwargs)
        raise RuntimeError("Playback type invalid: {0}, Available: {1}".format(playback_type, ",".join(type_map.keys())))

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/testing/gateway/playback/__init__.pyc
