# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/testing/gateway/recorder/__init__.py
import logging, time
from abc import ABCMeta, abstractmethod
log = logging.getLogger(__name__)

class AbstractGatewayRecorder(object):
    __metaclass__ = ABCMeta
    TRANSMIT_KEY = "TX"
    RECV_KEY = "RX"

    def __init__(self):
        return

    @abstractmethod
    def log_read(self, bus_id, message_id, payload, exception=None):
        return

    @abstractmethod
    def log_send(self, bus_id, message_id, payload, exception=None):
        return

    @abstractmethod
    def dump_logged(self):
        return

    @staticmethod
    def generate_fixture_object(type, bus_id, message_id, payload, exception, time_offset_ms=-1):
        serialized_exception = {'module':(exception.__class__).__module__,  'class':(exception.__class__).__name__,  'message':str(exception)} if exception else None
        return {'time_offset_ms':time_offset_ms, 
         'type':type, 
         'bus_id':int(bus_id), 
         'message_id':message_id, 
         'data':payload.hex() if payload else None, 
         'exception':serialized_exception}

    @classmethod
    def factory(cls, recorder_type: str, **kwargs) -> "AbstractGatewayRecorder":
        from .linear_recorder import LinearGatewayRecorder
        type_map = {"linear": LinearGatewayRecorder}
        if recorder_type in type_map:
            return (type_map[recorder_type])(**kwargs)
        raise RuntimeError("Recorder type invalid: {0}, Available: {1}".format(recorder_type, ",".join(type_map.keys())))

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/testing/gateway/recorder/__init__.pyc
