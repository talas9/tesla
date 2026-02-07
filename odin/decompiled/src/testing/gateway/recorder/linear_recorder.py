# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/testing/gateway/recorder/linear_recorder.py
import logging, time, yaml
from . import AbstractGatewayRecorder
log = logging.getLogger(__name__)

class LinearGatewayRecorder(AbstractGatewayRecorder):

    def __init__(self, logfile=None):
        super().__init__()
        self._LinearGatewayRecorder__logfile = logfile
        self._sequence_number = 0
        self._start_time = int(time.time() * 1000)
        self._LinearGatewayRecorder__buffer = []
        if self._LinearGatewayRecorder__logfile is not None:
            with open(self._LinearGatewayRecorder__logfile, "w") as fp:
                fp.truncate(0)

    def log_read(self, bus_id, message_id, payload, exception=None):
        self._log_record({(self._sequence_number): (self.generate_fixture_object(self.RECV_KEY, bus_id, message_id, payload, exception, self._get_time_offset()))})
        self._sequence_number += 1

    def log_send(self, bus_id, message_id, payload, exception=None):
        self._log_record({(self._sequence_number): (self.generate_fixture_object(self.TRANSMIT_KEY, bus_id, message_id, payload, exception, self._get_time_offset()))})
        self._sequence_number += 1

    def dump_logged(self):
        return self._LinearGatewayRecorder__buffer

    @staticmethod
    def compact_log(logged, limit=500):
        result = []
        if logged:
            for log in logged:
                if log.values():
                    v = list(log.values())[0]
                    result.append("{},0x{:02X},0x{:02X},{},T={}".format(v["type"], v["bus_id"], v["message_id"], v["data"], v.get("time_offset_ms") or "?"))

        return result[-limit:]

    def _get_time_offset(self):
        t = int(time.time() * 1000)
        offset = t - self._start_time
        return offset

    def _log_record(self, obj: dict):
        self._LinearGatewayRecorder__buffer.append(obj)
        if self._LinearGatewayRecorder__logfile is not None:
            with open(self._LinearGatewayRecorder__logfile, "a") as fp:
                yaml.dump(obj, fp, default_flow_style=False)

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/testing/gateway/recorder/linear_recorder.pyc
