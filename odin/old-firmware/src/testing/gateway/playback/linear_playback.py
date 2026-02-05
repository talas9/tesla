# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/testing/gateway/playback/linear_playback.py
import yaml, logging, importlib, json
from collections import defaultdict
from . import AbstractGatewayPlayback
log = logging.getLogger(__name__)

class LinearGatewayPlayback(AbstractGatewayPlayback):

    def __init__(self):
        super().__init__()
        self._playback_buffer = defaultdict(list)

    def _load_fixture_into_buffer(self, raw: dict):
        raw_array = [
         None] * len(raw)
        for k, v in raw.items():
            raw_array[int(k)] = v

        self._playback_buffer.clear()
        for entry in raw_array:
            index_key = self._generate_index_key(entry["bus_id"], entry["message_id"])
            self._playback_buffer[index_key].append(entry)

        log.debug("Fixture loaded: {}".format(self._playback_buffer))

    def load_fixture_from_csv_list(self, csv_list: list):
        raw = {}
        for counter, csv in enumerate(csv_list):
            values = csv.split(",")
            direction = values[0]
            bus_id = int(values[1], 16)
            message_id = int(values[2], 16)
            payload = None if values[3] == "None" else values[3]
            obj = {
             'bus_id': bus_id, 
             'message_id': message_id, 
             'type': direction, 
             'data': payload, 
             'exception': None}
            raw[counter] = obj
            counter += 1

        self._load_fixture_into_buffer(raw)

    def load_fixture_from_file(self, filepath: str):
        with open(filepath, "r") as fp:
            raw = yaml.load(fp)
        self._load_fixture_into_buffer(raw)

    def mock_read(self, bus_id: int, message_id: int) -> bytes:
        index_key = self._generate_index_key(bus_id, message_id)
        if index_key in self._playback_buffer:
            first_in_line = self._playback_buffer[index_key][0] if len(self._playback_buffer[index_key]) > 0 else None
            if first_in_line:
                if first_in_line["type"] == self.RECV_KEY:
                    exception, payload = self._deserialize_entry(first_in_line)
                    self._playback_buffer[index_key].pop(0)
                    if exception:
                        raise exception
                    return payload
        raise RuntimeError("Unable to find RECV message for bus_id={} message_id={}. Current queue for bus/msg={}".format(bus_id, message_id, self._playback_buffer.get(index_key)))

    def mock_send(self, bus_id, message_id, payload):
        index_key = self._generate_index_key(bus_id, message_id)
        if index_key in self._playback_buffer:
            first_in_line = self._playback_buffer[index_key][0] if len(self._playback_buffer[index_key]) > 0 else None
            if first_in_line:
                if first_in_line["type"] == self.TRANSMIT_KEY:
                    if first_in_line["data"] == payload.hex():
                        exception, _ = self._deserialize_entry(first_in_line)
                        self._playback_buffer[index_key].pop(0)
                        return exception
        raise RuntimeError("Unable to find TRANSMIT message for bus_id={} message_id={} payload={}. Current queue for bus/msg={}".format(bus_id, message_id, str(payload), self._playback_buffer.get(index_key)))

    @staticmethod
    def _generate_index_key(bus_id: int, message_id: int) -> str:
        return "{0}-{1}".format(int(bus_id), message_id)

    @staticmethod
    def _deserialize_entry(entry: dict) -> (Exception, bytes):
        exception = AbstractGatewayPlayback._deserialize_to_exception(entry["exception"])
        payload = bytes.fromhex(entry["data"]) if entry["data"] else bytes()
        return (exception, payload)

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/testing/gateway/playback/linear_playback.pyc
