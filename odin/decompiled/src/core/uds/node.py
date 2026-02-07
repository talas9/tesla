# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/uds/node.py
import asyncio, logging, sys
from attrdict import AttrDict
from copy import deepcopy
from typing import Callable, Iterable, List, Optional
from odin.core import can
from odin.core.uds import security_algorithms
from odin.exceptions import MessageNotFound, MessageOrSignalNotInWhitelist
log = logging.getLogger(__name__)
registry = {}

class Node(object):

    def __init__(self, name, bus_name=can.Bus.ETH.name.lower(), boot_message_name="", data_upload="", request_message_name="", response_message_name="", security=None, bus=None, boot_message=None, response_message=None, request_message=None, node_id=None, odj_sources=None, minimum_power_state=None, variant_group=None, **kw):
        super(Node, self).__init__()
        self.name = name
        self.bus_name = bus_name
        self.boot_message_name = boot_message_name
        self.data_upload = data_upload if isinstance(data_upload, str) else ""
        self.request_message_name = request_message_name
        self.response_message_name = response_message_name
        self.node_id = len(registry) if node_id is None else node_id
        self.odj_sources = odj_sources or []
        self.minimum_power_state = minimum_power_state
        self.variant_group = variant_group
        self._Node__routines = {}
        self._Node__data = {}
        self._Node__io_controls = {}
        self._Node__bus = bus
        self._Node__boot_message = boot_message
        self._Node__request_message = request_message
        self._Node__response_message = response_message
        self._Node__security = security
        registry[self.node_id] = self
        self.lock = asyncio.Lock()
        self.uds_client = None
        self.datalink = None

    def get_bus(self) -> can.Bus:
        if type(self._Node__bus) == int:
            return can.Bus(self._Node__bus)
        else:
            return self._Node__bus or can.Bus[self.bus_name.upper()]

    def set_odx_spec(self, spec_type: str, data: dict):
        self.__setattr__("__" + spec_type, data)

    def get_odx_data_spec(self, data_name: Optional[str]=None) -> dict:
        return self._Node__get_odx_spec("data", data_name)

    def get_odx_routine_spec(self, routine_name: Optional[str]=None) -> dict:
        return self._Node__get_odx_spec("routines", routine_name)

    def get_odx_iocontrol_spec(self, iocontrol_name: Optional[str]=None) -> dict:
        return self._Node__get_odx_spec("io_controls", iocontrol_name)

    def __get_odx_spec(self, spec_type: str, odx_name) -> dict:
        if odx_name is None:
            odx_entire_spec_for_type = deepcopy(self.__getattribute__("__" + spec_type))
            odx_name_not_in_whitelist = []
            for odx_name in odx_entire_spec_for_type:
                if odx_entire_spec_for_type[odx_name].get("not_in_whitelist", False):
                    odx_name_not_in_whitelist.append(odx_name)
                odx_entire_spec_for_type[odx_name]["node_name"] = self.name

            for rm_name in odx_name_not_in_whitelist:
                del odx_entire_spec_for_type[rm_name]

            return odx_entire_spec_for_type
        else:
            odx_spec_for_name = deepcopy(self.__getattribute__("__" + spec_type)[odx_name])
            odx_spec_for_name["node_name"] = self.name
            if odx_spec_for_name.get("not_in_whitelist", False):
                raise RuntimeError("ODX name {} (node={}) is not in whitelist. Please refer to tools/odin/integration for detail as how to add signal/message to whitelist.".format(odx_name, self.name))
            return odx_spec_for_name

    def __get_message(self, msg_name: str, bus_name: str=can.Bus.ETH.name.lower()) -> AttrDict:
        lib = can.library
        msg = None
        try:
            msg_by_bus = getattr(lib.messages, msg_name)
            try:
                msg = getattr(msg_by_bus, bus_name)
            except AttributeError:
                log.warning("Failed to look up {} from the preferred bus {}".format(msg_name, bus_name))
                msg = AttrDict(next(iter(msg_by_bus.values())))

        except (KeyError, AttributeError):
            raise MessageNotFound(msg_name)
        else:
            if msg:
                if msg.get("not_in_whitelist", False):
                    raise MessageOrSignalNotInWhitelist(msg_name, bus_name)
            return msg

    def get_boot_message(self) -> AttrDict:
        return self._Node__boot_message or self._Node__get_message((self.boot_message_name), bus_name=(self.bus.name.lower()))

    def get_key(self, seed: bytes) -> bytearray:
        hash_algorithm = getattr(security_algorithms, self._Node__security["algorithm"])
        if "kw" in self._Node__security:
            key = hash_algorithm(seed, **self._Node__security["kw"])
        else:
            key = hash_algorithm(seed)
        return key

    def get_request_message(self) -> AttrDict:
        return self._Node__request_message or self._Node__get_message((self.request_message_name), bus_name=(self.bus.name.lower()))

    def get_response_message(self) -> AttrDict:
        return self._Node__response_message or self._Node__get_message(self.response_message_name)

    def get_seed_size(self) -> int:
        return self._Node__security["buffer_size"]

    def is_applicable(self) -> bool:
        qualifier = self.variant_group.get("qualifier", {})
        qualifier_file = qualifier.get("file")
        if not qualifier_file:
            log.error("qualifier file of {} variant group is not defined".format(self.name))
            return False
        qualifier_parser = qualifier.get("parser")
        if not qualifier_parser:
            log.error("qualifier parser of file {} is not defined".format(qualifier_file))
            return False
        else:
            parser = getattr(self, "_qualifier_parser_" + str(qualifier_parser))
            if not isinstance(parser, Callable):
                log.error("qualifier parser {} is not implemented".format(qualifier_parser))
                return False
            return parser(qualifier)

    def _qualifier_parser_kv_pair(self, qualifier: dict) -> bool:
        delimiter = qualifier.get("delimiter")
        key = qualifier.get("key")
        qualified_values = qualifier.get("values", [])
        try:
            with open(qualifier.get("file"), "r") as f:
                return self._parser_kv_pair_core(f, delimiter, key, qualified_values)
        except OSError as e:
            log.error(e)

        return False

    def _qualifier_parser_text_value(self, qualifier: dict) -> bool:
        try:
            with open(qualifier.get("file"), "r") as f:
                return self._parser_text_value_core(f, qualifier.get("values", []))
        except OSError as e:
            log.error(e)

        return False

    @staticmethod
    def _parser_kv_pair_core(fd: Iterable, delimiter: Optional[str], key: str, qualified_values: List) -> bool:
        for line in fd:
            item = line.strip()
            if len(item) > 0 and item[0] != "#":
                try:
                    k, v = item.split(delimiter) if delimiter else item.split()
                    if k.strip(' \t"\'') == key:
                        return v.strip(' \t"\'') in qualified_values
                except ValueError:
                    pass

        return False

    @staticmethod
    def _parser_text_value_core(fd: Iterable, qualified_values: List) -> bool:
        for line in fd:
            value = line.strip()
            if len(value) > 0:
                if value[0] != "#":
                    return value in qualified_values

        return False

    bus = property(get_bus)
    boot_message = property(get_boot_message)
    request_message = property(get_request_message)
    response_message = property(get_response_message)


def node_factory(name, **kw):
    uname = name.upper()
    lname = name.lower()
    kw.setdefault("name", uname)
    kw.setdefault("bus_name", can.Bus.ETH.name.lower())
    kw.setdefault("boot_message_name", "{0}_bootID".format(uname))
    kw.setdefault("request_message_name", "UDS_{0}Request".format(lname))
    kw.setdefault("response_message_name", "{0}_udsResponse".format(uname))
    kw.setdefault("security", {'algorithm':"tesla_hash",  'buffer_size':16})
    kw.setdefault("odj_sources", ["{}.odj".format(uname)])
    log.debug("Creating node with {}".format(kw))
    return Node(**kw)

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/uds/node.pyc
