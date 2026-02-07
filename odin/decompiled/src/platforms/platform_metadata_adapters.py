# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/platforms/platform_metadata_adapters.py
import json, logging, os, re
from abc import ABCMeta, abstractmethod
from enum import IntEnum
from fnmatch import fnmatch
from attrdict import AttrDict
from typing import Dict
import odin
from odin.adapter import Adapter
from odin.core.can import dej_parser, bus_alerts_map_parser
from odin.core.uds.node import node_factory
from odin.core.uds.node import Node
from odin.platforms import get_network_dirs
from odin.platforms.platform_metadata_ports import PlatformMetadataPort
log = logging.getLogger(__name__)

class PlatformMetadataAdapters(Adapter, metaclass=ABCMeta):
    port_class = PlatformMetadataPort

    @abstractmethod
    def init_can_library(self) -> None:
        return

    @abstractmethod
    def init_connector_info(self):
        return

    @abstractmethod
    def init_nodes(self) -> AttrDict:
        return

    @abstractmethod
    def init_odjs(self) -> AttrDict:
        return

    @abstractmethod
    def init_power_map(self) -> AttrDict:
        return


class FilesystemPlatformMetadataAdapter(PlatformMetadataAdapters):

    def __init__(self, nodes_path, dej_root, connector_info_path, odj_root, bus, power_map_path, iris_path, bus_alerts_map_path):
        self.nodes_path = nodes_path
        self.connector_info_path = connector_info_path
        self.dej_root = dej_root
        self.odj_root = odj_root
        self.bus = bus
        self.power_map_path = power_map_path
        self.iris_path = iris_path
        self.bus_alerts_map_path = bus_alerts_map_path
        self._binary_metadata_reader = self._try_import_binary_metadata_reader()

    @staticmethod
    def _try_import_binary_metadata_reader():
        try:
            from odin.platforms.binary_metadata_utils import binary_metadata_reader
            return binary_metadata_reader
        except ImportError:
            log.warning("Binary metadata reader not found.")
            return

    def init_iris_data(self) -> Dict:
        task_directory = os.path.join(get_network_dirs()[0], "tasks", "")
        iris_data = {}
        try:
            with open(self.iris_path, "r") as f:
                iris_raw_data = json.load(f)
            for self_test_data in iris_raw_data:
                task_name = self._get_iris_task_name(self_test_data["file"], task_directory)
                connectors_raw = self_test_data.get("dependencies", {}).get("connectors", [])
                connectors = [connector["name"] for connector in connectors_raw]
                exit_codes = self_test_data.get("exit_codes", {})
                iris_data[task_name] = {'connectors':connectors, 
                 'exit_codes':exit_codes}

        except FileNotFoundError:
            log.exception("Could not find Iris info json: {}".format(self.iris_path))
        except json.JSONDecodeError:
            log.exception("Iris info json is corrupt: {}".format(self.iris_path))

        return iris_data

    @staticmethod
    def _get_iris_task_name(task_name: str, platform_task_directory: str):
        task = os.path.splitext(task_name)[0]
        split_task_name = task_name.split("/")
        if len(split_task_name) > 1:
            return task
        else:
            return os.path.join(platform_task_directory, task)

    @staticmethod
    def _json_reader(full_path: str):
        with open(full_path, "r") as fp:
            return json.load(fp)

    def init_can_library(self) -> AttrDict:
        if not os.path.exists(self.dej_root):
            log.warning("DEJ directory doesn't exist: {}".format(self.dej_root))
            return AttrDict()
        else:
            library = {}
            filter = re.compile("^[A-Za-z0-9]+._([A-Z0-9]{2,8})\\.compact\\.json.*$")
            for file in os.listdir(self.dej_root):
                match = filter.match(file)
                if match:
                    read_function = None
                    if file.endswith(".compact.json"):
                        read_function = self._json_reader
                    else:
                        if file.endswith(".compact.json.bin"):
                            read_function = self._binary_metadata_reader
                    full_path = os.path.join(self.dej_root, file)
                    log.debug("loading file: {0}".format(full_path))
                    if read_function is None:
                        log.warning("Skipped. No suitable reader for file: {}".format(full_path))
                        continue
                    jdata = read_function(full_path)
                    bus_meta = jdata.get("busMetadata", {})
                    file_bus_name = match.groups()[0].lower()
                    bus_name = bus_meta.get("name", file_bus_name)
                    enum_bus_id = int(self.bus[bus_name.upper()]) if bus_name.upper() in self.bus.__members__ else -1
                    bus_id = bus_meta.get("id", enum_bus_id)
                    jdata["busMetadata"] = {'name':bus_name, 
                     'id':bus_id}
                    dej_parser.add_to_library(jdata, library)

            if not library:
                raise FileNotFoundError(os.path.join(self.dej_root, "*.compact.json*"))
            try:
                with open(self.bus_alerts_map_path, "r") as f:
                    hashed_bus_alerts_map = json.load(f)
            except FileNotFoundError:
                log.exception("Could not find bus-to-alerts map json: {}".format(self.bus_alerts_map_path))
            except json.JSONDecodeError:
                log.exception("Bus-to-alerts map json is corrupt: {}".format(self.bus_alerts_map_path))
            else:
                bus_alerts_map_parser.add_to_library(hashed_bus_alerts_map, library)
            return AttrDict(library)

    def init_connector_info(self) -> Dict:
        connector_map = {}
        try:
            file_list = [item for item in os.listdir(self.connector_info_path) if fnmatch(item, "*.json")]
        except FileNotFoundError:
            log.exception("Could not find directory: {}".format(self.connector_info_path))
            return {}
        else:
            for file in file_list:
                with open(os.path.join(self.connector_info_path, file)) as f:
                    try:
                        exit_code_list = json.load(f)
                    except json.JSONDecodeError:
                        log.exception("{} is corrupt".format(file))
                    else:
                        file_map = {}
                        for item in exit_code_list:
                            key = int(str(item.pop("exit_code")), 16)
                            file_map[key] = item

                        connector_map[file] = file_map

            return connector_map

    def init_nodes(self) -> AttrDict:
        if not os.path.exists(self.nodes_path):
            log.warning("Nodes directory doesn't exist: {}".format(self.nodes_path))
            return AttrDict()
        else:
            nodes = AttrDict()
            with open(self.nodes_path, "r") as f:
                node_defs = json.load(f)
            variant_group_nodes = {}
            for name, overrides in node_defs.items():
                name = overrides.get("variant_group", {}).get("node_name", name)
                node_obj = node_factory(name, **overrides)
                if node_obj.variant_group:
                    variant_group_nodes.setdefault(name, []).append(node_obj)
                else:
                    nodes[name] = node_obj

            for name, variant_nodes in variant_group_nodes.items():
                node = self.get_applicable_node(variant_nodes)
                if node:
                    nodes[name] = node

            return nodes

    @staticmethod
    def get_applicable_node(nodes: list) -> Node:
        default = None
        for node in nodes:
            if node.variant_group.get("default"):
                default = node
            else:
                if node.is_applicable():
                    return node

        if default is None:
            raise RuntimeError("default node in variant group must be defined: {}".format([node.name for node in nodes]))
        return default

    def init_odjs(self) -> AttrDict:
        if not os.path.exists(self.odj_root):
            log.warning("ODJ directory doesn't exist: {}".format(self.odj_root))
            return AttrDict()
        else:
            odj_files = AttrDict()
            for root, dirs, files in os.walk(self.odj_root):
                for file in files:
                    read_function = None
                    if file.endswith(".odj"):
                        read_function = self._json_reader
                    else:
                        if file.endswith(".odj.bin"):
                            read_function = self._binary_metadata_reader
                    full_path = os.path.join(self.odj_root, file)
                    if read_function is None:
                        log.warning("Skipped. No suitable reader for file: {}".format(full_path))
                        continue
                        index_file_name = file if file.endswith(".odj") else file.replace(".odj.bin", ".odj")
                        odj_files[index_file_name] = read_function(full_path)

            return odj_files

    def init_power_map(self) -> AttrDict:
        raw_power_map = []
        try:
            with open(self.power_map_path, "r") as power_map_file:
                raw_power_map = json.load(power_map_file)
        except FileNotFoundError:
            log.exception("Could not find power map json: {}".format(self.power_map_path))
        except json.JSONDecodeError:
            log.exception("Power map json is corrupt: {}".format(self.power_map_path))

        return AttrDict(raw_power_map)


messages_port = FilesystemPlatformMetadataAdapter.create_port

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/platforms/platform_metadata_adapters.pyc
