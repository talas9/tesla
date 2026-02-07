# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/platforms/__init__.py
import logging, os, yaml
from typing import Dict, List, Optional
import odin
from odin.core.utils import arch
from odin.core.utils.singleton import make_singleton_getter
from architect.ports.client import ClientPort
from architect.adapters.client import ModuleSimpleClient, RootRelativeSimpleClient
log = logging.getLogger(__name__)
PORT = None

def architect_client_port() -> ClientPort:
    global PORT
    return PORT or configure_architect_port()


def clear_architect_port():
    global PORT
    from odin.core.engine.tasks import clear_task_data
    PORT = None
    clear_task_data()
    architect_scripts_port.reset()


def configure_architect_port() -> ClientPort:
    global PORT
    PORT = _make_architect_port()
    return PORT


def _make_architect_port() -> ClientPort:
    network_root_path = odin.get_network_path()
    network_module = odin.get_network_module()
    log.info("create port for network_root_path={} network_module={}".format(network_root_path, network_module))
    if network_module:
        return ModuleSimpleClient.create_port(network_module)
    else:
        return RootRelativeSimpleClient.create_port(network_root_path)


def _make_architect_scripts_port() -> ClientPort:
    port = _make_architect_port()
    port.adapter.storage.adapter.extension = ".py"
    return port


architect_scripts_port = make_singleton_getter(_make_architect_scripts_port)

def get_bcast_topic_infix() -> Optional[str]:
    if not odin.options["core"]["onboard"]:
        return
    else:
        return get_platform_info().get("bcast_topic_infix")


def get_gateway_interface() -> Optional[str]:
    return get_platform_info().get("gateway_interface")


def get_network_dirs() -> List:
    network_dirs = get_platform_info().get("network_dirs") or []
    if arch.is_tegra():
        network_dirs.insert(0, "Tegra")
    return network_dirs


def get_node_dirs() -> List:
    return get_platform_info().get("node_dirs") or []


def get_platform_info() -> Dict:
    return odin.platform_info or _load_platform_info() or {}


def get_ui_portal() -> Optional[str]:
    return get_platform_info().get("ui_portal")


def _load_platform_info() -> Optional[Dict]:
    root_path = odin.get_metadata_path()
    info_path = os.path.join(root_path, "interfaces.yaml")
    with open(info_path, "r") as f:
        odin.platform_info = yaml.safe_load(f)
    return odin.platform_info

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/platforms/__init__.pyc
