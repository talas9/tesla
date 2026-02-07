# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/__init__.py
__authors__ = [
 ('Toolbox Devs', 'toolbox-devs@tesla.com')]
__author__ = ",".join(x[0] for x in __authors__)
__email__ = ",".join(x[1] for x in __authors__)
__copyright__ = "Copyright Tesla Motors Inc. 2017"
__license__ = "proprietary"
try:
    from ._version import __major__, __minor__, __revision__, __hash__
except ImportError:
    __major__, __minor__, __revision__, __hash__ = (0, 0, 0, '')

__version_info__ = (__major__, __minor__, __revision__)
__version__ = ("{0}.{1}.{2}".format)(*__version_info__)
import logging, os, sys, aiohttp
from dbus_next.aio import MessageBus
from dbus_next.message_bus import BusType
from .config import options
from . import nodes
from .exceptions import MissingData
from .services import *
from .core.patch.loader import is_mounted, MOUNT_TARGET
from .core.orchestrator.locks import method_lock
__platform__ = None
aiohttp_session = None
system_dbus = None
aiohttp_unix_session = None
platform_info = None
DEFAULT_FW_VERSION = "default_fw_version"
log = logging.getLogger(__name__)

async def cleanup():
    await close_http_session()
    await close_unix_http_session()


async def close_http_session():
    global aiohttp_session
    if aiohttp_session:
        if not aiohttp_session.closed:
            await aiohttp_session.close()
    aiohttp_session = None


async def close_unix_http_session():
    global aiohttp_unix_session
    if aiohttp_unix_session:
        if not aiohttp_unix_session.closed:
            await aiohttp_unix_session.close()
    aiohttp_unix_session = None


def configure_as(platform_name: str, fw_version: str='') -> bool:
    global __platform__
    global platform_info
    curr_fw_version = options["core"]["fw_version"]
    if __platform__ == platform_name:
        if fw_version in (curr_fw_version, ""):
            return bool(__platform__)
    platform_info = None
    pkg_name = "odin.platforms.{0}".format(platform_name)
    __import__(pkg_name)
    module = sys.modules[pkg_name]
    __platform__ = platform_name
    options["core"]["platform"] = platform_name
    if fw_version:
        options["core"]["fw_version"] = fw_version.split(" ")[0]
    network_module = get_network_module()
    network_path = get_network_path()
    if network_module:
        update_sys_path(network_path)
    return module.configure()


async def get_http_session() -> aiohttp.ClientSession:
    global aiohttp_session
    if not aiohttp_session or aiohttp_session.closed:
        aiohttp_session = aiohttp.ClientSession()
    return aiohttp_session


@method_lock()
async def get_system_dbus() -> MessageBus:
    global system_dbus
    if not system_dbus or not system_dbus.connected:
        log.info("Connecting to system dbus")
        system_dbus = await MessageBus(bus_type=(BusType.SYSTEM)).connect()
    return system_dbus


async def get_unix_http_session(unix_socket: str=None) -> aiohttp.ClientSession:
    global aiohttp_unix_session
    if aiohttp_unix_session:
        connector = aiohttp_unix_session.connector
        if connector.path != unix_socket:
            aiohttp_unix_session.close()
    if not aiohttp_unix_session or aiohttp_unix_session.closed:
        conn = aiohttp.UnixConnector(path=unix_socket)
        aiohttp_unix_session = aiohttp.ClientSession(connector=conn)
    return aiohttp_unix_session


def get_resource_path(relpath: str) -> str:
    if options["core"]["resource_path"]:
        return os.path.join(options["core"]["resource_path"], relpath)
    else:
        if getattr(sys, "frozen", False):
            return os.path.join(sys._MEIPASS, relpath)
        return os.path.join(os.path.dirname(__file__), relpath)


def get_metadata_path(target_platform: str='') -> str:
    artifacts_path = options["core"]["artifacts_path"]
    base_path = options["core"]["metadata_path"] or os.path.join(artifacts_path, "data")
    odin_platform = target_platform if target_platform else options["core"]["platform"]
    default_fw_platform = dict([(p, p.replace("_", " ").title().replace(" ", "")) for p in set(options["core"]["supported_platforms"].values())])
    fw_platform = default_fw_platform.get(odin_platform, "platform_not_defined")
    fw_version = options["core"]["fw_version"] or DEFAULT_FW_VERSION
    platform_path = os.path.join(base_path, fw_platform) % {"fw_version": fw_version}
    if not os.path.exists(platform_path):
        raise MissingData("Invalid data path {}".format(platform_path))
    return platform_path


def get_network_module() -> str:
    return options["core"]["network_module"]


def get_network_path() -> str:
    artifacts_path = options["core"]["artifacts_path"]
    path = options["core"]["network_path"]
    if os.path.ismount(MOUNT_TARGET):
        path = os.path.join(MOUNT_TARGET, "odin_bundle.zip")
    else:
        if not path:
            path = os.path.join(artifacts_path, "networks")
    fw_version = options["core"]["fw_version"] or DEFAULT_FW_VERSION
    path = path % {"fw_version": fw_version}
    if not os.path.exists(path):
        raise MissingData("Invalid network path: {}".format(path))
    return os.path.abspath(path)


def update_sys_path(network_path: str):
    bundle_string = "odin_bundle"
    remove_from_syspath(bundle_string)
    if network_path not in sys.path:
        sys.path.append(network_path)


def remove_from_syspath(substring):
    modules_paths_to_remove = [x for x in sys.path if substring in x]
    for p in modules_paths_to_remove:
        log.info("removing from syspath: {}".format(p))
        sys.path.remove(p)


if options["core"]["platform"]:
    configure_as((options["core"]["platform"]),
      fw_version=(options["core"]["fw_version"]))

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/__init__.pyc
