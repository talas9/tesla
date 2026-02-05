# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/platforms/common/__init__.py
import asyncio, logging, os
from attrdict import AttrDict
from typing import Dict, Optional
import odin
from odin.core import can, uds, cid
from odin.core.gateway.abstract import AbstractGateway
from odin.core.power.abstract import AbstractPowerInterface
from odin.core.utils import arch
from odin.platforms.platform_metadata_adapters import FilesystemPlatformMetadataAdapter
from odin.platforms.platform_metadata_ports import PlatformMetadataPort
from .dummy_power import DummyPower
from .dummy_gateway import DummyGateway
from .config_options import DefaultConfigOptions
log = logging.getLogger(__name__)
connector_info = {}
gtw_config_options = None

async def detect_platform() -> str:
    if not odin.options["core"]["onboard"]:
        return odin.options["core"].get("platform")
    else:
        car_type_alias_map = {"ModelS2": "ModelS"}
        car_type_platform_map = odin.options["core"].get("supported_platforms", {})
        log.info("Supported chassis types: {}".format(",".join(car_type_platform_map.keys())))
        try:
            chassis_type = await odin.core.cid.interface.get_chassis_type()
            if chassis_type not in car_type_platform_map:
                raise RuntimeError("Unexpected chassis type: {}".format(chassis_type))
            log.debug("Detecting platform from chassis type: {}".format(chassis_type))
            return car_type_platform_map[chassis_type]
        except (FileNotFoundError, RuntimeError):
            log.error("Failed to determine platform from chassis type")
        except:
            log.exception("Unexpected error occurred while detecting platform from chassis type")

        try:
            car_type_raw = await odin.core.cid.interface.get_data_value("VAPI_carType")
            car_type = car_type_alias_map.get(car_type_raw, car_type_raw)
            log.debug("Detecting platform from VAPI_carType: {}".format(car_type))
        except asyncio.TimeoutError:
            log.error("Could not read VAPI_carType")
            raise odin.exceptions.OdinException("Could not determine platform")

        if car_type not in car_type_platform_map:
            log.error("Could not determine platform from VAPI_carType: {} (raw:{}). Supported platforms: {}".format(car_type, car_type_raw, car_type_platform_map.keys()))
            raise odin.exceptions.OdinException("Could not determine platform, or platform not supported.")
        return car_type_platform_map[car_type]


def configure(platform: str, gateway_interface: AbstractGateway=DummyGateway, power_interface: callable=DummyPower, bus: Optional[can.Bus]=None, config_options_interface: callable=DefaultConfigOptions) -> bool:
    global connector_info
    load_udslite = False
    transport = odin.options.get("core", {}).get("transport", "gateway")
    if transport == "gateway":
        if platform in ('model_s', 'model_x'):
            if not arch.is_tegra():
                load_udslite = True
    else:
        if transport == "canapi2":
            from .canapi2 import Canapi2Gateway
            gateway_interface = Canapi2Gateway
            power_interface = DummyPower
            load_udslite = True
    odin.core.gateway.gtw_config_options = config_options_interface()
    odin.core.gateway.interface = gateway_interface()
    odin.core.power.interface = power_interface()
    can.Bus = bus
    odin.platforms.clear_architect_port()
    if load_udslite:
        from odin.core.isotp.datalink.udslite_gateway import UdsliteGatewayDatalink
        from odin.core.uds.functions_udslite import init_uds_interface
        from odin.core.isotp.udslite_service import init_isotp_interface
        odin.core.isotp.datalink_class = UdsliteGatewayDatalink
    else:
        from odin.core.isotp.datalink.gateway import GatewayDatalink
        from odin.core.uds.functions_odin import init_uds_interface
        from odin.core.isotp.service import init_isotp_interface
        odin.core.isotp.datalink_class = GatewayDatalink
    init_uds_interface()
    init_isotp_interface()
    try:
        metadata_port = platform_loader_factory(platform, bus)
    except odin.exceptions.MissingData:
        log.exception("Could not load firmware, ODIN will not function properly")
        return False
    else:
        odin.core.can.library = metadata_port.init_can_library()
        odin.core.iris_data = metadata_port.init_iris_data()
        nodes = metadata_port.init_nodes()
        odjs = metadata_port.init_odjs()
        assign_odj_objects(nodes, odjs)
        odin.core.uds.nodes = AttrDict(nodes)
        odin.core.gateway.power_map = metadata_port.init_power_map()
        connector_info = metadata_port.init_connector_info()
        return True


def platform_loader_factory(platform: str, bus: can.Bus) -> PlatformMetadataPort:
    root_path = odin.get_metadata_path()
    dej_root = os.path.abspath(os.path.join(root_path, "dej"))
    connector_info_path = os.path.abspath(os.path.join(root_path, "test-exit-codes"))
    nodes_path = os.path.join(root_path, "nodes.json")
    odj_root = os.path.join(root_path, "odj")
    power_map_path = os.path.join(root_path, "power_map.json")
    iris_path = os.path.join(root_path, "self-test-output.json")
    bus_alerts_map_path = os.path.join(root_path, "bus-alerts-map.json")
    return FilesystemPlatformMetadataAdapter.create_port(nodes_path=nodes_path, dej_root=dej_root,
      connector_info_path=connector_info_path,
      odj_root=odj_root,
      bus=bus,
      power_map_path=power_map_path,
      iris_path=iris_path,
      bus_alerts_map_path=bus_alerts_map_path)


def assign_odj_objects(nodes: Dict[(str, uds.Node)], odjs: Dict[(str, Dict)]) -> None:
    for name, node in nodes.items():
        routines = {}
        data = {}
        io_controls = {}
        for source in node.odj_sources:
            try:
                odj_objects = odjs[source]
            except KeyError:
                log.debug("could not find: {}".format(source))
            else:
                log.debug("assigning to {}: {}".format(name, source))
                routines.update(odj_objects["routines"])
                data.update(odj_objects["data"])
                io_controls.update(odj_objects["io_controls"])

        node.set_odx_spec("routines", AttrDict(routines))
        node.set_odx_spec("data", AttrDict(data))
        node.set_odx_spec("io_controls", AttrDict(io_controls))


# global gtw_config_options ## Warning: Unused global

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/platforms/common/__init__.pyc
