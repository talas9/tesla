# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/odx/interface.py
import logging, time
from typing import Any, Generator, Tuple
from odin.core import uds
from odin.core.utils import payload
log = logging.getLogger(__name__)

def find_by_id(odj_objects: dict, hex_id: int) -> Tuple[(str, dict)]:
    for odj_object_name, odj_object in odj_objects.items():
        if int(odj_object["hex_id"], 16) == hex_id:
            __odx_whitelist_check(odj_object, odj_object_name, hex_id)
            return (odj_object_name, odj_object)
    else:
        raise RuntimeError("could not find hex id: 0{:x}".format(hex_id))


async def io_control(control_type: uds.IoControl, odj_object: dict, **kw):
    node = uds.nodes[odj_object["node_name"]]
    try:
        inputs = odj_object["input"]
    except KeyError:
        input_data = []
    else:
        input_data = payload.generate(kw, inputs)
    output_length = odj_object["output_size"]
    output_data = await uds.io_control(node, int(odj_object["hex_id"], 16), control_type, input_data, output_length)
    return (
     payload.parse(bytes(output_data), odj_object["output"]), output_data)


async def read_data(odj_object: dict) -> Generator[(Tuple[(str, Any)], None, None)]:
    try:
        read_info = odj_object["read"]
    except KeyError:
        raise RuntimeError("{0} is write only".format(odj_object["hex_id"]))
    else:
        node = uds.nodes[odj_object["node_name"]]
        byte_data = await uds.read_data_by_id(node, int(odj_object["hex_id"], 16), read_info["output_size"])
        return payload.parse(bytes(byte_data), read_info["output"])


async def request_results(odj_object: dict, **kw) -> Tuple[(Generator[(Tuple[(str, Any)], None, None)], bytes)]:
    return await routine_control((uds.RoutineControl.REQUEST_ROUTINE_RESULTS), odj_object, **kw)


async def routine_control(control_type: uds.RoutineControl, odj_object: dict, **kw) -> Tuple[(Generator[(Tuple[(str, Any)], None, None)], bytes)]:
    if control_type == uds.RoutineControl.START_ROUTINE:
        info = odj_object["start"]
    elif control_type == uds.RoutineControl.STOP_ROUTINE:
        info = odj_object["stop"]
    else:
        info = odj_object["results"]
    node = uds.nodes[odj_object["node_name"]]
    try:
        inputs = info["input"]
    except KeyError:
        input_data = []
    else:
        input_data = payload.generate(kw, inputs)
    output_length = info["output_size"]
    output_data = await uds.routine_control(node, int(odj_object["hex_id"], 16), control_type, input_data, output_length)
    return (
     payload.parse(bytes(output_data), info["output"]), output_data)


async def security_access(node: uds.Node, info: dict) -> None:
    security_level = info["security_level"]
    logging.debug("ODX Spec Security access: {0}".format(security_level))
    if security_level:
        await uds.security_access(node, security_level=security_level)


async def start_routine(odj_object: dict, **kw) -> Tuple[(Generator[(Tuple[(str, Any)], None, None)], bytes)]:
    return await routine_control((uds.RoutineControl.START_ROUTINE), odj_object, **kw)


async def stop_routine(odj_object: dict, **kw) -> Tuple[(Generator[(Tuple[(str, Any)], None, None)], bytes)]:
    return await routine_control((uds.RoutineControl.STOP_ROUTINE), odj_object, **kw)


async def write_data(odj_object: dict, data: dict) -> None:
    try:
        info = odj_object["write"]
    except KeyError:
        raise RuntimeError("{0} is read-only".format(odj_object.get("hex_id")))
    else:
        node = uds.nodes[odj_object["node_name"]]
        input_data = payload.generate(data, info["input"])
        await uds.write_data_by_id(node, int(odj_object["hex_id"], 16), input_data)


def __odx_whitelist_check(odj_object: dict, odj_object_name: str, hex_id: int):
    if odj_object.get("not_in_whitelist", False):
        raise RuntimeError("ODX id {} ({}) is not in whitelist. Please refer to tools/odin/integration for detail as how to add signal/message to whitelist.".format(hex_id, odj_object_name))

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/odx/interface.pyc
