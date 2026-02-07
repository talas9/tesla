# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/services/data_upload/data_upload.py
import asyncio, logging
from asyncio import sleep
from typing import AsyncGenerator, Optional, Dict, Tuple
from uuid import uuid4
from odin.core import isotp, uds
from odin.core.cid.interface import is_fused
from .request_lock import unlocked_data_upload, Requests
from .adapters.rcm_data_upload_adapter import RCMDataUploadAdapter
from .adapters.data_upload_adapter import TeslaDataUploadAdapter, LegacyTeslaDataUploadAdapter
from .data_upload_pipeline import process_upload, upload_directory_to_hermes_server
from .data_upload_ports import DataUploadPort
from . import request_history
from ..utils.request_limit import within_request_limit, MAX_REQ_PERIOD, MAX_UPLOAD_COUNT
log = logging.getLogger(__name__)
interface_collection = {}
protocol_map = {'tesla_protocol':TeslaDataUploadAdapter, 
 'legacy_tesla_protocol':LegacyTeslaDataUploadAdapter, 
 'rcm_protocol':RCMDataUploadAdapter}
MAX_UPLOAD_COUNT_DEV = 30

async def start_service(boot=False, alert: str=''):
    if boot:
        await sleep(3)
    async with unlocked_data_upload() as unlocked:
        if unlocked:
            log.info("Enable Data Upload Service, triggered by {}".format(alert))
            await handle_all_requests()
            await clean_and_upload()
            if Requests.new_request:
                await handle_all_requests()
            log.info("Terminate Data Upload")
        else:
            log.info("Data Upload Service Already Enabled, triggered by {}".format(alert))


async def handle_all_requests():
    interface, descriptor = await get_interface_and_descriptor_of_highest_priority()
    while interface:
        await execute_request(interface, descriptor)
        await asyncio.sleep(0.5)
        interface, descriptor = await get_interface_and_descriptor_of_highest_priority()

    log.info("No active data upload requests")


async def get_interface_and_descriptor_of_highest_priority() -> Tuple[(Optional[DataUploadPort], Dict)]:
    interface_queue = await enqueue_interfaces_by_priority()
    try:
        _, interface, descriptor = interface_queue.get_nowait()
    except asyncio.QueueEmpty:
        interface = None
        descriptor = {}

    return (
     interface, descriptor)


async def enqueue_interfaces_by_priority() -> asyncio.PriorityQueue:
    interface_queue = asyncio.PriorityQueue()
    interface_gen = generate_interfaces()
    fused = await is_fused()
    limit = MAX_UPLOAD_COUNT if fused else MAX_UPLOAD_COUNT_DEV
    async for interface in interface_gen:
        priority, descriptor = await interface.get_priority_and_descriptor()
        if priority:
            if not within_request_limit((interface.get_node_name()), max_upload_per_day=limit):
                log.error("Abort data upload: Data Upload limit reached by {}. \nLimit: {} times per {} seconds".format(interface.get_node_name(), limit, MAX_REQ_PERIOD))
            else:
                log.info("Request for {} with priority {}".format(interface.get_node_name(), priority.name))
                await interface_queue.put((-priority, interface, descriptor))

    return interface_queue


async def generate_interfaces() -> AsyncGenerator[(DataUploadPort, None)]:
    global interface_collection
    for node_name, node in uds.nodes.items():
        if node_with_valid_protocol(node):
            if interface_collection.get(node_name) is None:
                interface_collection[node_name] = interface_factory(node_name, node)
            yield interface_collection[node_name]


def node_with_valid_protocol(node: uds.Node) -> bool:
    valid = node.data_upload in protocol_map
    if not valid:
        if len(node.data_upload):
            log.error("Invalid registered data protocol: {}".format(node.data_upload))
    return valid


def interface_factory(node_name: str, node: uds.Node) -> DataUploadPort:
    adapter_inst = protocol_map.get(node.data_upload, TeslaDataUploadAdapter)(node_name, node)
    return DataUploadPort(adapter_inst)


async def execute_request(highest: DataUploadPort, descriptor: dict=None):
    request_id = generate_request_id()
    request_history.init_request_info(request_id)
    try:
        log.info("Start to execute data upload for node_name: {}".format(highest.get_node_name()))
        result_gen = await process_upload(highest, request_id, descriptor)
    except (RuntimeError, uds.UdsException, isotp.ISOTPError, asyncio.TimeoutError) as exc:
        log.error("Failed to execute data upload: {}".format(str(exc)))
        request_history.set_request_info_result(request_id, False)
    else:
        async for result, data in result_gen:
            log.info("Finished upload pipeline with {}".format(data))
            request_history.set_request_info_result(request_id, result)


def generate_request_id() -> str:
    return str(uuid4())


async def clean_and_upload():
    await upload_directory_to_hermes_server()

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/services/data_upload/data_upload.pyc
