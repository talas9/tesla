# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/services/data_upload/data_upload_pipeline.py
import asyncio, io, os, json, logging, tarfile
from datetime import datetime
from functools import reduce
from typing import *
from odin.core.utils.desync import desync
from odin.core import cid
from odin.core.cid.interface import hermes_file_upload
from odin.core.cid.interface import filesystem
from odin.core.cid.interface import file_rotate
from . import ROOT
from ..data_upload.data_upload_ports import DataUploadPort
from . import request_history
ARCHIVE_PATH = ROOT + "/archive"
META_ENTRIES = [
 'binary_file', 
 'firmware_version', 
 'log_descriptor', 
 'meta_format_version', 
 'node_name', 
 'time_stamp', 
 'time_stamp_epoch', 
 'vin']
log = logging.getLogger(__name__)

async def process_upload(interface: Union[(DataUploadPort, None)], guid: str, descriptor: dict=None) -> AsyncGenerator:
    data_collector = _data_collector_factory(descriptor)
    request_history.set_data_collector(guid, data_collector)
    return reduce(_reducer, _get_steps(), (interface, data_collector))


def _get_steps() -> list:
    return [
     get_descriptor, 
     get_data, 
     get_meta_data, 
     store_data, 
     set_received, 
     broadcast_file]


def _data_collector_factory(descriptor: dict=None) -> dict:
    data_collector = {
     'vin': None, 
     'firmware_version': None, 
     'time_stamp': None, 
     'time_stamp_epoch': None, 
     'meta_format_version': None, 
     'node_name': None, 
     'log_descriptor': None, 
     'binary_data': None, 
     'binary_file': None, 
     'tar_file_path': None, 
     'log_descriptor_success': None, 
     'upload_success': None, 
     'hermes_upload_success': None, 
     'store_data_to_disk_success': None}
    if descriptor:
        data_collector["log_descriptor"] = descriptor
    return data_collector


def _reducer(interface_accum: Tuple[(Union[(AsyncGenerator, DataUploadPort)], dict)], func: Callable) -> Callable:
    return func(interface_accum)


async def get_descriptor(pipeline: Tuple[(DataUploadPort, dict)]) -> AsyncGenerator[(DataUploadPort, dict)]:
    interface, data_collector = pipeline
    descriptor = data_collector.get("log_descriptor")
    if not descriptor:
        descriptor = await interface.get_descriptor()
        data_collector["log_descriptor"] = descriptor
    data_collector["log_descriptor_success"] = True if descriptor else False
    log.debug("Descriptor: {}".format(descriptor))
    yield (interface, data_collector)


async def get_data(pipeline: AsyncGenerator[(DataUploadPort, dict)]) -> AsyncGenerator[(DataUploadPort, dict)]:
    async for interface, data_collector in pipeline:
        if not _is_get_descriptor_success(data_collector):
            log.error("Not executing uds data upload because log descriptor is undefined")
            binary_data = None
            success = False
        else:
            descriptor = data_collector.get("log_descriptor")
            success, binary_data = await interface.get_data(descriptor)
            log.debug("{} retrieving uds data".format("Success" if success else "Failure"))
        if success:
            interface.verify_binary_data_length(descriptor, binary_data)
        data_collector["binary_data"] = binary_data
        data_collector["upload_success"] = success
        yield (interface, data_collector)


def _is_get_descriptor_success(data_collector: dict) -> bool:
    return data_collector["log_descriptor_success"]


async def get_meta_data(pipeline: AsyncGenerator[(DataUploadPort, dict)]) -> AsyncGenerator[(DataUploadPort, dict)]:
    async for interface, data_collector in pipeline:
        try:
            try:
                fw_version = await cid.interface.get_fw_version()
            except asyncio.TimeoutError:
                fw_version = ""

        finally:
            data_collector["firmware_version"] = fw_version

        data_collector["node_name"] = interface.get_node_name().lower()
        time_stamp = datetime.now().replace(microsecond=0)
        data_collector["time_stamp"] = time_stamp.isoformat()
        data_collector["time_stamp_epoch"] = time_stamp.timestamp()
        data_collector["meta_format_version"] = 1.1
        try:
            try:
                vin = await cid.interface.get_vin()
            except asyncio.TimeoutError:
                vin = ""

        finally:
            data_collector["vin"] = vin

        yield (
         interface, data_collector)


async def store_data(pipeline: AsyncGenerator[(DataUploadPort, dict)]) -> AsyncGenerator[(DataUploadPort, dict)]:
    async for interface, data_collector in pipeline:
        if _is_data_upload_success(data_collector):
            base_name = "ecu_log_{}".format(data_collector["node_name"])
            upload_name = "{}-{}".format(base_name, data_collector["time_stamp"])
            binary_data_file_name = data_collector["binary_file"] = "{}.bin".format(upload_name)
            file_objects = {binary_data_file_name: (data_collector.pop("binary_data")), 
             "meta.json": (json.dumps(_filter_meta_data(data_collector)))}
            odin_tmp = await filesystem.mkdir_odin_tmp()
            tmp_file_path = os.path.join(odin_tmp, "{}.tgz".format(upload_name))
            try:
                await _stream_to_compressed_archive(path=tmp_file_path, **file_objects)
                tar_path = await _move_to_storage(tmp_file_path=tmp_file_path,
                  base_name=base_name,
                  middle_name=(data_collector["time_stamp"]))
            except (OSError, RuntimeError, asyncio.TimeoutError) as err:
                log.error("Failure occurred when storing data on disk: {}".format(repr(err)))
                data_collector["store_data_to_disk_success"] = False
                data_collector["tar_file_path"] = ""
                await filesystem.remove_real_file(tmp_file_path)
            else:
                data_collector["store_data_to_disk_success"] = True
                data_collector["tar_file_path"] = tar_path
        yield (
         interface, data_collector)


def _is_data_upload_success(data_collector: dict) -> bool:
    return data_collector.get("upload_success", False)


def _filter_meta_data(data_collector: dict) -> dict:
    return dict(filter((lambda x: x[0] in META_ENTRIES), data_collector.items()))


async def _stream_to_compressed_archive(path: str, **file_objects):
    archive = await desync(tarfile.open, path, "w:gz")
    try:
        archive = await desync(_stream_to_archive, archive, file_objects)
    finally:
        await desync(archive.close)


def _stream_to_archive(archive: tarfile.TarFile, file_objects: dict) -> tarfile.TarFile:
    for file_name, data in file_objects.items():
        try:
            data = _convert_to_bytes(data)
        except ValueError:
            log.error("Failed converting data {}".format(data))
        else:
            tarinfo = tarfile.TarInfo(name=file_name)
            tarinfo.size = len(data)
            archive.addfile(tarinfo, io.BytesIO(data))

    return archive


def _convert_to_bytes(data: Any) -> bytes:
    if not data:
        return b''
    else:
        if isinstance(data, str):
            return data.encode("utf8")
        if isinstance(data, dict):
            return str(data).encode("utf8")
        if isinstance(data, bytes) or isinstance(data, bytearray):
            return data
    raise ValueError("Can not convert to bytes")


async def _move_to_storage(tmp_file_path, base_name, middle_name):
    return await file_rotate.move_and_rotate(file_path=tmp_file_path,
      target_dir=ARCHIVE_PATH,
      base_name=base_name,
      middle_name=middle_name,
      suffix="tgz")


async def set_received(pipeline: AsyncGenerator[(DataUploadPort, dict)]) -> AsyncGenerator[(DataUploadPort, dict)]:
    async for interface, data_collector in pipeline:
        if _is_get_descriptor_success(data_collector):
            await interface.set_received(data_upload_success=(_is_data_upload_success(data_collector)), descriptor=(data_collector.get("log_descriptor")))
        yield (
         interface, data_collector)


async def broadcast_file(pipeline: AsyncGenerator[(DataUploadPort, dict)]) -> AsyncGenerator[(bool, dict)]:
    async for interface, data_collector in pipeline:
        success = False
        if _is_data_upload_success(data_collector):
            file_path = data_collector.get("tar_file_path")
            if file_path.endswith(".tgz"):
                success = await _upload_file_to_hermes_server(file_path)
            else:
                log.error("Skip Hermes File Upload: Wrong file name format {}".format(file_path))
        else:
            log.error("Skip hermes file upload: Uds data upload failure")
        data_collector["hermes_upload_success"] = success
        yield (success, data_collector)


async def _upload_file_to_hermes_server(file_path: str) -> bool:
    if not await filesystem.exists(file_path):
        log.error("File not found: {}".format(file_path))
        return False
    else:
        log.debug("Attempt to upload file: {}".format(file_path))
        response = await hermes_file_upload.upload_file(file_path)
        if not response or response["exit_status"] != 0:
            log.error("Hermes File Upload failed: {}".format(response))
            return False
        log.debug("Hermes File Upload succeeded: {}".format(str(response)))
        return True


async def upload_directory_to_hermes_server():
    try:
        is_success, responses = await hermes_file_upload.upload_directory(ARCHIVE_PATH, pattern="*.tgz")
    except OSError as exc:
        log.error("Failed to upload all stored datafiles in {}: {}".format(ARCHIVE_PATH, str(exc)))
    else:
        if not is_success:
            log.warning("Failed to upload files: {}".format(str(responses)))

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/services/data_upload/data_upload_pipeline.pyc
