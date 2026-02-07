# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/services/hrl/hrl_upload.py
import asyncio, logging, time, os
from json import JSONDecodeError
from typing import Optional, Union
from odin.core.cid.interface import filesystem, hermes_file_upload, is_on_wifi
from .adapters import HrlEcu, HrlGameMode, HrlUdp
from odin.core.utils.singleton import make_singleton_getter
from odin.core.cid.hrl import is_marked_as_critical
MAX_REQ_PERIOD = 86400
WIFI_CHECK_INTERVAL = 30
CELL_DAILY_ALLOWED_BYTES = 20971520
CELL_DISABLED_SENTINEL = "/home/odin/HRL/disabled_cell_upload"
Hrl_Adapter_Type = Union[(HrlEcu, HrlGameMode, HrlUdp)]
hrl_lock = make_singleton_getter(asyncio.Lock)
log = logging.getLogger(__name__)
upload_worker_on_wifi = None
remaining_files = []
_hrl_adapters = None
cell_upload_disabled = None

class UploadLimitReached(Exception):
    return


class UnknownAdapter(Exception):
    return


def hrl_adapters() -> dict:
    global _hrl_adapters
    if _hrl_adapters is None:
        _hrl_adapters = {'hrl_ecu':HrlEcu(),  'hrl_game_mode':HrlGameMode(), 
         'hrl_udp':HrlUdp()}
    return _hrl_adapters


async def start_service(hrl_type: str='hrl_ecu', boot: bool=False):
    global remaining_files
    global upload_worker_on_wifi
    async with hrl_lock():
        adapter = hrl_adapters().get(hrl_type)
        if adapter is None:
            log.error("Invalid hrl adapter from hrl_type: {}".format(hrl_type))
            return
        daily_bytes_limit = await adapter.daily_allowed_bytes()
        if daily_bytes_limit <= 0:
            log.debug("Abort {} upload: Feature disabled.".format(adapter.name()))
            return
        if boot:
            await asyncio.sleep(5)
        async for size, gtw_file_name in adapter.available_files():
            file_name = await adapter.transfer(gtw_file_name, size)
            if not file_name:
                pass
            else:
                try:
                    result = await _limited_hermes_file_upload(file_name, adapter)
                except (hermes_file_upload.VehicleNotOnWifi, UploadLimitReached) as err:
                    log.info(err)
                else:
                    if result.get("exit_status") != 0:
                        log.error("Failure of hrl upload to hermes: {}. Error: {}".format(file_name, result["stderr"]))
                    else:
                        log.info("Success of hrl upload to hermes: {}".format(file_name))

        remaining_files = []
        for _, adapter in hrl_adapters().items():
            remaining_files.extend(await filesystem.list_dir((adapter.ice_dir), doesnt_exist_ok=True))

        _sort_file_by_criticality_and_oldest(remaining_files)
    if len(remaining_files) > 0:
        if upload_worker_on_wifi is None or upload_worker_on_wifi.done():
            upload_worker_on_wifi = asyncio.ensure_future(_upload_stored_hrl_on_wifi())


def _sort_file_by_criticality_and_oldest(remaining_files):

    def sort_for_critical(file_name):
        return int(is_marked_as_critical(file_name))

    remaining_files.sort(key=(lambda x: (sort_for_critical(x), str(x).split("-")[-1])), reverse=True)


async def _limited_hermes_file_upload(file_name: str, adapter: Hrl_Adapter_Type) -> dict:
    collection = {
     'time': 0.0, 
     'sum': 0, 
     'time_critical_hrl': 0.0, 
     'sum_critical_hrl': 0}
    if await filesystem.exists(adapter.bytes_uploaded_file):
        try:
            collection.update(await filesystem.load_json(adapter.bytes_uploaded_file))
        except JSONDecodeError as e:
            log.error("Failed to load {}: {}".format(adapter.bytes_uploaded_file, e))

    try:
        return await _upload_within_limits(file_name, adapter, collection)
    finally:
        await filesystem.write_json(adapter.bytes_uploaded_file, collection)


async def _upload_within_limits(file_name, adapter, collection):
    if await should_upload_on_cell(file_name):
        daily_limit = CELL_DAILY_ALLOWED_BYTES
        last_uploaded_key = "time_critical_hrl"
        bytes_uploaded_key = "sum_critical_hrl"
        wifi_only = False
    else:
        daily_limit = await adapter.daily_allowed_bytes()
        last_uploaded_key = "time"
        bytes_uploaded_key = "sum"
        wifi_only = True
    if time.time() - collection.get(last_uploaded_key, 0) > MAX_REQ_PERIOD:
        collection[bytes_uploaded_key] = 0
        collection[last_uploaded_key] = time.time()
    size = await filesystem.file_size(file_name)
    if collection[bytes_uploaded_key] + size > daily_limit:
        raise UploadLimitReached("Daily data upload limit reached of {}".format(daily_limit))
    result = await hermes_file_upload.upload_file(file_name,
      wifi_only=wifi_only,
      keep_alive_min=(await adapter.upload_ice_keep_alive()),
      timeout=(adapter.upload_timeout))
    if result.get("exit_status") is 0:
        collection[bytes_uploaded_key] += size
    return result


async def should_upload_on_cell(file_name: str) -> bool:
    return is_marked_as_critical(file_name) and not await is_cell_upload_disabled_via_sentinel()


async def is_cell_upload_disabled_via_sentinel() -> bool:
    global cell_upload_disabled
    if cell_upload_disabled is None:
        cell_upload_disabled = await filesystem.exists(CELL_DISABLED_SENTINEL)
    return cell_upload_disabled


async def _upload_stored_hrl_on_wifi():
    while len(remaining_files):
        try:
            async with hrl_lock():
                file_name = str(remaining_files[0])
                adapter = get_adapter_from_prefix(file_name)
                result = await _limited_hermes_file_upload(file_name, adapter)
                if result["exit_status"] is 0:
                    remaining_files.pop(0)
                else:
                    log.error("Failure of hrl upload of remaining files: {}. Error: {}".format(file_name, result["stderr"]))
                    break
        except UnknownAdapter:
            remaining_files.pop(0)
            await filesystem.remove_real_file(file_name)
        except UploadLimitReached:
            log.info("Abort hrl upload: {0}.Daily limit of bytes uploaded of {1} bytes reached".format(file_name, await adapter.daily_allowed_bytes()))
            remaining_files.pop(0)
        except hermes_file_upload.VehicleNotOnWifi:
            await _wait_for_wifi()


def get_adapter_from_prefix(file_name: str) -> Hrl_Adapter_Type:
    prefix = os.path.basename(file_name).split("-")[0]
    adapter = hrl_adapters().get(prefix)
    if adapter is None:
        raise UnknownAdapter("Invalid hrl adapter from hrl file name: {}".format(file_name))
    return adapter


async def _wait_for_wifi():
    while not await is_on_wifi(silent=True):
        await asyncio.sleep(WIFI_CHECK_INTERVAL)
    else:
        log.info("Vehicle on wifi now")

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/services/hrl/hrl_upload.pyc
