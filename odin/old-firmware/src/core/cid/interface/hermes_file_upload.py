# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/cid/interface/hermes_file_upload.py
import asyncio, logging, os
from typing import Dict, Tuple
from . import filesystem
from . import exec_command
from . import is_on_wifi
from . import request_do_not_sleep
log = logging.getLogger(__name__)

class VehicleNotOnWifi(Exception):
    return


async def upload_directory(dir_path: str, pattern: str='*', sort_order: str='st_mtime', wifi_only: bool=False, keep_alive_min: int=0) -> Tuple[(bool, dict)]:
    if not await filesystem.is_dir(dir_path):
        log.warning("Given dir_path does not exist: {}".format(dir_path))
        return (
         False, {})
    else:
        return await _upload_sorted_files_in_directory(dir_path, pattern, sort_order, wifi_only, keep_alive_min)


async def _upload_sorted_files_in_directory(dir_path: str, pattern: str='*', sort_order: str='st_mtime', wifi_only: bool=False, keep_alive_min: int=0) -> Tuple[(bool, dict)]:
    dir_list = await filesystem.list_dir(dir_path)
    if not dir_list:
        return (True, {})
    else:
        dir_list.sort(key=(lambda x: getattr(x.lstat(), sort_order)))
        failures = dict()
        for item in dir_list:
            if item.is_file():
                if item.match(pattern):
                    try:
                        success = await upload_file((os.path.join(dir_path, item.name)),
                          wifi_only=wifi_only,
                          keep_alive_min=keep_alive_min)
                    except VehicleNotOnWifi as err:
                        failures[item.name] = err
                        break

                if success.get("exit_status") is not 0:
                    failures[item.name] = success

        if not len(failures):
            return (True, {})
        return (False, failures)


async def upload_file(file_path, remove_on_success=True, wifi_only=False, keep_alive_min=0, timeout=10):
    on_wifi = await is_on_wifi(silent=True)
    if wifi_only:
        if not on_wifi:
            raise VehicleNotOnWifi("Vehicle not on wifi - Abort upload: {}".format(file_path))
    if await filesystem.is_symlink(file_path):
        return {'exit_status':1, 
         'stderr':"Not allowed to upload a symlink"}
    log.info("Attempting to upload on wifi={} file={}".format(str(on_wifi), os.path.basename(file_path)))
    if keep_alive_min > 0:
        await request_do_not_sleep(minutes=keep_alive_min, silent=True)
    try:
        response = await exec_command(["/opt/hermes/hermes_fileupload",
         "-filename", file_path, "-upload-only"],
          timeout=timeout,
          user="root")
    except asyncio.TimeoutError:
        return {'exit_status':1, 
         'stderr':"Hermes File Upload timed out"}
    else:
        if remove_on_success:
            if response["exit_status"] is 0:
                await filesystem.remove_real_file(file_path)
        return response

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/cid/interface/hermes_file_upload.pyc
