# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/cid/interface/file_rotate.py
from hashlib import sha1
from odin import config
from odin.core.cid import interface
from . import filesystem
FILE_ROTATE_SCRIPT = "/usr/local/bin/crashlogrotate"
MAX_DIR_SIZE_KEY = "max_dir_size_bytes"
MAX_FILE_NUM = 50
MAX_FILE_NUM_KEY = "max_file_count"
PATTERN = "*-*-*.*"

async def move_and_rotate(file_path, target_dir, base_name, middle_name, suffix):
    await filesystem.mkdir(target_dir, parents=True, exist_ok=True)
    max_dir_size = _get_max_dir_size_in_bytes(target_dir)
    if max_dir_size:
        file_size = await filesystem.file_size(file_path)
        if file_size > max_dir_size:
            raise RuntimeError("{} of {} bytes over dir limit of {} bytes".format(file_path, file_size, max_dir_size))
        await _remove_highest_over_limit(target_dir, file_size, max_dir_size)
    max_file_count = _get_max_file_count_for_dir(target_dir)
    return await _rotate(file_path, target_dir, base_name, middle_name, suffix, max_file_count)


def _get_max_dir_size_in_bytes(dir_path: str) -> int:
    return _get_storage_handler().get(dir_path, {}).get(MAX_DIR_SIZE_KEY, 0)


def _get_max_file_count_for_dir(archive_path: str) -> int:
    return _get_storage_handler().get(archive_path, {}).get(MAX_FILE_NUM_KEY, MAX_FILE_NUM)


def _get_storage_handler() -> dict:
    return config.options.get("storage_handler", {})


async def _remove_highest_over_limit(path: str, buffer: int, limit: int):
    files = await filesystem.globpath(path, PATTERN)
    files.sort(key=(lambda x: x.split("-")[-1]))
    byte_sum = buffer
    for file in files:
        if byte_sum <= limit:
            byte_sum += await filesystem.file_size(file)
        if byte_sum > limit:
            await filesystem.remove_real_file(file)


async def _rotate(file_path, target_dir, base_name, middle_name, suffix, max_file_num):
    lock_name = sha1(target_dir.encode()).hexdigest()
    response = await interface.exec_command(args=[
     FILE_ROTATE_SCRIPT, lock_name, target_dir, base_name, middle_name, suffix, file_path, str(max_file_num)],
      timeout=10,
      user="root")
    return response.get("stdout").rstrip()

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/cid/interface/file_rotate.pyc
