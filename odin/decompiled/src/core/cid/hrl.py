# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/cid/hrl.py
import asyncio, logging, os
from datetime import datetime
from uuid import uuid4
from typing import Dict, Union, Optional, Tuple, Set
from . import hrl_parser
from .interface import filesystem
from .interface import file_rotate
from .interface import gwxfer
from .interface import exec_command
HRL_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S"
MAX_HRL_SIZE = 268435456
UDP_HRL_PATH = "udp.hrl"
TARGET_ICE_DIR_FOR_UDP_HRL = "/home/odin/HRL/udp_hrl"
SYMBOL_CRITICAL_HRL = "c"
log = logging.getLogger(__name__)

class TransferError(Exception):
    return


async def start_hrl(timeout: int=300) -> Dict[(str, Union[(int, str)])]:
    timeout_upper_byte = timeout >> 8 & 255
    timeout_lower_byte = timeout & 255
    args = ["HIGH_RES_TRIGGER", "{:#x}".format(timeout_upper_byte), "{:#x}".format(timeout_lower_byte)]
    expected_value = "{:02X} {:02X}".format(timeout_upper_byte, timeout_lower_byte)
    return await exec_hrl_cmd(args, expected_value)


async def stop_hrl() -> Dict[(str, Union[(int, str)])]:
    return await exec_hrl_cmd(["HIGH_RES_STOP"], "01")


async def exec_hrl_cmd(cmd_args: list, expected_value: str, timeout=2) -> Dict[(str, Union[(int, str)])]:
    cmd = [
     "/usr/sbin/gw-diag"] + cmd_args
    log.debug("Executing cmd: {}".format(cmd))
    result = await exec_command(cmd, user="odin", timeout=timeout)
    if result["stdout"].rstrip() != expected_value:
        result["exit_status"] = 1
        log.error("Failed to execute HRL cmd. Expected: {0}, Actual: {1}".format(expected_value, result["stdout"]))
    return result


async def transfer_udp_url(file_name: str, timeout: int) -> str:
    return await transfer_hrl(TARGET_ICE_DIR_FOR_UDP_HRL, file_name, UDP_HRL_PATH, timeout=timeout)


async def transfer_hrl(target_dir: str, base_name: str, gateway_file: str, gateway_file_created_at: Optional[str]=None, gateway_file_size: Optional[int]=None, timeout: int=60, critical_triggers: Optional[Set[int]]=None) -> str:
    allowed, message = await _validate_hrl_size(gateway_file, gateway_file_size)
    if not allowed:
        raise TransferError(message)
    middle = datetime.utcnow().strftime(HRL_DATE_FORMAT) if not gateway_file_created_at else gateway_file_created_at
    odin_tmp = await filesystem.mkdir_odin_tmp()
    temp_file_path = os.path.join(odin_tmp, "{}.hrl".format(str(uuid4())))

    async def _transfer_and_move():
        nonlocal base_name
        try:
            result = await gwxfer.transfer(gateway_file, temp_file_path, timeout=timeout)
        except (OSError, RuntimeError, asyncio.TimeoutError) as error:
            raise TransferError(error)
        else:
            if result.get("exit_status") != 0:
                raise TransferError(result["stderr"])
            else:
                base_name = "hrl_log" if not base_name else base_name
                if "-" in base_name:
                    raise TransferError("Invalid base name")
                is_critical = _hrl_has_critical_trigger(temp_file_path, critical_triggers)
                if is_critical:
                    base_name = _mark_base_name_as_critical(base_name)
                try:
                    compressed_file_path = await filesystem.gzip_file(temp_file_path)
                    return await file_rotate.move_and_rotate(compressed_file_path, target_dir, base_name, middle, "hrl.gz")
                except (OSError, RuntimeError, asyncio.TimeoutError) as error:
                    raise TransferError(error)

    try:
        return await _transfer_and_move()
    except TransferError:
        await filesystem.remove_real_file(temp_file_path)
        raise


def _hrl_has_critical_trigger(hrl_file: str, critical_triggers: Set[int]) -> bool:
    if not critical_triggers:
        return False
    else:
        try:
            hrlReader = hrl_parser.HrlReader(hrl_file)
        except Exception as e:
            log.error("Failed to parse hrl header: {}".format(e))
            return False

        if hrlReader.header.triggers == None:
            return False
        return any(set(hrlReader.header.triggers) & critical_triggers)


def is_marked_as_critical(hrl_file: str) -> bool:
    return os.path.basename(hrl_file).split("-")[1] == SYMBOL_CRITICAL_HRL


def _mark_base_name_as_critical(base_name: str) -> str:
    return "{}-{}".format(base_name, SYMBOL_CRITICAL_HRL)


async def _validate_hrl_size(gateway_file: str, gateway_file_size: Optional[int]=None) -> (bool, str):
    result = await (gateway_file_size or gwxfer.get_size(gateway_file))
    if result["exit_status"] is not 0:
        return (False, "Unable to get size of {} file from gateway".format(gateway_file))
    else:
        try:
            gateway_file_size = int(result["stdout"].strip())
        except ValueError:
            return (
             False, "Unable to extract the size of {} file from gateway".format(gateway_file))

        if gateway_file_size > MAX_HRL_SIZE:
            return (
             False, "Hrl file size of size {} bytes exceeds the limit".format(gateway_file_size))
        return (True, '')

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/cid/hrl.pyc
