# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/patch/ssqutil.py
import aiofiles, asyncio, base64, logging, os
from . import PatchError
from odin.core.cid.interface import exec_command
from odin.core.cid.updater import get_installed_firmware_signature
SSQ_UTIL = "ssq-util"
SIGNATURE_LENGTH = 64
SIGNATURE_LENGTH_BASE_64 = 88
log = logging.getLogger(__name__)

async def decrypt(file: str, key_file: str, target: str):
    cmd = [
     SSQ_UTIL, '--decrypt', '--key', key_file, '--file', file, 
     '--target', 
     target]
    try:
        result = await exec_command(cmd, user="root")
    except asyncio.TimeoutError:
        raise PatchError("decryption timed out")
    except FileNotFoundError as e:
        raise PatchError(str(e))

    if result["exit_status"] != 0:
        raise PatchError("decryption failure: {}".format(result["stderr"]))
    log.info("ssq-util: decrypt {}".format(result["stdout"]))


async def verify_nacl_signature(file: str, keys: list):
    cmd = [
     SSQ_UTIL, "--verify", "--file", file]
    for key in keys:
        cmd.extend(["--key", key])

    try:
        result = await exec_command(cmd, user="root")
    except asyncio.TimeoutError:
        raise PatchError("signature verification timed out")
    except FileNotFoundError as e:
        raise PatchError(str(e))

    if result["exit_status"] != 0:
        raise PatchError("signature verification failure: {}".format(result["stderr"]))
    log.info("ssq-util: verify {}".format(result["stdout"]))


async def load_ssq_under_dm_verity(ssq_file, keys, dm_name, mount_target):
    cmd = [
     SSQ_UTIL, '--load', '--file', ssq_file, 
     '--name', dm_name, 
     '--target', mount_target, 
     '--eio']
    for key in keys:
        cmd.extend(["--key", key])

    try:
        result = await exec_command(cmd, user="root")
    except asyncio.TimeoutError:
        raise PatchError("ssq loading timed out")
    except FileNotFoundError as e:
        raise PatchError(str(e))

    if result["exit_status"] != 0:
        raise PatchError("ssq loading failure: {}".format(result["stderr"]))
    log.info("ssq-util: load {}".format(result["stdout"]))


async def unload_ssq_under_dm_verity(dm_name: str, mount_target: str):
    cmd = [
     SSQ_UTIL, '--unload', '--name', dm_name, '--target', mount_target]
    try:
        result = await exec_command(cmd, user="root")
    except asyncio.TimeoutError:
        raise PatchError("System-reboot recommended: ssq unloading timed out")
    except FileNotFoundError as e:
        raise PatchError(str(e))

    if result["exit_status"] != 0:
        raise PatchError("System-reboot recommended: ssq unloading failure: {}".format(result["stderr"]))
    log.info("ssq-util: unload {}".format(result["stdout"]))


async def assert_patch_firmware_signature_match(ssq_file: str):
    patch_firmware_signature = await get_patch_firmware_signature_from_ssq(ssq_file)
    await assert_installed_firmware_signature_matches_signature(patch_firmware_signature)


async def assert_installed_firmware_signature_matches_signature(signature: str):
    installed_firmware_sig = await get_installed_firmware_signature(retries=5)
    if not installed_firmware_sig:
        raise PatchError("failed to get firmware signature from updater")
    else:
        if len(installed_firmware_sig) != SIGNATURE_LENGTH_BASE_64:
            raise PatchError("invalid firmware signature length: {}".format(installed_firmware_sig))
    if signature != installed_firmware_sig:
        raise PatchError("signature mismatch: installed_fw_sig={} odin_patch_fw_sig={}".format(installed_firmware_sig, signature))


async def get_patch_firmware_signature_from_ssq(ssq_file: str) -> str:
    try:
        async with aiofiles.open(ssq_file, "rb") as fd:
            await fd.seek(-(2 * SIGNATURE_LENGTH), os.SEEK_END)
            binary_sig = await fd.read(SIGNATURE_LENGTH)
    except FileNotFoundError:
        raise PatchError("file not found: {}".format(ssq_file))
    except OSError as e:
        log.error("failed to read firmware signature: {}".format(e))
        raise PatchError("failed get firmware signature from ssq")

    try:
        return base64.b64encode(binary_sig).decode()
    except TypeError as e:
        raise PatchError("failed to encode from firmware signature: {}".format(e))


async def get_patch_signature_from_ssq(ssq_file: str) -> str:
    try:
        async with aiofiles.open(ssq_file, "rb") as fd:
            await fd.seek(-SIGNATURE_LENGTH, os.SEEK_END)
            binary_sig = await fd.read()
    except (FileNotFoundError, OSError) as e:
        log.error("failed to read patch sig: {}".format(e))
        raise PatchError("failed get patch signature from ssq")

    try:
        return base64.b64encode(binary_sig).decode()
    except TypeError as e:
        raise PatchError("failed to encode from patch signature: {}".format(e))

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/patch/ssqutil.pyc
