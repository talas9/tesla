# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/patch/loader.py
import logging
from odin.core.cid.interface import restart_odin_engine
from odin.core.cid.interface import is_fused
from odin.core.cid.interface import filesystem
from . import *
from .ssqutil import load_ssq_under_dm_verity, unload_ssq_under_dm_verity, assert_patch_firmware_signature_match, get_patch_signature_from_ssq
SSQ_FILE_INSTALLED = os.path.join(PATCH_HOME, "odinpatch.ssq-installed")
PERSISTENT_SSQ_FILE_INSTALLED = os.path.join(PATCH_HOME, "odinpatch.ssq-installed-persist")
INSTALLED_PATTERN = "odinpatch.ssq-installed*"
PROD_VERITY_KEY = os.path.join(ODIN_KEYS, "verity-odin-patch-prod.pub")
DEV_VERITY_KEY = os.path.join(ODIN_KEYS, "verity-odin-patch-dev.pub")
MOUNT_TARGET = os.path.join(ODIN_ROOT, "patch")
DM_DEVICE_NAME = "odinpatch"
ACTIVE_SIGNATURE_LENGTH = 8
log = logging.getLogger(__name__)
active_patch_signature = ""

async def load_ssq_on_boot():
    try:
        await load_ssq(on_boot=True)
    except PatchInfo as e:
        log.info(e)
    except Exception as e:
        log.error(e)
    else:
        log.info("patch successfully mounted")


async def load_ssq(on_boot=True):

    async def _load():
        mounted = await is_mounted()
        installed = await is_installed()
        if on_boot:
            if await is_installed_non_persistent():
                raise PatchNonPersist("{}mounted non-persistent patch found".format("" if mounted else "non-"))
        if on_boot:
            if await is_fused():
                raise PatchError("can't mount persistent patch on fused vehicle")
        if mounted:
            if installed:
                await assert_patch_firmware_signature_matches_installed()
                raise PatchAlreadyMounted("patch already mounted")
        if mounted:
            if not installed:
                raise PatchStillMounted("no patch installed, but mounted")
        if not installed:
            raise PatchNotInstalled("no patch installed")
        await assert_patch_firmware_signature_matches_installed()
        await mount_odin_patch()

    try:
        try:
            await _load()
        except PatchStillMounted:
            await unmount_odin_patch()
            raise
        except PatchError as e:
            log.error("failed to load patch: {}".format(repr(e)))
            await remove_patch_and_unmount()
            raise

    finally:
        await set_active_patch_signature()


async def set_active_patch_signature():
    global active_patch_signature
    if await is_mounted() and await is_installed():
        active_patch_signature = (await get_patch_signature_from_ssq(await get_installed_ssq_path()))[:ACTIVE_SIGNATURE_LENGTH]
        log.info(f"active patch signature: {active_patch_signature}")
    else:
        reset_active_patch_signature()


def get_active_patch_signature():
    return active_patch_signature


def reset_active_patch_signature():
    global active_patch_signature
    active_patch_signature = ""


async def assert_patch_firmware_signature_matches_installed():
    await assert_patch_firmware_signature_match(await get_installed_ssq_path())


async def is_installed() -> bool:
    try:
        await get_installed_ssq_path()
    except PatchNotInstalled:
        return False
    else:
        return True


async def get_installed_ssq_path() -> str:
    files = await filesystem.globpath(PATCH_HOME, INSTALLED_PATTERN)
    if len(files) == 0:
        raise PatchNotInstalled()
    else:
        if len(files) != 1:
            raise PatchError(f"more than one installed patch found: {files}")
    return files[0]


async def mount_odin_patch():
    fused = True
    try:
        fused = await is_fused()
    except Exception as e:
        log.warning("can not read fused state {}".format(e))

    keys = [PROD_VERITY_KEY]
    if not fused:
        keys.insert(0, DEV_VERITY_KEY)
    await load_ssq_under_dm_verity(await get_installed_ssq_path(), keys, DM_DEVICE_NAME, MOUNT_TARGET)


async def unmount_odin_patch():
    reset_active_patch_signature()
    mounted = await is_mounted()
    try:
        await unload_ssq_under_dm_verity(DM_DEVICE_NAME, MOUNT_TARGET)
    except PatchError as e:
        if mounted:
            log.error("failure when unmounting {}".format(e))
            raise


async def uninstall_patch_and_reboot_if_mounted():
    mounted = await is_mounted()
    log.info("mark {}mounted patch as non-persistent".format("" if mounted else "non-"))
    await mark_installed_persistent(persist=False)
    exc = None
    try:
        await unmount_odin_patch()
    except PatchError as e:
        exc = e

    if mounted:
        await restart_odin_engine(delay=2)
    if exc:
        raise exc


async def remove_patch_and_unmount():
    await remove_installed()
    await unmount_odin_patch()


async def mark_installed_persistent(persist: bool=False):
    if not await is_installed():
        return
    else:
        installed_path = await get_installed_ssq_path()
        target_path = PERSISTENT_SSQ_FILE_INSTALLED if persist else SSQ_FILE_INSTALLED
        if await filesystem.exists(target_path):
            return
        try:
            await filesystem.rename_file(installed_path, target_path)
        except (FileNotFoundError, OSError) as e:
            raise PatchError(f"Can not move file {SSQ_FILE_INSTALLED} to {PERSISTENT_SSQ_FILE_INSTALLED}: {e}")


async def is_installed_non_persistent() -> bool:
    return await filesystem.exists(SSQ_FILE_INSTALLED)


async def is_mounted() -> bool:
    return await filesystem.is_mount_point(MOUNT_TARGET)


async def remove_installed():
    files = await filesystem.globpath(PATCH_HOME, INSTALLED_PATTERN)
    for file in files:
        log.info(f"Remove {file}")
        await remove_file(file)


async def remove_file(file: str):
    try:
        await filesystem.remove_file(file)
    except FileNotFoundError:
        log.debug("nothing to remove: {}".format(file))
    except OSError as e:
        raise PatchError("can not remove {}: {}".format(file, e))

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/patch/loader.pyc
