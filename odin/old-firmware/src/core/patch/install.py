# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/patch/install.py
import asyncio, logging, aiofiles
from base64 import b64decode
from binascii import Error as BinasciiError
from odin.core.cid import firmware_server
from odin.core.cid.interface import filesystem
from odin.core.cid.interface import restart_odin_engine, is_fused
from odin.core.engine.handlers.utils import Timer
from . import *
from . import loader
from .ssqutil import decrypt, verify_nacl_signature, assert_patch_firmware_signature_match, assert_installed_firmware_signature_matches_signature
DOWNLOAD_RETRIES = 2
CSSQ_FILE_DOWNLOAD = os.path.join(PATCH_HOME, "odinpatch.cssq-download")
SSQ_FILE_DOWNLOAD = os.path.join(PATCH_HOME, "odinpatch.ssq-download")
SSQ_FILE_STAGED = os.path.join(PATCH_HOME, "odinpatch.ssq-staged")
CRYPTO_KEY_FILE = os.path.join(PATCH_HOME, "odinpatch.ckey")
REQUIRED_STORAGE_BYTES = 4194304
PROD_KEY = os.path.join(ODIN_KEYS, "odin-patch-prod.pub")
DEV_KEY = os.path.join(ODIN_KEYS, "odin-patch-dev.pub")
log = logging.getLogger(__name__)
lock = asyncio.Lock()

async def install_patch(persist: bool=False, timeout: float=300) -> dict:
    patch_metadata = {}

    async def _install():
        nonlocal patch_metadata
        try:
            patch_signature_response = await firmware_server.available_patch_sig()
            await verify_patch_firmware_signature_response(patch_signature_response)
        except PatchFirmwareSignatureNotFound as e:
            return {'exit_code':1, 
             'status':format_exc(e)}

        patch_metadata = patch_signature_response
        if await check_already_installed(patch_signature_response):
            log.info("Package already downloaded - reloading")
            try:
                await loader.load_ssq(on_boot=False)
            except PatchAlreadyMounted as e:
                return {'exit_code':0, 
                 'status':format_exc(e)}
            except (PatchInfo, PatchError) as e:
                return {'exit_code':2,  'status':format_exc(e)}

            return {'exit_code':0, 
             'status':"PatchMounted - installed patch successfully mounted",  'reboot':True}
        else:
            try:
                with Timer() as download_timer:
                    await do_download(patch_signature_response, timeout)
            except PatchError as e:
                return {'exit_code':4, 
                 'status':format_exc(e)}

            log.info(f"Successfully downloaded patch firmware_signature={patch_signature_response.get(firmware_server.FIRMWARE_SIG_KEY)} patch_signature={patch_signature_response.get(firmware_server.PATCH_SIG_KEY)} elapsed={download_timer.elapsed}")
            try:
                await verify_staged_ssq_package()
            except PatchError as e:
                return {'exit_code':5, 
                 'status':format_exc(e)}

            log.info("Successfully verified patch")
            try:
                await loader.load_ssq(on_boot=False)
            except (PatchError, PatchInfo) as e:
                return {'exit_code':6, 
                 'status':format_exc(e)}

            return {'exit_code':0,  'status':"PatchMounted - patch successfully mounted",  'reboot':True}

    async with lock:
        resp = await _install()
        if patch_metadata:
            resp["patch_metadata"] = patch_metadata
        if resp["exit_code"] == 0:
            await loader.mark_installed_persistent(persist)
            resp["persist"] = persist
            if resp.get("reboot", False):
                log.info("restarting odin..")
                await restart_odin_engine(2)
        else:
            await loader.remove_patch_and_unmount()
            await clear_downloaded_and_staged()
        return resp


def format_exc(e: Exception) -> str:
    separator = "("
    if separator in repr(e):
        return f"{repr(e).split(separator)[0]} - {str(e)}"
    else:
        return repr(e)


async def verify_patch_firmware_signature_response(patch_signature_response: dict):
    if "error" in patch_signature_response:
        raise PatchFirmwareSignatureNotFound(f'error={patch_signature_response["error"]}')
    try:
        await assert_installed_firmware_signature_matches_signature(patch_signature_response.get(firmware_server.FIRMWARE_SIG_KEY))
    except PatchError as e:
        raise PatchFirmwareSignatureNotFound(f"{str(e)} for patch_sig={patch_signature_response.get(firmware_server.PATCH_SIG_KEY)}")


async def check_already_installed(patch_signature_response: dict) -> bool:
    if not await loader.is_installed():
        return False
    else:
        return await loader.get_patch_signature_from_ssq(await loader.get_installed_ssq_path()) == patch_signature_response.get(firmware_server.PATCH_SIG_KEY)


async def do_download(patch_signature_response: dict, timeout: float):
    patch_sig = patch_signature_response[firmware_server.PATCH_SIG_KEY]
    sig_res_response = await firmware_server.sig_res(patch_sig)
    if "error" in sig_res_response:
        raise SigResError(f'Sig-res failure patch_signature={patch_sig} error={sig_res_response["error"]}')
    await clear_downloaded_and_staged()
    try:
        await firmware_server.verify_sufficient_storage(PATCH_HOME,
          required_bytes=(patch_signature_response.get(firmware_server.NUM_BYTES_KEY, REQUIRED_STORAGE_BYTES)))
    except OSError as e:
        raise InsufficientFilesystemStorage(e)

    await download_and_decrypt(sig_res_response, timeout)


async def clear_downloaded_and_staged():
    await filesystem.remove_real_file(SSQ_FILE_STAGED)
    files = await filesystem.globpath(PATCH_HOME, "odinpatch.*-download")
    for f in files:
        await filesystem.remove_real_file(f)


async def download_and_decrypt(meta: dict, timeout: float):
    downloaded_ssq = SSQ_FILE_DOWNLOAD
    if meta.get("crypto_key"):
        downloaded_ssq = CSSQ_FILE_DOWNLOAD
    unencrypted_ssq = SSQ_FILE_DOWNLOAD
    staged_ssq_target = SSQ_FILE_STAGED
    if "ssq_download_url" not in meta:
        raise PatchError("invalid download metadata: {}".format(meta))
    log.info(f'downloading url={meta["ssq_download_url"]} target={downloaded_ssq}')
    success = await firmware_server.download_file(url=(meta["ssq_download_url"]),
      target_path=downloaded_ssq,
      retries=DOWNLOAD_RETRIES,
      timeout=timeout)
    if not success:
        raise PatchError("failed to download odin patch")
    crypto_key = meta.get("crypto_key")
    if crypto_key:
        try:
            async with aiofiles.open(CRYPTO_KEY_FILE, "wb") as f:
                await f.write(b64decode(crypto_key))
        except (OSError, BinasciiError) as err:
            await filesystem.remove_real_file(CRYPTO_KEY_FILE)
            raise PatchError(f"can not write decoded crypto-key {crypto_key} to file: {err}")

        try:
            await decrypt(downloaded_ssq, CRYPTO_KEY_FILE, unencrypted_ssq)
        finally:
            await filesystem.remove_real_file(CRYPTO_KEY_FILE)
            await filesystem.remove_real_file(CSSQ_FILE_DOWNLOAD)

    try:
        await filesystem.rename_file(unencrypted_ssq, staged_ssq_target)
    except (FileNotFoundError, OSError) as e:
        raise PatchError(f"can not move file {unencrypted_ssq} to {staged_ssq_target}: {e}")


async def verify_staged_ssq_package():
    await verify_signature()
    await assert_patch_firmware_signature_match(SSQ_FILE_STAGED)
    try:
        await loader.remove_patch_and_unmount()
    except PatchError as e:
        log.error("Can not uninstall installed ssq: {}".format(e))
        raise

    try:
        await filesystem.rename_file(SSQ_FILE_STAGED, loader.SSQ_FILE_INSTALLED)
    except (FileNotFoundError, OSError) as e:
        raise PatchError("can not move file {} to {}: {}".format(SSQ_FILE_STAGED, loader.SSQ_FILE_INSTALLED, e))


async def verify_signature():
    fused = True
    try:
        fused = await is_fused()
    except Exception as e:
        log.warning("can not read fused state {}".format(e))

    keys = [PROD_KEY]
    if not fused:
        keys.insert(0, DEV_KEY)
    await verify_nacl_signature(SSQ_FILE_STAGED, keys)

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/patch/install.pyc
