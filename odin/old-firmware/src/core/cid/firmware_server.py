# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/cid/firmware_server.py
import asyncio, aiofiles
from aiohttp.client_exceptions import ClientError
import logging, urllib.parse, odin
from odin.core.cid.interface import get_vin
from odin.core.cid.interface import filesystem
CHUNK_SIZE = 1024
SIG_RES_URL = "http://firmware.vn.teslamotors.com:4567/packages/signature"
PATCH_URL = "http://firmware.vn.teslamotors.com:4567/vehicles/{}/odinpatch"
PATCH_SIG_KEY = "odinpatch_signature"
FIRMWARE_SIG_KEY = "firmware_signature"
NUM_BYTES_KEY = "num_bytes"
SSQ_URL_KEY = "ssq_download_url"
log = logging.getLogger(__name__)

async def available_patch_sig(timeout: float=5) -> dict:
    try:
        vin = await get_vin()
    except asyncio.TimeoutError:
        return {"error": "no vin found"}
    else:
        try:
            resp = await _get_json((PATCH_URL.format(vin)), timeout=timeout, retries=2)
        except (asyncio.TimeoutError, ClientError) as e:
            log.error("failure available_patch_sig: {}".format(e))
            return {"error": (str(e))}
        else:
            if "error" in resp or PATCH_SIG_KEY in resp and FIRMWARE_SIG_KEY in resp:
                return resp
            else:
                log.error("unknown response available_patch_sig: {}".format(resp))
                return {"error": "unknown response to request available odin patch signature"}


async def sig_res(package_signature: str, timeout: float=5) -> dict:
    if not package_signature:
        return {"error": "missing package_signature"}
    else:
        params = {"signature": (urllib.parse.quote(package_signature))}
        try:
            resp = await _get_json(SIG_RES_URL, params=params, timeout=timeout, retries=2)
        except (asyncio.TimeoutError, ClientError) as e:
            log.error("failure sig_res: {}".format(e))
            return {"error": (repr(e))}
        else:
            log.info(f"sigres response: {resp}")
        if SSQ_URL_KEY not in resp:
            return {"error": ("missing key={} response={}".format(SSQ_URL_KEY, str(resp)))}
        return resp


async def _get_json(url, params=None, timeout=3, retries=0):
    session = await odin.get_http_session()
    for i in range(retries + 1):
        try:
            async with session.get(url, params=params, timeout=timeout) as resp:
                resp.raise_for_status()
                if "json" in resp.headers.get("content-type", ""):
                    return await resp.json()
                else:
                    return {"error": (await resp.text())}
        except asyncio.TimeoutError as e:
            log.error("Attempt {}: TimeoutError url={} seconds_timeout={}".format(i, url, timeout))
            if i == retries:
                raise e


async def download_file(url, target_path, retries=0, timeout=120):
    for i in range(retries + 1):
        try:
            await _download(url, target_path, timeout=timeout)
        except (OSError, ClientError, asyncio.TimeoutError) as err:
            log.error('Attempt {}" Failure during download:\ntarget: {}\n url: {}\nerr: {}'.format(i, target_path, url, repr(err)))
        else:
            return True

    return False


async def _download(url: str, target_path: str, timeout: float=10):
    session = await odin.get_http_session()
    async with session.get(url, timeout=timeout) as resp:
        resp.raise_for_status()
        async with aiofiles.open(target_path, "bw") as f:
            async for data in resp.content.iter_chunked(CHUNK_SIZE):
                await f.write(data)


async def verify_sufficient_storage(path: str, required_bytes: int):
    _, _, free = await filesystem.disk_usage(path)
    if free < required_bytes:
        raise OSError("Insufficient disk space: path={}, available_bytes={}, required_bytes={}".format(path, free, required_bytes))

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/cid/firmware_server.pyc
