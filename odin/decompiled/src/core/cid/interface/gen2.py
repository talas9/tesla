# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/cid/interface/gen2.py
import odin
from odin.core.cid import settings

async def acc_power_on(timeout: float=settings.DEFAULT_TIMEOUT) -> bool:
    from . import get_url
    url = get_url("carserver", command="acc_power_on")
    session = await odin.get_http_session()
    async with session.get(url, timeout=timeout) as resp:
        resp.raise_for_status()
        results = await resp.json()
        result = results.get("result")
        if not result:
            reason = results.get("reason")
            raise RuntimeError("Failed to set ACC power on: {}".format(reason))
        else:
            return True

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/cid/interface/gen2.pyc
