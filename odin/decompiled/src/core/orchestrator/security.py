# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/orchestrator/security.py
import logging
from typing import Optional, Tuple
import odin.core.can.signal
from odin.core.cid.interface import is_fused
from . import locks
log = logging.getLogger(__name__)
_GTW_DIAG_LEVEL_SIGNAL = "GTW_diagLevel"
_GTW_DIAG_REMAINING_SECONDS_SIGNAL = "GTW_diagRemainingSeconds"
_GTW_UNLOCKED_LEVELS = {"LEVEL_FACTORY", "LEVEL_SERVICE"}

@locks.timed_cache(2)
async def get_gateway_status() -> Tuple[(Optional[str], Optional[int])]:
    try:
        readings = await odin.core.can.signal.read_by_names([
         _GTW_DIAG_LEVEL_SIGNAL,
         _GTW_DIAG_REMAINING_SECONDS_SIGNAL])
        diag_level = readings.get(_GTW_DIAG_LEVEL_SIGNAL)
        diag_seconds = readings.get(_GTW_DIAG_REMAINING_SECONDS_SIGNAL, 0)
        return (diag_level, diag_seconds)
    except RuntimeError:
        log.exception("Error reading gateway status")
        return (None, None)


async def gateway_unlocked() -> bool:
    diag_level, _ = await get_gateway_status()
    return diag_level in _GTW_UNLOCKED_LEVELS


async def allow_fused_jobs(jobs_file: str) -> bool:
    if jobs_file == "fuse-jobs":
        return True
    else:
        if not await is_fused():
            return True
        return await gateway_unlocked()

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/orchestrator/security.pyc
