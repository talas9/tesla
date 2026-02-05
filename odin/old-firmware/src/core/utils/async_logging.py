# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/utils/async_logging.py
import logging
from .desync import desync
log = logging.getLogger(__name__)
try:
    from syslog import syslog
except ImportError:
    syslog = log.info

async def async_syslog(log_string: str):
    await desync(syslog, log_string)

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/utils/async_logging.pyc
