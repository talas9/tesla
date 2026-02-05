# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/services/data_upload/request_lock.py
import asyncio
from asyncio_extras import async_contextmanager
from odin.core.utils.singleton import make_singleton_getter

class Requests:
    new_request = False


@async_contextmanager
async def unlocked_data_upload():
    lock = get_lock()
    if lock.locked():
        Requests.new_request = True
        yield False
    else:
        await lock
        try:
            yield True
        finally:
            Requests.new_request = False
            lock.release()


get_lock = make_singleton_getter(asyncio.Lock)

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/services/data_upload/request_lock.pyc
