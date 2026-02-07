# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/utils/options.py
from functools import wraps
from odin.config import options
from ..utils.nested_get import nested_get

def override_with_option(option):

    def _override(func):

        @wraps(func)
        async def wrapper(*args, **kw):
            _option = nested_get(options, option)
            if _option:
                return _option
            else:
                return await func(*args, **kw)

        return wrapper

    return _override

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/utils/options.pyc
