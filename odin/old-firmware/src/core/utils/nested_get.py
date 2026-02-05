# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/utils/nested_get.py
from typing import Any

def nested_get(dict_: dict, path: str) -> Any:
    parts = path.split(".")
    option_value = dict_
    for part in parts:
        try:
            option_value = option_value[part]
        except KeyError:
            break
        except TypeError:
            option_value = None

    else:
        return option_value

    return

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/utils/nested_get.pyc
