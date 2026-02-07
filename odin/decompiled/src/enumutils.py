# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/enumutils.py
from operator import ior
from functools import reduce

def flags_to_string(value):
    return str(value).split(".")[1]


def flags_from_string(flags, value):
    return reduce(ior, (flags[x] for x in value.split("|")))

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/enumutils.pyc
