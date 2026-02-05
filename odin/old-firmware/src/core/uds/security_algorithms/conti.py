# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/uds/security_algorithms/conti.py
import struct

def conti_hash(seed, invert_seed=False, pin=0):
    seed_size = len(seed)
    seed = struct.unpack(">I", seed)[0]
    key = 0
    if invert_seed:
        key = ~seed & 4294967295L
    else:
        if pin:
            key = seed + pin
    key = bytearray(int.to_bytes(key, byteorder="big", length=seed_size))
    return key

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/uds/security_algorithms/conti.pyc
