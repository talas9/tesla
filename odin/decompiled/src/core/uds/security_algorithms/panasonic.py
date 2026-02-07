# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/uds/security_algorithms/panasonic.py
import struct

def panasonic_hash(seed: bytes) -> bytearray:
    seed_size = len(seed)
    seed = struct.unpack(">H", seed)[0]
    key = 0
    for bitIndex in range(16):
        key |= (seed >> bitIndex & 1) << 15 - bitIndex

    key ^= 23145
    key = bytearray(int.to_bytes(key, byteorder="big", length=seed_size))
    return key

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/uds/security_algorithms/panasonic.pyc
