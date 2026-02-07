# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/uds/security_algorithms/bitron.py


def bitron_hash(seed: bytes) -> bytearray:
    key = bytearray(len(seed))
    key[0] = (seed[1] << 1) + 1 & 255
    key[1] = (seed[3] >> 1) + seed[2] & 255
    key[2] = seed[2] + key[0] & 255
    key[3] = seed[0] + key[1] & 255
    return key

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/uds/security_algorithms/bitron.pyc
