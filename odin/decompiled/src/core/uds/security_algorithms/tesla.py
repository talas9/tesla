# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/uds/security_algorithms/tesla.py


def tesla_hash(seed: bytes) -> bytearray:
    tesla_simple_byte_mask = 53
    key_list = [byte & 255 ^ tesla_simple_byte_mask for byte in seed]
    key = bytearray(key_list)
    return key

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/uds/security_algorithms/tesla.pyc
