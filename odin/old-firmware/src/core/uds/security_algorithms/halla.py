# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/uds/security_algorithms/halla.py
import struct

def halla_hash(seed: bytes) -> bytearray:
    key_table = [0, 
     43432, 
     48157, 
     63860, 
     9569, 
     46348, 
     58126, 
     14696, 
     8588, 
     35476, 
     41447, 
     17805, 
     22467, 
     23025, 
     59813, 
     29621]
    seed_size = len(seed)
    seed = struct.unpack(">H", seed)[0]
    msb = seed >> 8
    lsb = seed & 255
    key = key_table[lsb & 15] ^ (msb << 8 | lsb)
    key = bytearray(int.to_bytes(key, byteorder="big", length=seed_size))
    return key

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/uds/security_algorithms/halla.pyc
