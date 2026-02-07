# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/uds/security_algorithms/bosch.py
import struct

def bosch_hash(seed: bytes, invert_seed: bool=False) -> bytearray:
    seed_size = len(seed)
    seed = struct.unpack(">I", seed)[0]
    if invert_seed:
        seed = ~seed & 4294967295L
    else:
        location = {
         'A': 17, 
         'B': 8, 
         'C': 13, 
         'D': 2, 
         'E': 24, 
         'F': 5, 
         'G': 31}
        shift_direction = seed >> location["A"] & 1
        num_shifts = (seed >> location["B"] & 1) << 3 | (seed >> location["C"] & 1) << 2 | (seed >> location["D"] & 1) << 1 | seed >> location["E"] & 1
        if shift_direction == 0:
            mask = ~(255 << num_shifts)
            shifted_seed = seed >> num_shifts | (seed & mask) << 32 - num_shifts
        else:
            mask = ~(255 << num_shifts) << 32 - num_shifts
            shifted_seed = seed << num_shifts | (seed & mask) >> 32 - num_shifts
        seed_rule = (seed >> location["F"] & 1) << 1 | seed >> location["G"] & 1
        if seed_rule == 0:
            key = seed | shifted_seed
        elif seed_rule == 1:
            key = seed & shifted_seed
        elif seed_rule == 2:
            key = seed ^ shifted_seed
        else:
            key = shifted_seed
    key &= 4294967295L
    key = bytearray(int.to_bytes(key, byteorder="big", length=seed_size))
    return key

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/uds/security_algorithms/bosch.pyc
