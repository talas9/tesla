# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/uds/security_algorithms/jlr.py


def jlr_hash(seed: bytes) -> bytearray:
    cb_h = 1441932025
    ch_l = 536870912 | (seed[2] & 255) << 16 | (seed[1] & 255) << 8 | seed[0] & 255
    mask = 15691735
    a_bytes = 12927401
    for i in range(32):
        cb_low = ch_l & 1
        a_temp = a_bytes & 1
        b_byte_24 = a_temp ^ cb_low
        a_bytes >>= 1
        a_bytes += b_byte_24 << 23
        b_byte_21 = a_bytes >> 20
        b_byte_21 = b_byte_21 & 1
        b_byte_16 = a_bytes >> 15
        b_byte_16 = b_byte_16 & 1
        b_byte_13 = a_bytes >> 12
        b_byte_13 = b_byte_13 & 1
        b_byte_6 = a_bytes >> 5
        b_byte_6 = b_byte_6 & 1
        b_byte_4 = a_bytes >> 3
        b_byte_4 = b_byte_4 & 1
        c_byte_21 = b_byte_24 ^ b_byte_21
        c_byte_21 &= 1
        c_byte_16 = b_byte_24 ^ b_byte_16
        c_byte_16 &= 1
        c_byte_13 = b_byte_24 ^ b_byte_13
        c_byte_13 &= 1
        c_byte_6 = b_byte_24 ^ b_byte_6
        c_byte_6 &= 1
        c_byte_4 = b_byte_24 ^ b_byte_4
        c_byte_4 &= 1
        a_bytes &= mask
        a_bytes += c_byte_21 << 20
        a_bytes += c_byte_16 << 15
        a_bytes += c_byte_13 << 12
        a_bytes += c_byte_6 << 5
        a_bytes += c_byte_4 << 3
        ch_l >>= 1

    for i in range(32):
        cb_high = cb_h & 1
        a_temp = a_bytes & 1
        b_byte_24 = a_temp ^ cb_high
        a_bytes >>= 1
        a_bytes += b_byte_24 << 23
        b_byte_21 = a_bytes >> 20
        b_byte_21 = b_byte_21 & 1
        b_byte_16 = a_bytes >> 15
        b_byte_16 = b_byte_16 & 1
        b_byte_13 = a_bytes >> 12
        b_byte_13 = b_byte_13 & 1
        b_byte_6 = a_bytes >> 5
        b_byte_6 = b_byte_6 & 1
        b_byte_4 = a_bytes >> 3
        b_byte_4 = b_byte_4 & 1
        c_byte_21 = b_byte_24 ^ b_byte_21
        c_byte_21 &= 1
        c_byte_16 = b_byte_24 ^ b_byte_16
        c_byte_16 &= 1
        c_byte_13 = b_byte_24 ^ b_byte_13
        c_byte_13 &= 1
        c_byte_6 = b_byte_24 ^ b_byte_6
        c_byte_6 &= 1
        c_byte_4 = b_byte_24 ^ b_byte_4
        c_byte_4 &= 1
        a_bytes &= mask
        a_bytes += c_byte_21 << 20
        a_bytes += c_byte_16 << 15
        a_bytes += c_byte_13 << 12
        a_bytes += c_byte_6 << 5
        a_bytes += c_byte_4 << 3
        cb_h >>= 1

    r = bytearray(len(seed))
    r[0] = a_bytes & 4095
    r[0] >>= 4
    r_rhs = a_bytes >> 20
    r_rhs &= 15
    r_lhs = a_bytes >> 12
    r_lhs &= 15
    r_lhs <<= 4
    r[1] = r_lhs + r_rhs
    r_lhs = a_bytes & 15
    r_lhs <<= 4
    r_rhs = a_bytes >> 16
    r_rhs &= 15
    r[2] = r_lhs + r_rhs
    return r

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/uds/security_algorithms/jlr.pyc
