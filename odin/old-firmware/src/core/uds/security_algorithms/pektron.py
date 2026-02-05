# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/uds/security_algorithms/pektron.py


def pektron_hash(seed: bytes, fixed_bytes: bytes) -> bytearray:
    if isinstance(fixed_bytes, str):
        fixed_bytes = bytes.fromhex(fixed_bytes)
    challenge_bits = fixed_bytes[4] << 56
    challenge_bits |= fixed_bytes[3] << 48
    challenge_bits |= fixed_bytes[2] << 40
    challenge_bits |= fixed_bytes[1] << 32
    challenge_bits |= fixed_bytes[0] << 24
    challenge_bits |= seed[2] << 16
    challenge_bits |= seed[1] << 8
    challenge_bits |= seed[0]
    intermediate_word = 12927401
    for bit_counter in range(64):
        a = intermediate_word
        bit = challenge_bits >> bit_counter & 1
        b24 = a & 1 ^ bit
        b = a >> 1 | b24 << 23
        xor_mask = b24 << 3 | b24 << 5 | b24 << 12 | b24 << 15 | b24 << 20
        intermediate_word = b ^ xor_mask

    response_bytes = bytearray(3)
    response_bytes[0] = intermediate_word >> 4 & 255
    response_bytes[1] = intermediate_word >> 8 & 240 | intermediate_word >> 20 & 15
    response_bytes[2] = intermediate_word << 4 & 240 | intermediate_word >> 16 & 15
    return response_bytes

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/uds/security_algorithms/pektron.pyc
