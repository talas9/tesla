# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/utils/png.py
import struct, png

def uint16ToGrayscale(raw_bytes: bytes, width: int, height: int) -> png.Image:
    bytes_2d_array = []
    row_byte_len = width * 2
    for h in range(height):
        start = h * row_byte_len
        row = raw_bytes[start:start + row_byte_len]
        try:
            bytes_2d_array.append(struct.unpack("H" * width, row))
        except ValueError:
            pass

    return png.from_array(bytes_2d_array, mode="L;16")


def uint8ToRGB(raw_bytes: bytes, width: int, height: int) -> png.Image:
    bytes_2d_array = []
    row_byte_len = width * 3
    for h in range(height):
        start = h * row_byte_len
        row = raw_bytes[start:start + row_byte_len]
        try:
            bytes_2d_array.append(struct.unpack("c" * width * 3, row))
        except ValueError:
            pass

    return png.from_array(bytes_2d_array, mode="RGB;8", info={'height':height,  'width':width})

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/utils/png.pyc
