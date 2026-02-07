# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/utils/iqmath.py
__authors__ = [
 "Jonathan Tan"]
__author__ = ",".join(__authors__)
__email__ = "jtan@teslamotors.com"
__copyright__ = "Copyright Tesla Motors Inc. 2015"

def from_iq(number, m, n):
    sign_mask = 1 << m + n - 1
    factor = 1
    if number & sign_mask:
        factor = -1
        complement = (1 << m + n) - 1
        number = (int(number) ^ complement) + 1
    return float(number) * 2 ** (-1 * n) * factor


def from_iq28(number, base, offset=0):
    val = from_iq(number, 4, 28)
    return (val - offset) * base


def to_iq(number, m, n, signed=False):
    iq = int(round(number * 2 ** n))
    if number < 0:
        if not signed:
            iq = abs(iq)
            complement = (1 << m + n) - 1
            iq = (iq ^ complement) + 1
    return iq


def to_iq28(number, base, offset=0, signed=False):
    val = float(number) / base + offset
    return to_iq(val, 4, 28, signed=signed)

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/utils/iqmath.pyc
