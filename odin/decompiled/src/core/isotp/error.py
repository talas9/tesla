# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/isotp/error.py
import asyncio
from typing import Optional
from odin.core.exception import OdinException

class ISOTPError(OdinException):
    ecu_name = None
    return


class ISOTPTimeoutError(ISOTPError, asyncio.TimeoutError):

    def __init__(self, msg):
        default_msg = "This is the general error value. It shall be issued to the service user when an error has beendetected by the network layer and no other parameter value can be used to better describethe error. It can be issued to the service user on both the sender and receiver side."
        super().__init__(msg or default_msg)


class TimeoutA(ISOTPTimeoutError):

    def __init__(self, as_max, ar_max):
        msg = "This value is issued to the protocol user when the timer N_Ar/N_As has passed its time-out value N_Asmax({})/N_Armax({}); it can be issued to service user on both the sender and receiver side.".format(as_max, ar_max)
        super().__init__(msg)


class TimeoutAr(ISOTPTimeoutError):

    def __init__(self, ar_max):
        msg = "This value is issued to the protocol user when the timer N_Ar has passed its time-out value N_Armax({}); it can be issued to service user on both the sender and receiver side.".format(ar_max)
        super().__init__(msg)


class TimeoutAs(ISOTPTimeoutError):

    def __init__(self, as_max):
        msg = "This value is issued to the protocol user when the timer N_As has passed its time-out value N_Asmax({}); it can be issued to service user on both the sender and receiver side.".format(as_max)
        super().__init__(msg)


class TimeoutBs(ISOTPTimeoutError):

    def __init__(self, bs_max):
        msg = "This value is issued to the service user when the timer N_Bs has passed its time-out value N_Bsmax({}); it can be issued to the service user on the sender side only.".format(bs_max)
        super().__init__(msg)


class TimeoutCr(ISOTPTimeoutError):

    def __init__(self, cr_max):
        msg = "This value is issued to the service user when the timer N_Cr has passed its time-out value N_Crmax({}); it can be issued to the service user on the receiver side only.".format(cr_max)
        super().__init__(msg)


class WrongSn(ISOTPTimeoutError):

    def __init__(self, expected_sn, actual_sn):
        msg = "This value is issued to the service user upon reception of an unexpected sequence number (PCI.SN) value(expected:{}, actual:{}); it can be issued to the service user on the receiver side only.".format(expected_sn, actual_sn)
        super().__init__(msg)


class InvalidFs(ISOTPTimeoutError):

    def __init__(self, flow_status):
        msg = "This value is issued to the service user when an invalid or unknown FlowStatus value({}) has been received in a flow control (FC) N_PDU; it can be issued to the service user on the sender side only.".format(flow_status)
        super().__init__(msg)


class UnexpPdu(ISOTPTimeoutError):

    def __init__(self, pdu_data):
        msg = "This value is issued to the service user upon reception of an unexpected protocol data unit; it can be issued to the service user on the receiver side only.".format(pdu_data)
        super().__init__(msg)


class WftOvrn(ISOTPTimeoutError):

    def __init__(self, wft_max):
        msg = "This value is issued to the service user upon reception of flow control WAIT frame that exceeds the maximum counter N_WFTmax({}).".format(wft_max)
        super().__init__(msg)


class BufferOverflow(ISOTPTimeoutError):

    def __init__(self):
        msg = "This value is issued to the service user upon reception of a flow control (FC) ProtocolDataUnit with FlowStatus = OVFLW. It indicates that the buffer on the receiver side of a segmented message transmission cannot store the number of bytes specified by the FirstFrame DataLength (FF_DL) parameter in the FirstFrame and therefore the transmission of the segmented message was aborted. It can be issued to the service user on the sender side only."
        super().__init__(msg)


class DatalinkError(ISOTPError):
    return

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/isotp/error.pyc
