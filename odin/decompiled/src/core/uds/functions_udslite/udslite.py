# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/uds/functions_udslite/udslite.py
import udslite
from functools import wraps
from typing import Callable, Tuple
from odin.core import can, uds
from odin.core.isotp.datalink.udslite_gateway import UdsliteGatewayDatalink
from odin.core.isotp.constants import N_BS_TIMEOUT, UDS_SERVER_ENHANCED_RESPONSE_TIME
from odin.core.isotp.error import ISOTPError
uds_exception_map = {(udslite.exceptions.InvalidArgument): (uds.exceptions.InvalidParam), 
 (udslite.exceptions.IsotpSendFailure): ISOTPError, 
 (udslite.exceptions.IsotpRecvFailure): ISOTPError, 
 (udslite.exceptions.InvalidResponse): (uds.exceptions.UdsTransportError), 
 (udslite.exceptions.SecurityLevelAlreadyUnlocked): (uds.exceptions.HasSecurityAccess), 
 (udslite.exceptions.ChecksumMismatch): (uds.exceptions.UdsTransportError), 
 (udslite.exceptions.GeneralReject): (uds.exceptions.GeneralReject), 
 (udslite.exceptions.ServiceNotSupported): (uds.exceptions.ServiceNotSupported), 
 (udslite.exceptions.SubfunctionNotSupported): (uds.exceptions.SubfunctionNotSupported), 
 (udslite.exceptions.InvalidLengthOrFormat): (uds.exceptions.IncorrectMessageLengthOrInvalidFormat), 
 (udslite.exceptions.ResponseTooLong): (uds.exceptions.ResponseTooLong), 
 (udslite.exceptions.BusyRepeatRequest): (uds.exceptions.BusyRepeatRequest), 
 (udslite.exceptions.ConditionsNotCorrect): (uds.exceptions.ConditionsNotCorrect), 
 (udslite.exceptions.RequestSequenceError): (uds.exceptions.RequestSequenceError), 
 (udslite.exceptions.NoResponseFromSubnetComponent): (uds.exceptions.NoResponseFromSubnetComponent), 
 (udslite.exceptions.FailurePreventsExecution): (uds.exceptions.FailurePreventsExecutionOfRequestedAction), 
 (udslite.exceptions.RequestOutOfRange): (uds.exceptions.RequestOutOfRange), 
 (udslite.exceptions.SecurityAccessDenied): (uds.exceptions.SecurityAccessDenied), 
 (udslite.exceptions.InvalidKey): (uds.exceptions.InvalidKey), 
 (udslite.exceptions.ExceededNumberOfAttempts): (uds.exceptions.ExceededNumberOfAttempts), 
 (udslite.exceptions.RequiredTimeDelayNotExpired): (uds.exceptions.RequiredTimeDelayNotExpired), 
 (udslite.exceptions.UploadDownloadNotAccepted): (uds.exceptions.UploadDownloadNotAccepted), 
 (udslite.exceptions.TransferDataSuspended): (uds.exceptions.TransferDataSuspended), 
 (udslite.exceptions.GeneralProgrammingFailure): (uds.exceptions.GeneralProgrammingFailure), 
 (udslite.exceptions.WrongBlockSequenceCounter): (uds.exceptions.WrongBlockSequenceCounter), 
 (udslite.exceptions.ResponsePending): (uds.exceptions.RequestCorrectlyReceivedResponsePending), 
 (udslite.exceptions.SubfunctionNotSupportedInActiveSession): (uds.exceptions.SubfunctionNotSupportedInActiveSession), 
 (udslite.exceptions.ServiceNotSupportedInActiveSession): (uds.exceptions.ServiceNotSupportedInActiveSession), 
 (udslite.exceptions.TemperatureTooHigh): (uds.exceptions.TemperatureTooHigh), 
 (udslite.exceptions.TemperatureTooLow): (uds.exceptions.TemperatureTooLow), 
 (udslite.exceptions.VoltageTooHigh): (uds.exceptions.VoltageTooHigh), 
 (udslite.exceptions.VoltageTooLow): (uds.exceptions.VoltageTooLow)}

def get_udsclient_with_datalink(node: uds.Node) -> Tuple[(udslite.client.AsyncUDSClient, UdsliteGatewayDatalink)]:
    if node.uds_client is None or node.datalink is None:
        datalink = UdsliteGatewayDatalink(node.bus, can.Bus.ETH, node.request_message.message_id, node.response_message.message_id)
        client = udslite.client.AsyncUDSClient(datalink)
        node.uds_client = client
        node.datalink = datalink
    node.uds_client.set_timeout(timeout=N_BS_TIMEOUT, enhanced_timeout=UDS_SERVER_ENHANCED_RESPONSE_TIME)
    return (node.uds_client, node.datalink)


def translate_udslite_exception(request: Callable) -> Callable:

    @wraps(request)
    async def translate_and_reraise(*args, **kwargs):
        try:
            return await request(*args, **kwargs)
        except udslite.UDSException as e:
            raise uds_exception_map.get(type(e), e)

    return translate_and_reraise

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/uds/functions_udslite/udslite.pyc
