# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/uds/exceptions.py
from ..exception import OdinException

class UdsErrorRegistry(type):
    registry = {}

    def __new__(mcs, name, bases, attrs):
        new_class = super(UdsErrorRegistry, mcs).__new__(mcs, name, bases, attrs)
        if hasattr(new_class, "ResponseCode"):
            mcs.registry[new_class.ResponseCode] = new_class
        return new_class

    @classmethod
    def get(mcs, *args, **kwargs):
        return (mcs.registry.get)(*args, **kwargs)


class UdsException(OdinException):
    ecu_name = None


class UdsError(UdsException):

    def __init__(self, error_code=None):
        self.error_code = getattr(self, "ResponseCode", error_code)
        if self.error_code is None:
            message = "Type: {}".format(type(self).__bases__)
        else:
            message = getattr(self, "Description", "Type: {} Response Code: 0x{:x}".format(type(self).__bases__, self.error_code))
        super().__init__(message)


class NodeLocked(UdsException):

    def __init__(self, code):
        msg = "UDS node is locked: {0}".format(code)
        super().__init__(msg)


class UdsTransportErrorRegistry(UdsErrorRegistry):
    registry = {}


class UdsTransportError(UdsError, metaclass=UdsTransportErrorRegistry):
    return


class UdsEcuErrorRegistry(UdsErrorRegistry):
    registry = {}


class UdsEcuError(UdsError, metaclass=UdsEcuErrorRegistry):
    return


class UdsProtocolErrorRegistry(UdsErrorRegistry):
    registry = {}


class UdsProtocolError(UdsError, metaclass=UdsProtocolErrorRegistry):
    return


class TimeoutA01(UdsTransportError):
    ResponseCode = 1
    Description = "This value is issued to the protocol user when the timer N_Ar/N_As has passed its time-out value N_Asmax/N_Armax; it can be issued to service user on both the sender and receiver side."


class TimeoutA02(UdsTransportError):
    ResponseCode = 2
    Description = "This value is issued to the protocol user when the timer N_Ar/N_As has passed its time-out value N_Asmax/N_Armax; it can be issued to service user on both the sender and receiver side."


class TimeoutBs01(UdsTransportError):
    ResponseCode = 4
    Description = "This value is issued to the service user when the timer N_Bs has passed its time-out value N_Bsmax; it can be issued to the service user on the sender side only."


class TimeoutBs02(UdsTransportError):
    ResponseCode = 5
    Description = "This value is issued to the service user when the timer N_Bs has passed its time-out value N_Bsmax; it can be issued to the service user on the sender side only."


class TimeoutCr(UdsTransportError):
    ResponseCode = 6
    Description = "This value is issued to the service user when the timer N_Cr has passed its time-out value N_Crmax; it can be issued to the service user on the receiver side only."


class WrongSn(UdsTransportError):
    ResponseCode = 7
    Description = "This value is issued to the service user upon reception of an unexpected sequence number (PCI.SN) value; it can be issued to the service user on the receiver side only."


class InvalidFs01(UdsTransportError):
    ResponseCode = 8
    Description = "This value is issued to the service user when an invalid or unknown FlowStatus value has been received in a flow control (FC) N_PDU; it can be issued to the service user on the sender side only."


class InvavlidFs02(UdsTransportError):
    ResponseCode = 9
    Description = "This value is issued to the service user when an invalid or unknown FlowStatus value has been received in a flow control (FC) N_PDU; it can be issued to the service user on the sender side only."


class UnexpPdu01(UdsTransportError):
    ResponseCode = 10
    Description = "This value is issued to the service user upon reception of an unexpected protocol data unit; it can be issued to the service user on the receiver side only."


class UnexpPdu02(UdsTransportError):
    ResponseCode = 11
    Description = "This value is issued to the service user upon reception of an unexpected protocol data unit; it can be issued to the service user on the receiver side only."


class UnexpPdu03(UdsTransportError):
    ResponseCode = 12
    Description = "This value is issued to the service user upon reception of an unexpected protocol data unit; it can be issued to the service user on the receiver side only."


class UnexpPdu04(UdsTransportError):
    ResponseCode = 13
    Description = "This value is issued to the service user upon reception of an unexpected protocol data unit; it can be issued to the service user on the receiver side only."


class UnexpPdu05(UdsTransportError):
    ResponseCode = 14
    Description = "This value is issued to the service user upon reception of an unexpected protocol data unit; it can be issued to the service user on the receiver side only."


class WftOvrn(UdsTransportError):
    ResponseCode = 15
    Description = "This value is issued to the service user upon reception of flow control WAIT frame that exceeds the maximum counter N_WFTmax."


class BufferOverflow(UdsTransportError):
    ResponseCode = 16
    Description = "This is the general error value. It shall be issued to the service user when an error has beendetected by the network layer and no other parameter value can be used to better describethe error. It can be issued to the service user on both the sender and receiver side."


class Error01(UdsTransportError):
    ResponseCode = 17


class Error02(UdsTransportError):
    ResponseCode = 18


class Error03(UdsTransportError):
    ResponseCode = 19


class Error04(UdsTransportError):
    ResponseCode = 20


class Error05(UdsTransportError):
    ResponseCode = 21


class Error06(UdsTransportError):
    ResponseCode = 22


class Error07(UdsTransportError):
    ResponseCode = 23


class InvalidHandle(UdsTransportError):
    ResponseCode = 24


class LastError(UdsTransportError):
    ResponseCode = 25


class GeneralReject(UdsEcuError):
    ResponseCode = 272


class ServiceNotSupported(UdsEcuError):
    ResponseCode = 273


class SubfunctionNotSupported(UdsEcuError):
    ResponseCode = 274
    Description = "This code is returned if the requested sub-function is not supported."


class IncorrectMessageLengthOrInvalidFormat(UdsEcuError):
    ResponseCode = 275
    Description = "The length of the message is wrong."


class ResponseTooLong(UdsEcuError):
    ResponseCode = 276


class BusyRepeatRequest(UdsEcuError):
    ResponseCode = 289


class ConditionsNotCorrect(UdsEcuError):
    ResponseCode = 290
    Description = "This code shall be returned if the criteria for the request RoutineControl are not met."


class RequestSequenceError(UdsEcuError):
    ResponseCode = 292
    Description = 'This code shall be returned if the "stopRoutine" or "requestRoutineResults" subfunction is received without first receiving a "startRoutine" for the requested routineIdentifier.'


class NoResponseFromSubnetComponent(UdsEcuError):
    ResponseCode = 293
    Description = "This response code indicates that the server has received the request but the requested action could not be performed by the server, as a subnet component which is necessary to supply the requested information did not respond within the specified time."


class FailurePreventsExecutionOfRequestedAction(UdsEcuError):
    ResponseCode = 294
    Description = "This response code indicates that the requested action will not be taken because a failure condition, identified by a DTC (with at least one DTC status bit for TestFailed, Pending, Confirmed or TestFailedSinceLastClear set to 1), has occurred and that this failure condition prevents the server from performing the requested action. This NRC can, for example, direct the technician to read DTCs in order to identify and fix the problem. "


class RequestOutOfRange(UdsEcuError):
    ResponseCode = 305
    Description = "The code shall be returned if: 1) the server does not support the requested routineIdentifier 2) the user optional routineControlOptionRecord contains invalid data for the requested routineIdentifier."


class SecurityAccessDenied(UdsEcuError):
    ResponseCode = 307
    Description = "This code is returned if a client sends a request with an valid secure routineIdentifier and the server's security feature is currently active."


class InvalidKey(UdsEcuError):
    ResponseCode = 309
    Description = 'Send if an expected "sendKey" sub-function value is received and the value of the key does not match the server\'s internally stored/calculated key.'


class ExceededNumberOfAttempts(UdsEcuError):
    ResponseCode = 310
    Description = "Send if the delay timer is active due to exceeding the maximum number of allowed false access attempts."


class RequiredTimeDelayNotExpired(UdsEcuError):
    ResponseCode = 311
    Description = "Send if the delay timer is active and a request is transmitted."


class UploadDownloadNotAccepted(UdsEcuError):
    ResponseCode = 368
    Description = "This response code indicates than an attempt to download a server's memory cannot be accomplished due to fault conditions."


class TransferDataSuspended(UdsEcuError):
    ResponseCode = 369
    Description = "This response code indicates that a data transfer operation was halted due to a fault. The active transferData sequence shall be aborted."


class GeneralProgrammingFailure(UdsEcuError):
    ResponseCode = 370
    Description = "This return code shall be sent if the server detects an error when performing a routine which accesses server internal memory."


class WrongBlockSequenceCounter(UdsEcuError):
    ResponseCode = 371
    Description = "This return code shall be sent if the server detects an error in the sequence of the blockSequenceCounter. The repetition of a TransferData request message with a blockSequenceCounter equal to the one included in the previous TransferData request shall be accepted by the server."


class RequestCorrectlyReceivedResponsePending(UdsEcuError):
    ResponseCode = 376
    Description = "This response code indicates that the request message was received correctly, and that all parameters in the request message were valid, but the action to be performed is not yet completed and the server is not yet ready to receive another request."


class SubfunctionNotSupportedInActiveSession(UdsEcuError):
    ResponseCode = 382
    Description = "This code is returned if the requested subfunction is not supported in the active session"


class ServiceNotSupportedInActiveSession(UdsEcuError):
    ResponseCode = 383
    Description = "This code is returned if the requested service is not supported in the active session"


class RpmTooHigh(UdsEcuError):
    ResponseCode = 385
    Description = "This response code indicates that the requested action will not be taken because the server prerequisite condition for RPM is not met."


class RpmTooLow(UdsEcuError):
    ResponseCode = 386
    Description = "This response code indicates that the requested action will not be taken because the server prerequisite condition for RPM is not met."


class EngineIsRunning(UdsEcuError):
    ResponseCode = 387
    Description = "This is required for those actuator tests which cannot be actuated while the engine is running. This is different from the RPM too high negative response and needs to be allowed."


class EngineIsNotRunning(UdsEcuError):
    ResponseCode = 388
    Description = "This is required for those actuator tests which cannot be actuated unless the Engine is running. This is different from the RPM too low negative response and shall be allowed."


class EngineRunTimeTooLow(UdsEcuError):
    ResponseCode = 389
    Description = "This response code indicates that the requested action will not be taken because the server prerequisite condition for engine run time is not met."


class TemperatureTooHigh(UdsEcuError):
    ResponseCode = 390
    Description = "This response code indicates that the requested action will not be taken because the server prerequisite condition for temperature is not met."


class TemperatureTooLow(UdsEcuError):
    ResponseCode = 391
    Description = "This response code indicates that the requested action will not be taken because the server prerequisite condition for temperature is not met"


class VehicleSpeedTooHigh(UdsEcuError):
    ResponseCode = 392
    Description = "This response code indicates that the requested action will not be taken because the server prerequisite condition for vehicle speed is not met."


class VehicleSpeedTooLow(UdsEcuError):
    ResponseCode = 393
    Description = "This response code indicates that the requested action will not be taken because the server prerequisite condition for vehicle speed is not met."


class ThrottlePedalTooHigh(UdsEcuError):
    ResponseCode = 394
    Description = "This response code indicates that the requested action will not be taken because the server prerequisite condition for throttle/pedal position is not met."


class ThrottlePedalTooLow(UdsEcuError):
    ResponseCode = 395
    Description = "This response code indicates that the requested action will not be taken because the server prerequisite condition for throttle/pedal position is not met."


class TransmissionRangeNotInNeutral(UdsEcuError):
    ResponseCode = 396
    Description = "This response code indicates that the requested action will not be taken because the server prerequisite condition for being in neutral is not met"


class TransmissionRangeNotInGear(UdsEcuError):
    ResponseCode = 397
    Description = "This response code indicates that the requested action will not be taken because the server prerequisite condition for being in gear is not met"


class BrakeSwitchesNotClosed(UdsEcuError):
    ResponseCode = 399
    Description = "For safety reasons, this is required before beginning certain tests, and must be maintained for the entire duration of the test."


class ShifterLeverNotInPark(UdsEcuError):
    ResponseCode = 400
    Description = "For safety reasons, this is required before beginning certain tests, and must be maintained for the entire duration of the test."


class TorqueConverterClutchLocked(UdsEcuError):
    ResponseCode = 401
    Description = "This response code indicates that the requested action will not be taken because the server prerequisite condition for torque converter clutch is not met "


class VoltageTooHigh(UdsEcuError):
    ResponseCode = 402
    Description = "This return code shall be sent, as applicable, if the voltage measured at the primary pin of the server is out of the acceptable range for downloading data into the server's permanent memory."


class VoltageTooLow(UdsEcuError):
    ResponseCode = 403
    Description = "This response code indicates that the requested action will not be taken because the server prerequisite condition for voltage at the primary pin of the server (ECU) is not met"


class SidMismatch(UdsProtocolError):
    ResponseCode = 512
    Description = "Receive SID is different from requested SID."


class SubFuncMismatch(UdsProtocolError):
    ResponseCode = 768
    Description = "A mismatch in received sub function value."


class InvalidParam(UdsProtocolError):
    ResponseCode = 769
    Description = "An invalid parameter is being passed to the API."


class InvalidSubfunc(UdsProtocolError):
    ResponseCode = 770
    Description = "An invalid sub function is being passed to Read DTC function."


class HasSecurityAccess(UdsProtocolError):
    ResponseCode = 771
    Description = "Server is already in the requested security access level."


class TransportNotSetup(UdsProtocolError):
    ResponseCode = 772
    Description = "The transport layer callback function is not setup properly."

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/uds/exceptions.pyc
