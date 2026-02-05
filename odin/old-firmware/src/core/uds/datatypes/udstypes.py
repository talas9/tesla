# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/uds/datatypes/udstypes.py
from enum import IntEnum, unique, IntFlag

@unique
class RoutineControl(IntEnum):
    START_ROUTINE = 1
    STOP_ROUTINE = 2
    REQUEST_ROUTINE_RESULTS = 3


@unique
class IoControl(IntEnum):
    RETURN_TO_ECU = 0
    RESET_TO_DEFAULT = 1
    FREEZE = 2
    SHORT_TERM_ADJUST = 3


@unique
class SecurityLevel(IntEnum):
    LOCKED = 0
    LEVEL_1 = 1
    LEVEL_3 = 3
    LEVEL_5 = 5
    LEVEL_11 = 11


@unique
class Reset(IntEnum):
    HARD_RESET = 1
    KEY_OFF_ON_RESET = 2
    SOFT_RESET = 3


@unique
class SessionType(IntEnum):
    NO_SESSION = -1
    DEFAULT_SESSION = 1
    PROGRAMMING_SESSION = 2
    EXTENDED_DIAGNOSTIC_SESSION = 3
    SAFETY_SYSTEM_DIAGNOSTIC_SESSION = 4


@unique
class ModuleID(IntEnum):
    UDS_FLASH_APPLICATION = 0
    UDS_CPLD = 1
    UDS_CURRENT_SHUNT = 2
    UDS_SERIALIZED_BMB = 3
    UDS_LOAD_FLASH_API = 4
    UDS_FLASH_BOOTLOADER = 5
    UDS_SECONDARY_APPLICATION = 6
    UDS_CALIBRATION_DATA = 7
    UDS_TERTIARY_APPLICATION = 8
    UDS_SERIALIZED_BMB_BOOTUPDATE = 9
    UDS_ECU_CONFIG = 10
    UDS_SUBCOMPONENT1_BOOT = 11
    UDS_SUBCOMPONENT2_APP = 12
    UDS_SUBCOMPONENT3_FFS = 13
    UDS_SECONDARY_FLASH_APPLICATION = 14
    UDS_RAM_APPLICATION = 15
    UDS_FLASH_BOOTUPDATER = 16
    UDS_QUATERNARY_APPLICATION = 17
    UDS_INVALID_MODULE = 255


@unique
class DTCMask(IntFlag):
    TestFailed = 1
    TestFailedThisOperationCycle = 2
    PendingDTC = 4
    ConfirmedDTC = 8
    TestNotCompletedSinceLastClear = 16
    TestFailedSinceLastClear = 32
    TestNotCompletedThisOperationCycle = 64
    WarningIndicatorRequested = 128


@unique
class DTCReportType(IntEnum):
    NumberOfDTCByStatusMask = 1
    DTCByStatusMask = 2
    SupportedDTCs = 10
    FirstTestFailedDTC = 11
    FirstConfirmedDT = 12
    MostRecentTestFailedDTC = 13
    MostRecentConfirmedDTC = 14
    MirrorMemoryDTCByStatusMask = 15
    EmissionsRelatedOBDDTCByStatusMask = 19
    DTCWithPermanentStatus = 21


@unique
class DTCSettingType(IntEnum):
    On = 1
    Off = 2


@unique
class UdsServices(IntEnum):
    DIAGNOSTIC_SESSION_CONTROL = 16
    ECU_RESET = 17
    CLEAR_DIAGNOSTIC_INFORMATION = 20
    READ_DTC_INFORMATION = 25
    READ_DATA_BY_ID = 34
    READ_MEMORY_BY_ADDR = 35
    WRITE_DATA_BY_ID = 46
    WRITE_MEMORY_BY_ADDR = 61
    SECURITY_ACCESS = 39
    IO_CONTROL = 47
    ROUTINE_CONTROL = 49
    DATA_UPLOAD = 53
    TRANSFER_DATA = 54
    TRANSFER_EXIT = 55
    TESTER_PRESENT = 62
    CONTROL_DTC_SETTING = 133


UDS_SUPPRESS_POS_RESP_MASK = 128

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/uds/datatypes/udstypes.pyc
