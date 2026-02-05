# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/can/exceptions.py
from odin.core.exception import OdinException

class MessageException(OdinException):
    return


class BusNotFound(MessageException):

    def __init__(self, bus_name):
        msg = "could not find bus: {0}".format(bus_name)
        super(BusNotFound, self).__init__(msg)


class DuplicateMessageFound(MessageException):

    def __init__(self, message_name, bus):
        msg = "duplicate message found: {0} bus: {1}".format(message_name, bus)
        super(DuplicateMessageFound, self).__init__(msg)


class DuplicateSignalFound(MessageException):

    def __init__(self, signal_name, bus):
        msg = "duplicate signal found: {0} bus: {1}".format(signal_name, bus)
        super(DuplicateSignalFound, self).__init__(msg)


class MessageNotFound(MessageException):

    def __init__(self, message_name):
        msg = "could not find message: {0}".format(message_name)
        super(MessageNotFound, self).__init__(msg)


class MessageOrSignalNotInWhitelist(MessageException):

    def __init__(self, message_or_signal_name, bus=None):
        msg = "message or signal {0} (bus={1}) is not in whitelist. Please refer to tools/odin/integration for detail as how to add signal/message to whitelist.".format(message_or_signal_name, bus)
        super(MessageOrSignalNotInWhitelist, self).__init__(msg)

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/can/exceptions.pyc
