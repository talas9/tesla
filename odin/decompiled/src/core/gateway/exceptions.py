# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/gateway/exceptions.py
from ..exception import OdinException

class GatewayException(OdinException):
    return


class InvalidBusID(GatewayException):

    def __init__(self, bus_id):
        msg = "invalid bus id: {0}".format(bus_id)
        super(InvalidBusID, self).__init__(msg)


class InvalidPayloadSize(GatewayException):

    def __init__(self, size):
        msg = "invalid payload size: {0}".format(size)
        super(InvalidPayloadSize, self).__init__(msg)


class MessageIDOutOfRange(GatewayException):

    def __init__(self, message_id):
        msg = "message id is out of range: {0:x}".format(message_id)
        super(MessageIDOutOfRange, self).__init__(msg)

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/gateway/exceptions.pyc
