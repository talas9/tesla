# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/testing/execution/execution_logger.py


class ExecutionLogger(object):
    execution_logs = {}

    @classmethod
    def add_data(cls, guid: str, **kwargs):
        if guid:
            cls.execution_logs.setdefault(guid, {}).update(kwargs)

    @classmethod
    def pop_data(cls, guid) -> dict:
        try:
            return cls.execution_logs.pop(guid)
        except KeyError:
            pass

    @classmethod
    def clean_up(cls, guid) -> None:
        try:
            cls.execution_logs.pop(guid)
        except KeyError:
            pass

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/testing/execution/execution_logger.pyc
