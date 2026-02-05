# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/adapter.py


class Adapter(object):
    port_class = None

    @classmethod
    def create_port(cls, *args, **kw):
        return cls.port_class(cls(*args, **kw))

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/adapter.pyc
