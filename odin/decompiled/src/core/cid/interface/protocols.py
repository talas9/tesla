# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/cid/interface/protocols.py
import asyncio, locale, logging
log = logging.getLogger(__name__)

class PartialOutputSubprocessProtocol(asyncio.SubprocessProtocol):

    def __init__(self):
        super().__init__()
        self.stdout = bytes()
        self.stderr = bytes()
        self.done = asyncio.Future()

    def get_stderr(self) -> str:
        return self.stderr.decode(locale.getpreferredencoding(False))

    def get_stdout(self) -> str:
        return self.stdout.decode(locale.getpreferredencoding(False))

    def pipe_data_received(self, fd: int, data: bytes):
        log.debug("{}".format(data.decode(locale.getpreferredencoding(False))))
        if fd == 1:
            self.stdout += data
        elif fd == 2:
            self.stderr += data

    def process_exited(self):
        if not self.done.done():
            self.done.set_result(True)

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/cid/interface/protocols.pyc
