# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/engine/handlers/logging_handler.py
import asyncio, logging
from odin_server.messages import LogRecorded

class EngineLoggingHandler(logging.Handler):
    DISABLED = 1000

    def __init__(self, app):
        super().__init__()
        self.app = app
        self.setLevel(self.DISABLED)

    def emit(self, record):
        log_entry = self.format(record)
        msg_handler = self.app["odin_server.message_handler"]
        try:
            asyncio.ensure_future(msg_handler.broadcast_muted((LogRecorded(log_entry)), product_id="current",
              ws_topic="logging"))
        except asyncio.CancelledError:
            pass

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/engine/handlers/logging_handler.pyc
