# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/engine/unix_socket_server.py
import asyncio, ast, logging, os
from typing import Coroutine
from odin.core.engine.handlers.commands import unix_command_registry
log = logging.getLogger(__name__)

class UnixSocketServer(asyncio.Protocol):
    SOCKET_FILEPATH = "/tmp/odin.sock"

    def __init__(self):
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def data_received(self, data: bytes):
        log.debug("Received data via unix socket: {}".format(data))
        try:
            self.run_from_payload(data)
        finally:
            self.transport.close()

    @staticmethod
    def format_data(data: bytes) -> dict:
        try:
            return ast.literal_eval(data.decode())
        except (SyntaxError, AttributeError):
            return {}

    @staticmethod
    def run_from_payload(data: bytes):
        request = UnixSocketServer.format_data(data)
        caller = unix_command_registry.get(request.get("command"))
        if caller:
            command_coroutine = caller(**request.get("args", {}))
            asyncio.ensure_future(command_coroutine,
              loop=(asyncio.get_event_loop()))

    @staticmethod
    async def start() -> Coroutine:
        loop = asyncio.get_event_loop()
        server = await loop.create_unix_server(UnixSocketServer, UnixSocketServer.SOCKET_FILEPATH)
        os.chmod(UnixSocketServer.SOCKET_FILEPATH, 511)
        return server

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/engine/unix_socket_server.pyc
