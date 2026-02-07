# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/gateway/socket.py
import asyncio, asyncio_extras, logging, socket, typing
from typing import Optional
from odin.config import options
log = logging.getLogger(__name__)

class GatewaySocketConnectionTimeout(asyncio.TimeoutError):
    return


class GatewaySocketManager(object):

    def __init__(self, family: int, type: int, connection_params: tuple, reader_coroutine: typing.Union[(callable, None)]):
        self.family = family
        self.type = type
        self.connection_params = connection_params
        self.socket = None
        self.connecting_event = asyncio.Event()
        self.ref_count = 0
        self.reader_coroutine = reader_coroutine
        self.reader_task = None
        self.keep_alive_settings = options.get("core", {}).get("gateway", {}).get("keep_alive", {})

    def __del__(self):
        if self.reader_task:
            if not self.reader_task.cancelled():
                self.reader_task.cancel()

    def reset_manager(self):
        log.debug("Reset Gateway Socket Manager")
        self.connecting_event.clear()
        if self.reader_task:
            self.reader_task.cancel()
            self.reader_task = None
        if self.socket:
            self.socket.close()
            self.socket = None

    async def connect_socket(self, family: int=None, type: int=None, connection_params: tuple=None) -> socket.socket:
        family = family or self.family
        type = type or self.type
        connection_params = connection_params or self.connection_params
        if not self.socket:
            self.socket = socket.socket(family, type)
            self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            if hasattr(socket, "SO_REUSEPORT"):
                self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.setblocking(False)
            self.configure_keepalive()
            loop = asyncio.get_event_loop()
            try:
                await loop.sock_connect(self.socket, connection_params)
            except Exception as err:
                log.debug("Failed to connect socket: {}".format(repr(err)))
                self.socket = None
                raise

            log.debug("Gateway Socket was connected.")
            if self.reader_coroutine:
                self.reader_task = asyncio.ensure_future(self.reader_coroutine())
                self.reader_task.add_done_callback(self.reader_task_done)
            self.connecting_event.set()
        else:
            await self.connecting_event.wait()
        return self.socket

    def configure_keepalive(self):
        try:
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, self.keep_alive_settings.get("idle", 2))
            self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, self.keep_alive_settings.get("interval", 1))
            self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, self.keep_alive_settings.get("count", 1))
        except AttributeError:
            log.debug("Socket keep-alive not set")
        else:
            log.info("Keep-alive set")

    def reader_task_done(self, task: asyncio.Task):
        try:
            exc = task.exception()
        except asyncio.CancelledError:
            log.error("Socket reader_task_done future was cancelled")
        else:
            if exc:
                log.error("Socket reader_task_done: {}".format(exc))
                self.reset_manager()

    async def get_socket(self, timeout: float=0) -> Optional[socket.socket]:
        try:
            return await asyncio.wait_for((self.connect_socket(self.family, self.type, self.connection_params)),
              timeout=(timeout if timeout else None))
        except asyncio.TimeoutError:
            raise GatewaySocketConnectionTimeout("Timed out to open socket to gateway")

    @asyncio_extras.async_contextmanager
    async def open_socket(self, func_name: str, timeout: float=0) -> typing.AsyncGenerator[(socket.socket, None)]:
        socket = await self.get_socket(timeout)
        try:
            yield socket
        except (asyncio.CancelledError, asyncio.TimeoutError) as exc:
            error_type = "got cancelled" if isinstance(exc, asyncio.CancelledError) else "timed out"
            log.debug("Yield socket on socket {}: {}".format(func_name, error_type))
            raise
        except Exception as exc:
            log.error("Failed on socket {}: {} {}".format(func_name, type(exc), exc))
            self.reset_manager()
            raise

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/gateway/socket.pyc
