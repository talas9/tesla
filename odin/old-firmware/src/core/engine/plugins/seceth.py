# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/engine/plugins/seceth.py
import apis, asyncio
from aiohttp import web
import json, logging, odin
from odin.core.utils import arch
from ..token import validate_and_decode_message
from ...cid.interface import exec_command, save_data
log = logging.getLogger(__name__)

class SecethPingSingleton(object):
    PING_INTERVAL = 30
    COMMAND = ["/sbin/seceth", "unlock"]
    TEGRA_UNLOCK_FILE = "/var/run/odin_unlock_seceth"
    n_references = 0
    ping_task = None

    @classmethod
    def increment(cls):
        cls.n_references += 1
        if cls.n_references == 1:
            cls.start_task()

    @classmethod
    def start_task(cls):
        cls.ping_task = asyncio.ensure_future(cls.periodic_ping())

    @classmethod
    async def periodic_ping(cls):
        while True:
            cls.run_ping()
            await asyncio.sleep(cls.PING_INTERVAL)

    @classmethod
    def run_ping(cls):
        log.debug("*** Attempt Unlocking Seceth ***")
        if arch.is_tegra():
            callback = asyncio.ensure_future(save_data(cls.TEGRA_UNLOCK_FILE, "90"))
        else:
            callback = asyncio.ensure_future(exec_command((cls.COMMAND), user="root"))
        callback.add_done_callback(cls.ping_task_done)

    @classmethod
    def ping_task_done(self, task: asyncio.Task):
        try:
            exc = task.exception()
        except asyncio.CancelledError:
            log.error("ping_task_done future was cancelled")
        else:
            if exc:
                log.error("ping_task_done: {}".format(exc))

    @classmethod
    def decrement(cls):
        cls.n_references = max(cls.n_references - 1, 0)
        if cls.n_references == 0:
            if cls.ping_task:
                cls.ping_task.cancel()


def make_handler():

    async def handler(request):
        ws = await prepare_ws(request)
        await count_authenticated_reference(ws)
        return ws

    return handler


async def prepare_ws(request):
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    return ws


async def count_authenticated_reference(ws):
    got_authenticated_connection = False
    try:
        try:
            async for msg in ws:
                log.info("Received unlock request")
                if not got_authenticated_connection:
                    if msg.type == web.MsgType.TEXT:
                        await check_token(msg)
                        got_authenticated_connection = True
                        SecethPingSingleton.increment()
                if not got_authenticated_connection:
                    log.debug("Unknown/Malformed Seceth Unlock request. Request={}".format(msg))

        except Exception:
            log.exception("Seceth Unlock encountered exception")
            raise

    finally:
        if got_authenticated_connection:
            SecethPingSingleton.decrement()


async def check_token(msg):
    data = json.loads(msg.data)
    await validate_and_decode_message(data)


def install_seceth_route():
    return apis.route("/ws_unlock_seceth")(make_handler())


def includeme(app):
    install_seceth_route()

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/engine/plugins/seceth.pyc
