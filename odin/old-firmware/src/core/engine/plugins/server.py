# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/engine/plugins/server.py
import asyncio, logging
from aiohttp import web
import odin_server
from odin.config import options
from odin.core.engine import messagebox
from odin.core.engine.handlers.logging_handler import EngineLoggingHandler
from odin.core.engine.handlers.message_handler import EngineMessageHandler
from odin.core.orchestrator import helpers

async def flush_outbox(app):
    handler = app["odin_server.message_handler"]
    try:
        while True:
            outgoing = await messagebox.outbox.get()
            await handler.broadcast((outgoing["message"]), product_id=(outgoing.get("product_id", "current")),
              ws_topic=(outgoing.get("ws_topic") or "commands"),
              hermes_topic=(outgoing.get("hermes_topic")),
              hermes_req_txid=(outgoing.get("hermes_req_txid", "")),
              hermes_status=(outgoing.get("hermes_status", 0)),
              command_type=(outgoing.get("command_type", 0)))

    except asyncio.CancelledError:
        pass


async def start_outbox_flusher(app):
    app["odin.outbox"] = app.loop.create_task(flush_outbox(app))


async def stop_outbox_flusher(app):
    app["odin.outbox"].cancel()
    await app["odin.outbox"]


def includeme(app: web.Application):
    permanent_send_topics = options["engine"]["permanent_send_topics"]
    message_handler = EngineMessageHandler(app,
      permanent_send_topics=permanent_send_topics)
    app["odin_server.message_handler"] = message_handler
    helpers._message_handler = message_handler
    logging_handler = EngineLoggingHandler(app)
    logging.getLogger("odin").addHandler(logging_handler)
    app.on_startup.append(start_outbox_flusher)
    app.on_cleanup.append(stop_outbox_flusher)
    odin_server.includeme(app)

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/engine/plugins/server.pyc
