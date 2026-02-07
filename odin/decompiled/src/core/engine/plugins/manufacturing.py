# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/engine/plugins/manufacturing.py
import asyncio, logging
from aiohttp import web, ClientError
from aiohttp.web_exceptions import HTTPClientError
from odin.core.engine.handlers.message_handler import EngineMessageHandler
from odin.core.engine.security_context import safe_is_fused
from odin.core.orchestrator import runner, settings
log = logging.getLogger(__name__)

async def initialize(app: web.Application):
    try:
        message_handler = app.get("odin_server.message_handler")
    except Exception as exc:
        log.error("Could not get message handler: {} {}".format(type(exc), exc))
        return

    try:
        is_fused = await safe_is_fused()
        if is_fused:
            await orchestrator_fused_startup(message_handler)
        else:
            await orchestrator_unfused_startup(message_handler)
    except Exception:
        log.exception("Failed to initialize manufacturing services")


async def orchestrator_fused_startup(message_handler: EngineMessageHandler):
    try:
        auto_start_jobs_file = await settings.get_auto_start_jobs()
        if auto_start_jobs_file is not None:
            await runner.enable_broadcast_mode_safe(message_handler)
            log.info("Auto-starting Orchestrator (vehicle fused): {}".format(auto_start_jobs_file))
            context = {"message_handler": message_handler}
            await runner.start_orchestrator_fused(context=context, jobs_file=auto_start_jobs_file, auto_start=True)
    except HTTPClientError:
        log.exception("Failed to initialize manufacturing service (`orchestrator_fused_startup`)")


async def orchestrator_unfused_startup(message_handler: EngineMessageHandler):
    try:
        await runner.enable_broadcast_mode_safe(message_handler)
        auto_start_jobs_file = await settings.get_auto_start_jobs()
        if auto_start_jobs_file is not None:
            log.info("Auto-starting Orchestrator (vehicle unfused): {}".format(auto_start_jobs_file))
            context = {"message_handler": message_handler}
            await runner.start_orchestrator(context=context, jobs=auto_start_jobs_file, auto_start=True)
    except HTTPClientError:
        log.exception("Failed to initialize manufacturing service (`orchestrator_unfused_startup`)")


def includeme(app: web.Application):
    app.on_startup.append(initialize)

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/engine/plugins/manufacturing.pyc
