# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/engine/handlers/reporting.py
import asyncio, datetime
from typing import Optional
from odin_server.messages import RequestFinished, RequestFailed, RequestCancelled
from odin_server.hermes import CommandType
from odin.core.engine.plugins import history
from odin.core.engine.handlers.message_handler import EngineMessageHandler

def check_successful_results(result: dict) -> bool:
    return isinstance(result, dict) and result.get("results", {}).get("exit_code", -1) == 0


def report_finish(message_handler: Optional[EngineMessageHandler], execution_options: dict, request_id: str, results: Optional[dict]=None, exc: Exception=None):
    if not message_handler:
        return
    broadcast_options = _get_reporting_broadcast_options(execution_options)
    msg_args = [
     request_id]
    if isinstance(exc, asyncio.CancelledError):
        msg_type = RequestCancelled
        broadcast_options["command_type"] = CommandType.CommandTypeErrorResponse
    elif exc is not None:
        msg_type = RequestFailed
        broadcast_options["command_type"] = CommandType.CommandTypeErrorResponse
        msg_args.append(exc)
    else:
        msg_type = RequestFinished
    if results is not None:
        msg_args.append(results)
    msg = msg_type(*msg_args)
    cmd = (message_handler.broadcast)(msg, **broadcast_options)
    asyncio.ensure_future(cmd)


def report_history(message_handler: Optional[EngineMessageHandler], test: str, started_time: datetime.datetime, finished_time: Optional[datetime.datetime], status: str, connectors: list):
    if message_handler:
        if message_handler.app.get("odin.core.engine.plugins.history"):
            history.write_to_history({'test':test, 
             'date':started_time.strftime("%m/%d"), 
             'started':started_time.strftime("%H:%M:%S"), 
             'finished':finished_time.strftime("%H:%M:%S") if finished_time else None, 
             'status':status, 
             'connectors':connectors})


async def report_start(message_handler: Optional[EngineMessageHandler], execution_options: dict, name: str, request_id: str=None):
    if not message_handler:
        return
    request = {'message_type':"command",  'args':{"name": name}, 
     'type':"command_request", 
     'command':"execute", 
     'request_id':request_id}
    broadcast_options = _get_reporting_broadcast_options(execution_options)
    broadcast_options["command_type"] = execution_options.get("command_type")
    await message_handler.broadcast_request_received(request, broadcast_options)


def _get_reporting_broadcast_options(execution_options: dict) -> dict:
    return {'product_id':"current", 
     'ws_topic':"commands", 
     'hermes_topic':execution_options.get("response_topic"), 
     'hermes_req_txid':execution_options.get("req_txid") or ""}

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/engine/handlers/reporting.pyc
