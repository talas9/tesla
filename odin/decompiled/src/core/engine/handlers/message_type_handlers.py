# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/engine/handlers/message_type_handlers.py
import asyncio, datetime, functools, logging, os, psutil
from typing import Dict, Optional
from odin.core import cid
from odin.core.engine.handlers import utils, commands
from odin.core.engine.plugins import history
from odin.core.utils.profiletools import Profiler
from odin.testing.execution import ExecutionLogger
from odin_server.messages import RequestFinished, RequestFailed, RequestCancelled
from odin_server.hermes import CommandType
message_type_registry = {}
blocking_message_types = []
log = logging.getLogger(__name__)
CURRENT_PROCESS = psutil.Process(os.getpid())

class TaskInfo:

    def __init__(self, request: Dict, profiler: Profiler, broadcast_options: Dict, start_time: Optional[datetime.datetime]=None):
        self.request = request
        self.profiler = profiler
        self.broadcast_options = broadcast_options
        self.start_time = start_time

    def request_id(self) -> Optional[str]:
        return self.request.get("request_id")

    def task_group(self) -> Optional[str]:
        return self.request.get("task_group")

    def to_dict(self) -> dict:
        task_dict = {"task_group": (self.task_group())}
        command = self.request.get("command")
        args = self.request.get("args")
        if command == "execute":
            if isinstance(args, dict):
                task_dict["task_name"] = args.get("name")
        return task_dict

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False
        else:
            return self.request_id() is not None and self.request_id() == other.request_id()


def message_type_handler(message_type: str='', blocking: bool=False) -> callable:

    def wrapper(func):
        message_type_name = message_type or func.__name__

        @functools.wraps(func)
        def caller(*args, **kw):
            log.info("calling message type handler: {}".format(message_type_name))
            return func(*args, **kw)

        message_type_registry[message_type_name] = caller
        if blocking:
            blocking_message_types.append(message_type_name)
        return caller

    return wrapper


@message_type_handler(blocking=True)
async def batch_command(message_handler, request: dict, broadcast_options: dict, request_context: dict, remote_request: bool) -> asyncio.Task:
    batch_commands = request["commands"]
    batch_tasks = [TaskInfo(payload, create_profiler(payload), broadcast_options) for payload in batch_commands]
    message_handler.pending_tasks.extend(batch_tasks)

    async def run_batch_commands():
        for task_info in batch_tasks:
            try:
                task = await start_task(message_handler, task_info, request_context, remote_request)
                await task
            except Exception as e:
                log.exception("Error executing task in batch: {}".format(e))

        all_request_ids = [t.request_id() for t in batch_tasks]
        payload = {"request_ids": all_request_ids}
        batch_request_finished = RequestFinished(request["request_id"], payload)
        asyncio.ensure_future((message_handler.broadcast)(batch_request_finished, **broadcast_options))

    return asyncio.ensure_future(run_batch_commands())


@message_type_handler()
async def command(message_handler, request: dict, broadcast_options: dict, request_context: dict, remote_request: bool) -> asyncio.Task:
    profiler = create_profiler(request)
    task_info = TaskInfo(request, profiler,
      broadcast_options,
      start_time=(datetime.datetime.now()))
    message_handler.pending_tasks.append(task_info)
    task = await start_task(message_handler, task_info, request_context, remote_request)
    return task


def create_profiler(payload: dict):
    request_id = payload.get("request_id")
    profiler_options = payload.get("profiler", {})
    if profiler_options.get("enabled"):
        profiler = Profiler(request_id=request_id, **profiler_options)
        profiler.start()
    else:
        profiler = None
    return profiler


def on_complete_task(message_handler, task: asyncio.Task):
    exc = task.exception()
    message_handler.refresh_lock_if_necessary()
    task_info = message_handler.running_tasks.pop(task)
    request, profiler, broadcast_options, start_time = (
     task_info.request,
     task_info.profiler,
     task_info.broadcast_options,
     task_info.start_time)
    msg_args = [
     request["request_id"]]
    msg_payload = None
    time_now = datetime.datetime.now()
    try:
        if exc is not None:
            msg_type = RequestFailed
            msg_args.append(exc)
            broadcast_options["command_type"] = CommandType.CommandTypeErrorResponse
        elif task.cancelled():
            msg_type = RequestCancelled
            broadcast_options["command_type"] = CommandType.CommandTypeErrorResponse
        else:
            msg_type = RequestFinished
            msg_payload = task.result()
            task_duration = (time_now - start_time).total_seconds()
            ExecutionLogger.add_data((request["request_id"]), task_started_at=(str(start_time)))
            ExecutionLogger.add_data((request["request_id"]), task_duration=task_duration)
            ExecutionLogger.add_data((request["request_id"]), current_rss=(CURRENT_PROCESS.memory_info().rss))
        if isinstance(msg_payload, dict):
            msg_payload.update(message_handler.performance_data(request["request_id"]))
    finally:
        ExecutionLogger.clean_up(request["request_id"])

    if message_handler.app.get("odin.core.engine.plugins.history"):
        if task_info.request.get("command") in ('execute', 'evaluate'):
            name = task_info.request.get("args", {}).get("name", "UNKNOWN")
            if msg_type == RequestFinished:
                task_results = task.result()
                connectors = task_results.get("debug", {}).get("connectors", [])
                status = "PASS" if task_results.get("results", {}).get("exit_code", -1) == 0 else "FAIL"
            else:
                connectors = []
                status = "FAIL"
            history.write_to_history({'test':name, 
             'date':task_info.start_time.strftime("%m/%d"), 
             'started':task_info.start_time.strftime("%H:%M:%S"), 
             'finished':time_now.strftime("%H:%M:%S"), 
             'status':status, 
             'connectors':connectors})
    if profiler:
        profiler.stop()
        if profiler.enabled:
            if type(msg_payload) is dict:
                debug = msg_payload.setdefault("debug", {})
                debug["profile"] = profiler.dump()
    if msg_payload is not None:
        msg_args.append(msg_payload)
    msg = msg_type(*msg_args)
    cmd = (message_handler.broadcast)(msg, **broadcast_options)
    asyncio.ensure_future(cmd)


def request_is_blocking(payload: dict) -> bool:
    blocking_task_group = payload.get("task_group") != "*"
    message_type_blocking = payload.get("message_type") in blocking_message_types
    return blocking_task_group and (message_type_blocking or commands.is_blocking_command(payload))


async def start_task(message_handler, task_info: TaskInfo, context: dict=None, remote_request: bool=False) -> asyncio.Task:
    cmd = utils.run_from_payload((task_info.request),
      context=context,
      handler=message_handler,
      remote_request=remote_request)
    task_info.start_time = datetime.datetime.now()
    task = asyncio.ensure_future(cmd)
    message_handler.pending_tasks.remove(task_info)
    message_handler.running_tasks[task] = task_info
    task.add_done_callback(functools.partial(on_complete_task, message_handler))
    if message_handler.app.get("odin.core.engine.plugins.history"):
        if task_info.request.get("command") in ('execute', 'evaluate'):
            name = task_info.request.get("args", {}).get("name", "UNKNOWN")
            history.write_to_history({'test':name, 
             'date':task_info.start_time.strftime("%m/%d"), 
             'started':task_info.start_time.strftime("%H:%M:%S"), 
             'finished':None, 
             'status':"RUNNING", 
             'connectors':[]})
    return task

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/engine/handlers/message_type_handlers.pyc
