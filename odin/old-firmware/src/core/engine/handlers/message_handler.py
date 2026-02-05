# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/engine/handlers/message_handler.py
import asyncio, copy, datetime, json, logging, uuid, copy
from typing import Dict, Optional, Union
from aiohttp.web import HTTPConflict, HTTPForbidden, HTTPUnauthorized
from dateutil.parser import parse
from architect.workflows.encoder import DatatypeEncoder
import odin
from odin.config import options
from odin.core import cid
from odin.core.utils import arch
from odin.core.utils.dispatch import Dispatch
from odin.core.utils.options import nested_get
from odin.testing.execution import ExecutionLogger
from odin_server import utils as server_utils
from odin_server.hermes import CommandType, CommandTypeResponseMap, Status as HermesStatus
from odin_server.message_handler import MessageHandler
from odin_server.messages import RequestReceived, RequestFinished, RequestFailed
from odin.core.engine import messagebox
from odin.core.engine.handlers import utils
from odin.core.engine.hermes import messagebox as hermes_messagebox
from odin.core.engine.handlers.message_type_handlers import TaskInfo, message_type_registry, request_is_blocking
from odin.core.engine.handlers.task_group_lock import TaskGroupLock
from tesla_messages.schema import Message
log = logging.getLogger(__name__)
TOKEN_KEYS = ["token", "tokenv2", "tbx_token"]

class EngineMessageHandler(MessageHandler):

    def __init__(self, app, default_response_topic='', permanent_send_topics=None):
        super().__init__(app=app,
          default_response_topic=default_response_topic,
          permanent_send_topics=(permanent_send_topics or set()))
        if arch.is_tegra():
            self.MAX_MSG_RESPONSE_SIZE = 160000
        else:
            self.MAX_MSG_RESPONSE_SIZE = 199000
        self.running_tasks = {}
        self.pending_tasks = []
        self.task_group_lock = TaskGroupLock()

    def _block_request(self, request: dict, broadcast_options: dict) -> asyncio.Task:
        log.info("Sending ODIN busy response")
        odin_busy = RequestFailed(request_id=(request["request_id"]),
          error=HTTPConflict(reason="ODIN is busy executing another task"),
          tasks=(self.describe_current_tasks()),
          active_lock=(self.locked_task_group()),
          hermes_status=(HermesStatus.ApplicationUnavailable))
        odin_busy_options = {**broadcast_options, **{"hermes_status": (HermesStatus.ApplicationUnavailable)}}
        task = asyncio.ensure_future((self.broadcast)(odin_busy, **odin_busy_options))
        return task

    async def broadcast_request_received(self, request: Dict, broadcast_options: Dict):
        msg = RequestReceived(request["request_id"], request)
        msg["hermes_status"] = HermesStatus.Acknowledgement
        ExecutionLogger.add_data((request["request_id"]), request_received_at=(str(datetime.datetime.now())))
        broadcast_msg = copy.deepcopy(msg)
        broadcast_msg = self.sanitize_tokens(broadcast_msg, TOKEN_KEYS)
        await (self.broadcast)(broadcast_msg, **{**broadcast_options, **{"hermes_status": (HermesStatus.Acknowledgement)}})

    def calculate_command_type(self, command_type: int) -> int:
        return CommandTypeResponseMap.get(command_type, 0)

    async def cancel_task(self, task_info: TaskInfo) -> bool:
        if task_info in self.pending_tasks:
            self.pending_tasks.remove(task_info)
            return True
        else:
            for task, running_task_info in self.running_tasks.items():
                if running_task_info == task_info:
                    return task.cancel()

            return False

    async def _create_task_from_request(self, request: Dict, broadcast_options: Dict, message: Optional[Dict]=None, remote_request: bool=False):
        await self.broadcast_request_received(request, broadcast_options)
        if message:
            request_context = {'topic':message.get("topic"),  'response_topic':message.get("response_topic"), 
             'command_type':message.get("command_type"), 
             'req_txid':message.get("txid")}
        else:
            request_context = {}
        command_type = broadcast_options.get("command_type", None)
        if command_type:
            request["command_type"] = command_type
        self._preprocess_request(request)
        if self._should_block_request(request):
            return self._block_request(request, broadcast_options)
        message_type = request["message_type"]
        handler = message_type_registry.get(message_type)
        if handler:
            return await handler(self, request, broadcast_options, request_context, remote_request)
        else:
            event = messagebox.inbox.get(message_type)
            if event is not None:
                event.set(message)
                return
            log.error("Invalid request type: %s", message_type)
            msg = RequestFailed(request_id=(request["request_id"]),
              error=HTTPUnauthorized(reason=("Invalid request type: {}".format(message_type))))
            await (self.broadcast)(msg, **broadcast_options)
            return

    def _current_task_group(self) -> Optional[str]:
        locked_task_group = self.locked_task_group()
        if locked_task_group:
            return locked_task_group
        else:
            return self._running_task_group()

    async def get_data_from_token(self, token: str) -> dict:
        if self.policy:
            if not token:
                raise HTTPUnauthorized(reason="No token provided")
            else:
                data = await self.policy.decode_from_token(token)
                await self.validate_data_from_token(data)
                principals = data.get("principals", []).copy()
                user = data.get("user")
                return {'principals':principals,  'user':user}
        return {}

    def describe_current_tasks(self) -> dict:
        running_tasks = [i for i in self.running_tasks.values()]
        pending_tasks = self.pending_tasks

        def task_info_to_dict(task_info: TaskInfo, is_running: bool) -> dict:
            task_dict = task_info.to_dict()
            if is_running:
                task_dict["status"] = "running"
                current_time = datetime.datetime.now()
                seconds_running = (current_time - task_info.start_time).total_seconds()
                task_dict["seconds_running"] = seconds_running
            else:
                task_dict["status"] = "pending"
            return task_dict

        tasks_dict = {}
        for task in running_tasks:
            tasks_dict[task.request_id()] = task_info_to_dict(task, True)

        for task in pending_tasks:
            tasks_dict[task.request_id()] = task_info_to_dict(task, False)

        return tasks_dict

    async def enable_broadcast_mode(self):
        from odin.platforms import get_bcast_topic_infix
        bcast_topic_infix = get_bcast_topic_infix()
        if bcast_topic_infix is None:
            return
        bcast_topic = "manufacturing_service.{}.task.complete.odin.{}"
        vin = await cid.interface.get_vin()
        topic = bcast_topic.format(bcast_topic_infix, vin)
        if topic not in self.permanent_send_topics:
            self.permanent_send_topics.add(topic)
            log.info("Broadcasting all responses to topic: {}".format(topic))

    async def handle_hermes_message(self, message: dict):
        topic = message.get("topic")
        status = message.get("status")
        hermes_req_txid = message.get("txid")
        if message["message_type"] == Message.Message().FlatbuffersCommand:
            msg = message.get("payload")
            command_type = message.get("command_type")
            try:
                payload = json.loads(msg)
            except (json.JSONDecodeError, TypeError):
                payload = msg
                request_id = message.get("txid")
            else:
                request_id = payload.get("request_id")
            log.info("received hermes message, request_id: %s, topic: %s, status: %s, message: %s, hermes_req_txid: %s", request_id, topic, status, server_utils.safe_log_hermes_message(copy.deepcopy(message)), hermes_req_txid)
            topic_dispatch = hermes_messagebox.topic_event_queue.get(topic, None)
            if isinstance(topic_dispatch, Dispatch):
                topic_dispatch.set(message)
            if status == HermesStatus.ServerReceived:
                log.debug("Hermes received message: {}".format(message))
            elif status == HermesStatus.Success:
                log.info("Received success message: {}".format(message))
            elif status in HermesStatus.__members__.values():
                log.warning("Received message with status {}: {}".format(HermesStatus(status).name, message))
            else:
                log.debug("Received message: {}".format(message))
                if topic:
                    _, product_id, product_topic = topic.split(".")
                    if product_topic == "odin":
                        if isinstance(payload, dict):
                            return await self.handle_request(payload,
                              product_id=product_id,
                              response_topic=(message.get("response_topic")),
                              hermes_req_txid=hermes_req_txid,
                              command_type=command_type,
                              message=message,
                              remote_request=True)
                        else:
                            return await self.handle_message(message)
                    else:
                        log.debug("Ignoring message: {}".format(message))
                else:
                    log.debug("Ignoring message: {}".format(message))
        elif topic:
            pass
        _, product_id, product_topic = topic.split(".")
        if product_topic == "odin":
            return await self.handle_message(message)

    async def handle_message(self, message: dict):
        message_type = str(message.get("message_type", "unknown"))
        event = messagebox.inbox.get(message_type)
        if event is not None:
            log.info("Listener found for message type: %s, dispatching.", message_type)
            event.set(message)
        else:
            log.info("No listeners for message type %s, ignoring message.", message_type)

    async def handle_request(self, request: dict, product_id: str='', response_topic: str='', hermes_req_txid: str='', command_type: CommandType=0, message: Union[(dict, None)]=None, remote_request: bool=False) -> asyncio.Future:
        request_id = request.setdefault("request_id", str(uuid.uuid4()))
        message_type = request.setdefault("message_type", "command")
        broadcast_permanent_topics = request.setdefault("broadcast_permanent_topics", True)
        log.info("received request, request_id: %s, product_id: %s, message_type: %s, response_topic: %s, request: %s, hermes_req_txid: %s command_type: %s", request_id, product_id, message_type, response_topic, server_utils.safe_log_request(copy.deepcopy(request)), hermes_req_txid, command_type)
        broadcast_options = {'product_id':"current", 
         'ws_topic':"commands", 
         'hermes_topic':response_topic, 
         'hermes_req_txid':hermes_req_txid, 
         'command_type':self.calculate_command_type(command_type), 
         'broadcast_permanent_topics':broadcast_permanent_topics}
        return await self._create_task_from_request(request,
          broadcast_options,
          message=(message or request),
          remote_request=remote_request)

    def _has_task_in_locked_task_group(self) -> bool:
        locked_task_group = self.task_group_lock.get_task_group(check_if_expired=False)
        return locked_task_group is not None and self._running_task_group() == locked_task_group

    def locked_task_group(self) -> Optional[str]:
        self.refresh_lock_if_necessary()
        return self.task_group_lock.get_task_group()

    def has_blocking_task(self) -> bool:
        all_task_infos = list(self.running_tasks.values()) + self.pending_tasks
        for task_info in all_task_infos:
            if request_is_blocking(task_info.request):
                return True

        return False

    async def is_factory_mode_on(self) -> bool:
        product_id = nested_get(options, "mock.product_id")
        if not product_id:
            return await cid.interface.factory_mode()
        else:
            return False

    def json_dumps(self, obj: object, to_hermes: bool=False) -> str:
        if to_hermes:
            if isinstance(obj, RequestFinished):
                response = json.dumps(obj=(obj.get("response")), cls=DatatypeEncoder)
                response_size = self._get_len(response)
                if response_size > self.MAX_MSG_RESPONSE_SIZE:
                    log.debug(f"Response size is {response_size} > {self.MAX_MSG_RESPONSE_SIZE} bytes so compressing")
                    compressed_response = self._compress_response(response)
                    obj["response"] = compressed_response
                    compressed_response_size = self._get_len(compressed_response.get("data"))
                    if compressed_response_size > self.MAX_MSG_RESPONSE_SIZE:
                        log.error(f"Compressed response too large to send {compressed_response_size} > {self.MAX_MSG_RESPONSE_SIZE} bytes. Response replaced with error message")
                        obj["response"] = {"error": f"Compressed response too large to send: {compressed_response_size} > {self.MAX_MSG_RESPONSE_SIZE} bytes"}
        return json.dumps(obj=obj, cls=DatatypeEncoder)

    @staticmethod
    def _get_len(the_str: str) -> int:
        return len(the_str.encode("utf-8"))

    @staticmethod
    def _compress_response(response: str) -> dict:
        return {'data':utils.compress_string(response), 
         'compressed':True}

    def performance_data(self, request_id) -> dict:
        return {"performance": (ExecutionLogger.pop_data(request_id) if request_id else None)}

    def _preprocess_request(self, request: dict):
        if "task_group" not in request:
            allow_concurrent = request.get("allow_concurrent") is True
            request["task_group"] = "*" if allow_concurrent else None

    def refresh_lock_if_necessary(self):
        if self._has_task_in_locked_task_group():
            self.task_group_lock.refresh()

    def _running_task_group(self) -> Optional[str]:
        all_task_infos = list(self.running_tasks.values()) + self.pending_tasks
        for task_info in all_task_infos:
            if request_is_blocking(task_info.request):
                return task_info.task_group()

        return

    def set_task_group_lock(self, task_group: str, timeout: float):
        locked_task_group = self.locked_task_group()
        if locked_task_group:
            if locked_task_group != task_group:
                raise HTTPConflict(reason=("Lock already in place for task group: {}".format(locked_task_group)))
        if self.has_blocking_task():
            if self._running_task_group() != task_group:
                raise HTTPConflict(reason="Different task group is currently running")
        self.task_group_lock.lock(task_group, timeout)

    def _should_block_request(self, request: dict) -> bool:
        if not request_is_blocking(request):
            return False
        else:
            locked_task_group = self.locked_task_group()
            request_task_group = request.get("task_group")
            if locked_task_group:
                return locked_task_group != request_task_group
            if self.has_blocking_task():
                running_task_group = self._running_task_group()
                return running_task_group is None or request_task_group != running_task_group
            return False

    async def test_connection(self, product_id: str) -> bool:
        if product_id == "current":
            return True
        else:
            try:
                my_id = await cid.interface.get_vin()
            except Exception:
                log.error("Unable to retrieve product ID from CID/ICE.")
                raise RuntimeError("Failed to retrieve product ID.")
            else:
                if my_id != product_id:
                    raise AssertionError("Requested product ID does not match.")
            return True

    def clear_task_group_lock(self, task_group: str):
        locked_task_group = self.locked_task_group()
        if locked_task_group:
            if task_group != "*":
                if locked_task_group != task_group:
                    raise HTTPConflict(reason=("Task group `{}` does not match the current locked task group `{}`".format(task_group, locked_task_group)))
            self.task_group_lock.unlock()

    def sanitize_tokens(self, data: Message, remove_from_payload: list) -> Message:
        for key in remove_from_payload:
            try:
                del data["request_payload"][key]
            except KeyError:
                pass

        return data

    async def validate_data_from_token(self, data: dict):
        expires_at = data.get("expires_at")
        if datetime.datetime.now() > parse(expires_at):
            raise HTTPUnauthorized(reason="Bearer token has expired.")
        product_id = data.get("product_id")
        try:
            await self.test_connection(product_id)
        except RuntimeError as exc:
            raise HTTPForbidden(reason=(repr(exc)))

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/engine/handlers/message_handler.pyc
