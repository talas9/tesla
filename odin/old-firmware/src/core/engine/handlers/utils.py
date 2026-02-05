# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/engine/handlers/utils.py
import asyncio, base64, copy, datetime, functools, logging, os, re, traceback, uuid, zlib
from typing import List, Optional
from aiohttp.web import HTTPNotFound
from architect.core.exceptions import StopNetwork
from architect.core.network import Network
from architect.core.node import Node
from architect.workflows.visitor import NodeVisitor
from architect.ports.client import ClientPort
import odin
from odin import platforms
from odin.core.cid.interface import is_fused
from odin.core.engine.handlers import commands, reporting
from odin.core.engine.handlers.message_handler import EngineMessageHandler
from odin.core.engine import security
from odin.core.engine import safety
from odin.core.engine import token
from odin.core.engine.security_context import make_security_context
from odin.nodes.misc import ReferencedValidationSubnetwork
from odin.nodes.comments import TaskInfo
from odin.platforms import get_network_dirs
from odin.testing.execution import ExecutionLogger
log = logging.getLogger(__name__)

class Timer(object):

    def __enter__(self):
        self.start = datetime.datetime.now()
        self.end = None
        return self

    def __exit__(self, *args, **kwargs):
        self.end = datetime.datetime.now()
        self.elapsed = (self.end - self.start).total_seconds()


def compress_string(data: str) -> str:
    return base64.b64encode(zlib.compress(data.encode())).decode("utf-8")


def convert_set_to_list(dictionary: dict):
    for key, value in dictionary.items():
        if isinstance(value, dict):
            convert_set_to_list(value)
        else:
            if isinstance(value, set):
                dictionary[key] = list(dictionary[key])


async def check_network_compatible(name: str) -> (str, bool):
    try:
        network = await load_network(name)
        validation_nodes = get_nodes_from_network(network, ReferencedValidationSubnetwork)
        is_compatible = await check_validation_nodes_pass(validation_nodes)
        return (
         name, is_compatible)
    except asyncio.CancelledError:
        raise
    except Exception:
        return (
         name, False)


async def check_validation_nodes_pass(validation_nodes: List[ReferencedValidationSubnetwork]) -> bool:
    tasks = [run_validation_node(n) for n in validation_nodes]
    is_compatible = all(await (asyncio.gather)(*tasks))
    return is_compatible


async def filter_tasks_for_compatibility(platform_tasks: List[str]) -> List[str]:
    compatibility_checks = [check_network_compatible(task_name) for task_name in platform_tasks]
    compatible_networks = await (asyncio.gather)(*compatibility_checks)
    return [name for name, passed in compatible_networks if passed]


def get_iris_data(name: str, exit_code: Optional[int]=None) -> dict:
    iris_data = odin.core.iris_data.get(name, {})
    all_connectors = iris_data.get("connectors", [])
    exit_code_to_connectors = iris_data.get("exit_codes", {})
    if exit_code is None or str(exit_code) not in exit_code_to_connectors:
        return {"connectors": all_connectors}
    else:
        exit_code_connectors = exit_code_to_connectors[str(exit_code)]
        return {"connectors": exit_code_connectors}


def get_nodes_from_network(network: Network, node_class: Node) -> List[Node]:
    return [n for n in NodeVisitor(network) if isinstance(n, node_class)]


async def get_platform_tasks() -> List[str]:
    task_dirs = [os.path.join(d, "tasks") for d in get_network_dirs()]
    architect_client = platforms.architect_client_port()
    all_tasks = await architect_client.asset_manager.list_basenames()
    platform_tasks = [n for n in all_tasks if os.path.dirname(n) in task_dirs]
    return platform_tasks


async def run_from_payload(payload, context=None, handler=None, remote_request=True):
    command_name = "unknown"
    try:
        command_name = payload["command"]
        command = commands.command_registry[command_name]
    except KeyError as exc:
        if str(exc) == "command":
            raise RuntimeError('"command" is a missing argument.')
        else:
            raise RuntimeError('No "{}" command found.'.format(command_name))
    else:
        tokenv2_raw = payload.get("tokenv2", {})
        if getattr(command, "token_required", True):
            payload = await token.validate_and_decode_message(payload, remote_request)
        context = await add_request_details_to_context(handler, payload, remote_request, context)
        if tokenv2_raw:
            context["tokenv2_raw"] = tokenv2_raw
        args = payload.get("args", {})
        with Timer() as principal_check_time:
            security_context = await make_security_context(context, command)
            await security.authorize(security_context)
        request_id = context["guid"]
        if request_id is not None:
            ExecutionLogger.add_data(request_id, principal_check_time=(principal_check_time.elapsed))
        with Timer() as safety_check_time:
            await safety.check_command_safety(command, context)
        if request_id is not None:
            ExecutionLogger.add_data(request_id, safety_check_time=(safety_check_time.elapsed))
        try:
            log.info("%s start", command_name)
            response = await command(context, **args)
        except Exception:
            log.exception("Command execution failed.")
            raise
        else:
            log.info("%s finish", command_name)
            return response


async def add_request_details_to_context(handler, payload, remote_request, context=None):
    if context is None:
        context = {}
    context["remote_request"] = remote_request
    context["message_handler"] = handler
    context["command_type"] = payload.get("command_type", 0)
    context["token"] = payload.get("token") or ""
    context["tokenv2"] = payload.get("tokenv2") or {}
    request_id = payload.get("request_id")
    context["guid"] = request_id
    with Timer() as load_timer:
        args = payload.get("args", {})
        context.update(await make_loaded_network_context(network_name=(args.get("name", "")),
          network=(args.get("network")),
          references=(args.get("references"))))
    if request_id is not None:
        ExecutionLogger.add_data(request_id, network_load_time=(load_timer.elapsed))
    return context


async def make_loaded_network_context(network_name: str=None, network: dict=None, references: dict=None):
    if references:
        return make_empty_loaded_network_context()
    else:
        network_object = await load_network(network_name=network_name,
          network=network)
        return {'network_name':network_name, 
         'loaded_network':network_object, 
         'network_meta_data':get_task_info_node(network_object)}


def make_empty_loaded_network_context() -> dict:
    return {'network_name':"", 
     'loaded_network':None, 
     'network_meta_data':None}


def get_task_info_node(network_object):
    task_info_nodes = [] if not network_object else get_nodes_from_network(network_object, TaskInfo)
    if task_info_nodes:
        return task_info_nodes[0]


async def load_network(network_name: str=None, network: dict=None) -> Optional[Network]:
    network_object = None
    architect_client = platforms.architect_client_port()
    if network_name:
        log.info("loading architect network by name: {}".format(network_name))
        if not await network_exists(architect_client, network_name):
            raise HTTPNotFound(reason=("Network {} does not exist.".format(network_name)))
        network_object = await architect_client.load_network(network_name)
    else:
        if network is not None:
            log.info("loading architect network from dict")
            network_object = await architect_client.asset_manager.load_from_data(network)
    return network_object


async def network_exists(client: ClientPort, network_name: str) -> bool:
    return await client.asset_manager.storage.adapter.exists(network_name)


async def execute_with_reporting(message_handler, execution_options, name, args):
    start_time = datetime.datetime.now()
    reporting.report_history(message_handler, test=name,
      started_time=start_time,
      finished_time=None,
      status="RUNNING",
      connectors=[])
    status = "FAIL"
    connectors = []
    base_name = os.path.split(name)[-1]
    random_uuid = str(uuid.uuid4())[:8]
    internal_request_id = "{}:{}".format(base_name, random_uuid)
    asyncio.ensure_future(reporting.report_start(message_handler, execution_options, name, internal_request_id))
    try:
        try:
            with Timer() as load_timer:
                network = await load_network(network_name=name)
            ExecutionLogger.add_data(internal_request_id, network_load_time=(load_timer.elapsed))
            results = await commands.run_network(internal_request_id, network, kw=args, network_name=name)
        except Exception as exc:
            reporting.report_finish(message_handler, execution_options, internal_request_id, exc=exc)
            raise
        else:
            results["job_performance"] = ExecutionLogger.pop_data(internal_request_id)
            reporting.report_finish(message_handler, execution_options, internal_request_id, results=results)
            status = "PASS" if reporting.check_successful_results(results) else "FAIL"
            connectors = results.get("debug", {}).get("connectors", [])
    finally:
        reporting.report_history(message_handler, test=name,
          started_time=start_time,
          finished_time=(datetime.datetime.now()),
          status=status,
          connectors=connectors)

    return results


async def run_validation_node(validation_node: ReferencedValidationSubnetwork) -> bool:
    if not hasattr(validation_node.slots, "enter"):
        return False
    try:
        await validation_node.slots.enter()
    except StopNetwork as stop_network:
        return stop_network.network.outputs.exit_code.value == 0


def py2json(py_obj):
    if isinstance(py_obj, bytes):
        return 'b"{}"'.format(py_obj.hex())
    opts = (py_obj, type(py_obj))
    raise TypeError(("Unserializable object {} of type {}".format)(*opts))


def json2py(json_obj):
    for k, v in json_obj.items():
        if isinstance(v, str):
            m = re.match('^b"([a-f0-9]*)"', v)
            if m:
                v = bytes.fromhex(m.group(1))
        json_obj[k] = v

    return json_obj


def make_exception_report(exc: Exception, include_traceback: bool=False) -> dict:
    error_code = getattr(exc, "status_code", 500)
    traceback_str = traceback.format_exc()
    if not include_traceback:
        log.info("Removing traceback from response:\n{}".format(traceback_str))
    output = {'results':{"exit_code": error_code}, 
     'error':{'description':getattr(exc, "message", str(exc)), 
      'traceback':traceback_str if include_traceback else "", 
      'error_code':error_code}}
    return output


def with_exception_report(func: callable):

    async def caller(*args, **kw):
        try:
            return await func(*args, **kw)
        except Exception as exc:
            log.exception("Function call erred")
            include_traceback = not await is_fused()
            return make_exception_report(exc, include_traceback=include_traceback)

    functools.wraps(func, caller)
    caller.__name__ = func.__name__
    return caller

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/engine/handlers/utils.pyc
