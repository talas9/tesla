# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/engine/handlers/commands.py

-- Stacks of completed symbols:
START ::= |- stmts . 
alias ::= IMPORT_FROM . store
alias ::= IMPORT_FROM store . 
alias ::= IMPORT_NAME . attributes store
alias ::= IMPORT_NAME . store
and ::= expr . JUMP_IF_FALSE_OR_POP expr COME_FROM
and ::= expr . jmp_false expr
and ::= expr . jmp_false expr COME_FROM
and ::= expr . jmp_false expr jmp_false
assert ::= assert_expr . jmp_true LOAD_ASSERT RAISE_VARARGS_1 COME_FROM
assert2 ::= assert_expr . jmp_true LOAD_ASSERT expr CALL_FUNCTION_1 RAISE_VARARGS_1 COME_FROM
assert_expr ::= expr . 
assert_expr_and ::= assert_expr . jmp_false expr
assert_expr_or ::= assert_expr . jmp_true expr
assign ::= expr . DUP_TOP designList
assign ::= expr . store
assign2 ::= expr . expr ROT_TWO store store
assign2 ::= expr expr . ROT_TWO store store
assign3 ::= expr . expr expr ROT_THREE ROT_TWO store store store
assign3 ::= expr expr . expr ROT_THREE ROT_TWO store store store
async_call ::= expr . CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr . pos_arg CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr . pos_arg expr CALL_FUNCTION_KW_1 GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr . pos_arg pos_arg CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr . pos_arg pos_arg expr CALL_FUNCTION_KW_2 GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg . CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg . expr CALL_FUNCTION_KW_1 GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg . pos_arg CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg . pos_arg expr CALL_FUNCTION_KW_2 GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg expr . CALL_FUNCTION_KW_1 GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg expr CALL_FUNCTION_KW_1 . GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg pos_arg . CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg pos_arg . expr CALL_FUNCTION_KW_2 GET_AWAITABLE LOAD_CONST YIELD_FROM
async_with_as_stmt ::= expr . async_with_pre store \e_suite_stmts_opt POP_BLOCK LOAD_CONST async_with_post
async_with_as_stmt ::= expr . async_with_pre store suite_stmts_opt POP_BLOCK LOAD_CONST async_with_post
async_with_stmt ::= expr . POP_TOP \e_suite_stmts_opt POP_BLOCK LOAD_CONST async_with_post
async_with_stmt ::= expr . POP_TOP \e_suite_stmts_opt async_with_post
async_with_stmt ::= expr . POP_TOP suite_stmts_opt POP_BLOCK LOAD_CONST async_with_post
async_with_stmt ::= expr . POP_TOP suite_stmts_opt async_with_post
async_with_stmt ::= expr . async_with_pre POP_TOP \e_suite_stmts_opt POP_BLOCK LOAD_CONST async_with_post
async_with_stmt ::= expr . async_with_pre POP_TOP \e_suite_stmts_opt async_with_post
async_with_stmt ::= expr . async_with_pre POP_TOP suite_stmts_opt POP_BLOCK LOAD_CONST async_with_post
async_with_stmt ::= expr . async_with_pre POP_TOP suite_stmts_opt async_with_post
attribute ::= expr . LOAD_ATTR
attribute ::= expr LOAD_ATTR . 
aug_assign1 ::= expr . expr inplace_op ROT_THREE STORE_SUBSCR
aug_assign1 ::= expr . expr inplace_op store
aug_assign1 ::= expr expr . inplace_op ROT_THREE STORE_SUBSCR
aug_assign1 ::= expr expr . inplace_op store
aug_assign2 ::= expr . DUP_TOP LOAD_ATTR expr inplace_op ROT_TWO STORE_ATTR
await_expr ::= expr . GET_AWAITABLE LOAD_CONST YIELD_FROM
bin_op ::= expr . expr binary_operator
bin_op ::= expr expr . binary_operator
call ::= expr . CALL_FUNCTION_0
call ::= expr . pos_arg CALL_FUNCTION_1
call ::= expr . pos_arg pos_arg CALL_FUNCTION_2
call ::= expr . pos_arg pos_arg pos_arg CALL_FUNCTION_3
call ::= expr pos_arg . CALL_FUNCTION_1
call ::= expr pos_arg . pos_arg CALL_FUNCTION_2
call ::= expr pos_arg . pos_arg pos_arg CALL_FUNCTION_3
call ::= expr pos_arg pos_arg . CALL_FUNCTION_2
call ::= expr pos_arg pos_arg . pos_arg CALL_FUNCTION_3
call_ex_kw4 ::= expr . expr expr CALL_FUNCTION_EX_KW
call_ex_kw4 ::= expr expr . expr CALL_FUNCTION_EX_KW
call_ex_kw4 ::= expr expr expr . CALL_FUNCTION_EX_KW
call_kw36 ::= expr . expr LOAD_CONST CALL_FUNCTION_KW_1
call_kw36 ::= expr . expr expr LOAD_CONST CALL_FUNCTION_KW_2
call_kw36 ::= expr . expr expr expr LOAD_CONST CALL_FUNCTION_KW_3
call_kw36 ::= expr . expr expr expr expr LOAD_CONST CALL_FUNCTION_KW_4
call_kw36 ::= expr expr . LOAD_CONST CALL_FUNCTION_KW_1
call_kw36 ::= expr expr . expr LOAD_CONST CALL_FUNCTION_KW_2
call_kw36 ::= expr expr . expr expr LOAD_CONST CALL_FUNCTION_KW_3
call_kw36 ::= expr expr . expr expr expr LOAD_CONST CALL_FUNCTION_KW_4
call_kw36 ::= expr expr LOAD_CONST . CALL_FUNCTION_KW_1
call_kw36 ::= expr expr LOAD_CONST CALL_FUNCTION_KW_1 . 
call_kw36 ::= expr expr expr . LOAD_CONST CALL_FUNCTION_KW_2
call_kw36 ::= expr expr expr . expr LOAD_CONST CALL_FUNCTION_KW_3
call_kw36 ::= expr expr expr . expr expr LOAD_CONST CALL_FUNCTION_KW_4
call_stmt ::= expr . POP_TOP
classdefdeco1 ::= expr . classdefdeco1 CALL_FUNCTION_1
classdefdeco1 ::= expr . classdefdeco2 CALL_FUNCTION_1
compare_chained ::= expr . compared_chained_middle ROT_TWO POP_TOP \e__come_froms
compare_chained ::= expr . compared_chained_middle ROT_TWO POP_TOP _come_froms
compare_single ::= expr . expr COMPARE_OP
compare_single ::= expr expr . COMPARE_OP
compared_chained_middle ::= expr . DUP_TOP ROT_THREE COMPARE_OP JUMP_IF_FALSE_OR_POP compare_chained_right COME_FROM
compared_chained_middle ::= expr . DUP_TOP ROT_THREE COMPARE_OP JUMP_IF_FALSE_OR_POP compared_chained_middle COME_FROM
dict ::= expr . LOAD_CONST BUILD_CONST_KEY_MAP_1
dict ::= expr . expr LOAD_CONST BUILD_CONST_KEY_MAP_2
dict ::= expr . expr expr LOAD_CONST BUILD_CONST_KEY_MAP_3
dict ::= expr . expr expr expr LOAD_CONST BUILD_CONST_KEY_MAP_4
dict ::= expr . expr expr expr expr expr LOAD_CONST BUILD_CONST_KEY_MAP_6
dict ::= expr . expr expr expr expr expr expr LOAD_CONST BUILD_CONST_KEY_MAP_7
dict ::= expr . expr expr expr expr expr expr expr expr expr LOAD_CONST BUILD_CONST_KEY_MAP_10
dict ::= expr LOAD_CONST . BUILD_CONST_KEY_MAP_1
dict ::= expr expr . LOAD_CONST BUILD_CONST_KEY_MAP_2
dict ::= expr expr . expr LOAD_CONST BUILD_CONST_KEY_MAP_3
dict ::= expr expr . expr expr LOAD_CONST BUILD_CONST_KEY_MAP_4
dict ::= expr expr . expr expr expr expr LOAD_CONST BUILD_CONST_KEY_MAP_6
dict ::= expr expr . expr expr expr expr expr LOAD_CONST BUILD_CONST_KEY_MAP_7
dict ::= expr expr . expr expr expr expr expr expr expr expr LOAD_CONST BUILD_CONST_KEY_MAP_10
dict ::= expr expr LOAD_CONST . BUILD_CONST_KEY_MAP_2
dict ::= expr expr expr . LOAD_CONST BUILD_CONST_KEY_MAP_3
dict ::= expr expr expr . expr LOAD_CONST BUILD_CONST_KEY_MAP_4
dict ::= expr expr expr . expr expr expr LOAD_CONST BUILD_CONST_KEY_MAP_6
dict ::= expr expr expr . expr expr expr expr LOAD_CONST BUILD_CONST_KEY_MAP_7
dict ::= expr expr expr . expr expr expr expr expr expr expr LOAD_CONST BUILD_CONST_KEY_MAP_10
dict_comp ::= LOAD_DICTCOMP . LOAD_STR MAKE_FUNCTION_0 expr GET_ITER CALL_FUNCTION_1
dict_comp ::= LOAD_DICTCOMP LOAD_STR . MAKE_FUNCTION_0 expr GET_ITER CALL_FUNCTION_1
dict_comp ::= LOAD_DICTCOMP LOAD_STR MAKE_FUNCTION_0 . expr GET_ITER CALL_FUNCTION_1
dict_comp ::= LOAD_DICTCOMP LOAD_STR MAKE_FUNCTION_0 expr . GET_ITER CALL_FUNCTION_1
expr ::= LOAD_CONST . 
expr ::= LOAD_FAST . 
expr ::= attribute . 
expr ::= call_kw36 . 
expr_jitop ::= expr . JUMP_IF_TRUE_OR_POP
expr_jt ::= expr . jmp_true
if_exp ::= expr . jmp_false expr jf_cf expr COME_FROM
if_exp ::= expr . jmp_false expr jump_absolute_else expr
if_exp ::= expr . jmp_false expr jump_forward_else expr COME_FROM
if_exp37 ::= expr . expr jf_cfs expr COME_FROM
if_exp37 ::= expr expr . jf_cfs expr COME_FROM
if_exp_lambda ::= expr . jmp_false expr return_if_lambda return_stmt_lambda LAMBDA_MARKER
if_exp_not ::= expr . jmp_true expr jump_forward_else expr COME_FROM
if_exp_not_lambda ::= expr . jmp_true expr return_if_lambda return_stmt_lambda LAMBDA_MARKER
if_exp_true ::= expr . JUMP_FORWARD expr COME_FROM
import ::= LOAD_CONST . LOAD_CONST alias
import ::= LOAD_CONST LOAD_CONST . alias
import_from ::= LOAD_CONST . LOAD_CONST IMPORT_NAME importlist POP_TOP
import_from ::= LOAD_CONST LOAD_CONST . IMPORT_NAME importlist POP_TOP
import_from ::= LOAD_CONST LOAD_CONST IMPORT_NAME . importlist POP_TOP
import_from ::= LOAD_CONST LOAD_CONST IMPORT_NAME importlist . POP_TOP
import_from ::= LOAD_CONST LOAD_CONST IMPORT_NAME importlist POP_TOP . 
import_from_star ::= LOAD_CONST . LOAD_CONST IMPORT_NAME IMPORT_STAR
import_from_star ::= LOAD_CONST LOAD_CONST . IMPORT_NAME IMPORT_STAR
import_from_star ::= LOAD_CONST LOAD_CONST IMPORT_NAME . IMPORT_STAR
importlist ::= alias . 
importlist ::= importlist . alias
importmultiple ::= LOAD_CONST . LOAD_CONST alias imports_cont
importmultiple ::= LOAD_CONST LOAD_CONST . alias imports_cont
kvlist_1 ::= expr . expr BUILD_MAP_1
kvlist_1 ::= expr expr . BUILD_MAP_1
lambda_body ::= expr . LOAD_LAMBDA LOAD_STR MAKE_FUNCTION_4
lambda_body ::= expr . expr LOAD_LAMBDA LOAD_STR MAKE_FUNCTION_5
lambda_body ::= expr expr . LOAD_LAMBDA LOAD_STR MAKE_FUNCTION_5
list ::= expr . BUILD_LIST_1
mkfunc ::= expr . LOAD_CODE LOAD_STR MAKE_FUNCTION_4
mkfunc ::= expr . expr LOAD_CODE LOAD_STR MAKE_FUNCTION_5
mkfunc ::= expr . load_closure LOAD_CODE LOAD_STR MAKE_FUNCTION_12
mkfunc ::= expr expr . LOAD_CODE LOAD_STR MAKE_FUNCTION_5
mkfuncdeco ::= expr . mkfuncdeco CALL_FUNCTION_1
mkfuncdeco ::= expr . mkfuncdeco0 CALL_FUNCTION_1
pos_arg ::= expr . 
ret_and ::= expr . JUMP_IF_FALSE_OR_POP return_expr_or_cond COME_FROM
ret_or ::= expr . JUMP_IF_TRUE_OR_POP return_expr_or_cond COME_FROM
return ::= return_expr . RETURN_END_IF
return ::= return_expr . RETURN_VALUE
return ::= return_expr . RETURN_VALUE COME_FROM
return_expr ::= expr . 
return_expr_lambda ::= return_expr . RETURN_VALUE_LAMBDA
return_expr_lambda ::= return_expr . RETURN_VALUE_LAMBDA LAMBDA_MARKER
sstmt ::= sstmt . RETURN_LAST
sstmt ::= stmt . 
stmt ::= import_from . 
stmts ::= sstmt . 
stmts ::= stmts . sstmt
store ::= STORE_FAST . 
store ::= expr . STORE_ATTR
store_subscript ::= expr . expr STORE_SUBSCR
subscript ::= expr . expr BINARY_SUBSCR
subscript ::= expr expr . BINARY_SUBSCR
subscript2 ::= expr . expr DUP_TOP_TWO BINARY_SUBSCR
subscript2 ::= expr expr . DUP_TOP_TWO BINARY_SUBSCR
testfalse ::= expr . jmp_false
testtrue ::= expr . jmp_true
tuple ::= expr . BUILD_TUPLE_1
tuple ::= expr . expr BUILD_TUPLE_2
tuple ::= expr . expr expr BUILD_TUPLE_3
tuple ::= expr expr . BUILD_TUPLE_2
tuple ::= expr expr . expr BUILD_TUPLE_3
tuple ::= expr expr expr . BUILD_TUPLE_3
unary_not ::= expr . UNARY_NOT
unary_op ::= expr . unary_operator
with ::= expr . SETUP_WITH POP_TOP \e_suite_stmts_opt POP_BLOCK LOAD_CONST COME_FROM_WITH WITH_CLEANUP_START WITH_CLEANUP_FINISH END_FINALLY
with ::= expr . SETUP_WITH POP_TOP suite_stmts_opt POP_BLOCK LOAD_CONST COME_FROM_WITH WITH_CLEANUP_START WITH_CLEANUP_FINISH END_FINALLY
with_as ::= expr . SETUP_WITH store \e_suite_stmts_opt POP_BLOCK LOAD_CONST COME_FROM_WITH WITH_CLEANUP_START WITH_CLEANUP_FINISH END_FINALLY
with_as ::= expr . SETUP_WITH store suite_stmts_opt POP_BLOCK LOAD_CONST COME_FROM_WITH WITH_CLEANUP_START WITH_CLEANUP_FINISH END_FINALLY
yield ::= expr . YIELD_VALUE
yield_from ::= expr . GET_YIELD_FROM_ITER LOAD_CONST YIELD_FROM
Instruction context:
-> 
 L. 166         0  LOAD_CONST               0
                   2  LOAD_CONST               ('cid',)
                   4  IMPORT_NAME              odin.core
                   6  IMPORT_FROM              cid
                   8  STORE_FAST               'cid'
                  10  POP_TOP          
import asyncio, json, functools, logging
from typing import List, Optional, Set, Tuple, Union
from aiohttp.web import HTTPBadRequest, HTTPNotFound, HTTPRequestTimeout
import async_timeout
from architect.core.network import Network
from architect.workflows.actions.action import DumpedActionEngine
from architect.workflows.dump import Dump
from architect.workflows.dump_results import DumpResults
from architect.workflows.dump_datatypes import DumpDatatypes
from architect.workflows.dump_nodedefs import DumpNodeDefinitions
from architect.workflows.encoder import DatatypeEncoder
import odin, odin.nodes
from odin.core import can, uds
from odin.core.orchestrator import exceptions as orchestrator_exceptions, memory as orchestrator_memory, runner as orchestrator_runner, triggers as orchestrator_triggers
from odin.platforms.common import detect_platform
from odin.services.data_upload import data_upload
from odin.services.hrl import hrl_upload
from odin.testing.gateway import get_recorder_instance, create_record_playback_instance, clear_record_replay_instance, DEFAULT_RUN_ID
from odin_server.messages import StatusUpdate
from odin.core.cid.interface import is_fused
from odin.core.patch import PatchError
from odin.core.patch import loader
from odin.core.patch import install
from odin.core.utils.async_logging import async_syslog
from odin.core.engine import messagebox
from odin.core.engine import safety
from odin.core.engine import security
from odin.core.engine.handlers.evaluate_references import load_network_with_references
from odin.core.engine.handlers.evaluate_references import make_references_client
from odin.core.engine.handlers import utils
from odin.core.engine.handlers.logging_handler import EngineLoggingHandler
from odin.core.engine.handlers.message_handler import TaskInfo
from odin.core.engine.security_context import make_user_context
from odin.core.engine.security_context import make_vehicle_context
from odin.core.engine import tasks
from odin.core.engine.plugins import signals as aio_signals
from odin.nodes import comments
from odin.platforms import get_gateway_interface
from odin.testing.execution import ExecutionLogger
log = logging.getLogger(__name__)
blocking_commands = []
command_registry = {}
configured_log_level = None
unix_command_registry = {}

def engine_command(name: str='', security_checks: Tuple[callable]=None, safety_checks: Tuple[callable]=None, token_required: bool=True, unix_socket_command: bool=False, blocking: bool=False) -> callable:

    def wrapper(func):
        command_name = name or func.__name__

        @functools.wraps(func)
        def caller(*args, **kw):
            log.info("calling engine command: {}".format(command_name))
            return func(*args, **kw)

        if unix_socket_command:
            unix_command_registry[command_name] = caller
        else:
            command_registry[command_name] = caller
        if blocking:
            blocking_commands.append(command_name)
        setattr(caller, "security_checks", security_checks or tuple())
        setattr(caller, "safety_checks", safety_checks or tuple())
        setattr(caller, "token_required", token_required)
        return caller

    return wrapper


@engine_command(token_required=False)
async def ping(context: dict) -> dict:
    return {"pong": True}


@engine_command(security_checks=(security.authenticated_permission,))
async def uninstall_patch(context: dict, timeout: int=60) -> dict:

    async def clear():
        async with install.lock:
            await loader.uninstall_patch_and_reboot_if_mounted()

    try:
        await asyncio.wait_for((clear()), timeout=timeout)
    except PatchError as e:
        return {'results':{"exit_code": 1}, 
         'error':install.format_exc(e)}
    except asyncio.TimeoutError:
        return {"results": {'exit_code':1,  'status':"installing patch still in progress"}}

    return {"results": {"exit_code": 0}}


@engine_command(security_checks=(security.authenticated_permission,))
async def install_patch(context, persist=False, timeout=300):
    if persist:
        if await is_fused():
            return {'results':{"exit_code": 1}, 
             'error':"persistent patch not supported."}
        if install.lock.locked():
            return {"results": {'exit_code':0,  'status':"already in progress"}}
    else:
        try:
            result = await asyncio.wait_for((install.install_patch(persist, timeout)), timeout=timeout)
        except asyncio.TimeoutError:
            await loader.uninstall_patch_and_reboot_if_mounted()
            return {'results':{"exit_code": 1},  'error':"patch install timed out"}
        except Exception as e:
            log.exception(e)
            await loader.uninstall_patch_and_reboot_if_mounted()
            return {'results':{"exit_code": 1},  'error':install.format_exc(e)}
        else:
            return {"results": result}


@engine_command(security_checks=(security.authenticated_permission,))
async def active_alertsParse error at or near `LOAD_CONST' instruction at offset 0


@engine_command(security_checks=(security.authenticated_permission,))
async def cancel_request(context: dict, cancel_id: str) -> dict:
    for task_info in get_context_tasks(context):
        request_id = task_info.request_id()
        if request_id == cancel_id:
            log.info("Cancelling request={}, request={}".format(task_info.request, request_id))
            if await cancel_task(context, task_info):
                return {"status": ("task {} is cancelled".format(cancel_id))}

    return {"status": "0 tasks cancelled"}


@engine_command(security_checks=(security.authenticated_permission,))
async def list_tasks(context: dict) -> Union[(list, dict)]:
    vehicle_context = await make_vehicle_context()
    user_context = await make_user_context(context)
    return await tasks.filter_tasks(context, vehicle_context, user_context)


@engine_command(security_checks=(security.local_engineering_check,))
async def list_signals(context: dict, buses: list=["eth"]) -> list:
    return can.signal.available_signals(buses)


@engine_command(security_checks=(security.engineering_check,))
async def edit_network(context, network, action, method, kw, references):
    action_engine = make_action_engine(references)
    result = await (action_engine.run_action)(action, method, network, **kw)
    return json.dumps(result, cls=DatatypeEncoder)


def make_action_engine(references):
    client = make_references_client(references)
    return DumpedActionEngine(asset_manager=(client.asset_manager))


@engine_command(security_checks=(security.engineering_check,))
async def load_network_from_data(context, network, references):
    network = await load_network_with_references(network, references)
    return Dump().dump(network)


@engine_command(security_checks=(security.engineering_check,))
async def datatypes(context: dict) -> list:
    return utils.compress_string(DumpDatatypes().dumps())


@engine_command(security_checks=(security.engineering_check,))
async def nodes(context: dict) -> list:
    return utils.compress_string(DumpNodeDefinitions().dumps())


@engine_command(security_checks=(security.authenticated_permission,))
async def cancel_by_name(context: dict, name: str):
    cancelled_request_ids = []
    for task_info in get_context_tasks(context):
        task_name = task_info.request.get("args", {}).get("name")
        request_id = task_info.request_id()
        if task_name and task_name == name:
            log.info("Cancelling request by name={}, request_id={}".format(task_info.request, request_id))
            if await cancel_task(context, task_info):
                cancelled_request_ids.append(request_id)

    return {"status": ("{} tasks cancelled".format(",".join(cancelled_request_ids or [])))}


@engine_command(security_checks=(security.authenticated_permission,))
async def cancel_all_requests(context: dict) -> dict:
    cancelled_request_ids = []
    for task_info in get_context_tasks(context):
        request_id = task_info.request_id()
        log.info("Cancelling request={}, request_id={}".format(task_info.request, request_id))
        if await cancel_task(context, task_info):
            cancelled_request_ids.append(request_id)

    return {"status": ("{} tasks cancelled".format(",".join(cancelled_request_ids or [])))}


async def cancel_task(context: dict, task_info: TaskInfo) -> bool:
    handler = context.get("message_handler")
    if handler:
        return await handler.cancel_task(task_info)
    else:
        return False


@engine_command(security_checks=(security.authenticated_permission,))
async def clear_dtcs(context: dict, node_names: list=None) -> dict:
    output = {}
    for node_name, node in uds.nodes.items():
        if not node_names or node_name in node_names:
            msg = StatusUpdate(context.get("guid"), "Clearing {}...".format(node_name))
            await messagebox.outbox.put(msg)
            try:
                await uds.clear_diagnostic_information(node)
            except Exception as exc:
                log.exception("Failed to clear dtcs.")
                output[node_name] = {"error": {"description": (str(exc))}}

            output[node_name] = {"error": None}

    return output


@engine_command(security_checks=(security.authenticated_permission,))
async def disable_remote_logging(context: dict) -> dict:
    global configured_log_level
    odin_logger = logging.getLogger("odin")
    if configured_log_level is not None:
        odin_logger.setLevel(configured_log_level)
    for handler in odin_logger.handlers:
        if isinstance(handler, EngineLoggingHandler):
            handler.setLevel(handler.DISABLED)
            return {"status": "ok"}
    else:
        return {"error": "Could not find ODIN engine logging handler."}


@engine_command(security_checks=(security.authenticated_permission,))
async def disable_remote_monitoring(context: dict, signal_names: list=None):
    aio_signals.remove_signals(signal_names or [])
    return {"status": "ok"}


@engine_command(unix_socket_command=True, token_required=False)
async def enable_data_upload(alert: str=''):
    asyncio.ensure_future(data_upload.start_service(alert=alert))


@engine_command(unix_socket_command=True, token_required=False)
async def enable_hrl_upload(hrl_type: str='hrl_ecu'):
    asyncio.ensure_future(hrl_upload.start_service(hrl_type))
    return {"status": "ok"}


@engine_command(security_checks=(security.authenticated_permission,))
async def enable_remote_monitoring(context: dict, signals: dict=None):
    values = {}
    if signals is not None:
        values = await aio_signals.add_signals(signals)
    return {"values": values}


@engine_command(security_checks=(security.engineering_check,))
async def enable_remote_logging(context: dict, level: str='ERROR') -> dict:
    global configured_log_level
    odin_logger = logging.getLogger("odin")
    for handler in odin_logger.handlers:
        if isinstance(handler, EngineLoggingHandler):
            try:
                configured_log_level = odin_logger.getEffectiveLevel()
                odin_logger.setLevel(level)
                handler.setLevel(level)
            except (TypeError, ValueError) as e:
                return {"error": (repr(e))}

            return {"level": (logging.getLevelName(handler.level))}
    else:
        return {"error": "Could not find ODIN engine logging handler."}


@engine_command(security_checks=(security.authenticated_permission,))
async def keep_alive_remote_monitoring(context: dict):
    await aio_signals.keep_alive()
    return {"status": "ok"}


@engine_command(security_checks=(security.engineering_check,))
async def add_hermes_send_topic(context: dict, topic_prefix: str):
    MAX_PERMANENT_SEND_TOPICS = 3
    handler = context.get("message_handler")
    if handler:
        from odin.core import cid
        vin = await cid.interface.get_vin()
        topic = "{}.{}.odin".format((topic_prefix or "").strip(), vin)
        if topic in handler.permanent_send_topics:
            return {"result": "already_enabled"}
        else:
            if len(handler.permanent_send_topics) >= MAX_PERMANENT_SEND_TOPICS:
                return {"result": "not_enabled_too_many_topics"}
            handler.permanent_send_topics.add(topic)
            return {"result": "enabled"}
    else:
        return {"result": "not_enabled_no_message_handler"}


async def run_network(request_id: str, network: Network, kw: dict, testing: Optional[dict]=None, network_name: Optional[str]=None) -> dict:
    dump_results = DumpResults()
    try:
        with utils.Timer() as setup_uds_trace_timer:
            setup_testing_instance(testing)
        log.info("architect network start")
        with utils.Timer() as network_exec_timer:
            results = await network(**kw)
        log.info("architect network finish")
        with utils.Timer() as uds_trace_dump_timer:
            uds_trace = get_uds_trace()
        ExecutionLogger.add_data(request_id, uds_trace_setup_time=(setup_uds_trace_timer.elapsed))
        ExecutionLogger.add_data(request_id, architect_network_exec_time=(network_exec_timer.elapsed))
        ExecutionLogger.add_data(request_id, uds_trace_dump_time=(uds_trace_dump_timer.elapsed))
        if uds_trace:
            ExecutionLogger.add_data(request_id, uds_trace_first_frame=(uds_trace[0]))
            ExecutionLogger.add_data(request_id, uds_trace_last_frame=(uds_trace[-1]))
    finally:
        with utils.Timer() as cleanup_uds_trace_timer:
            cleanup_testing_instance()
        ExecutionLogger.add_data(request_id, uds_trace_cleanup_time=(cleanup_uds_trace_timer.elapsed))

    with utils.Timer() as result_dump_timer:
        output = dump_results.dump(results)
        output.pop("tasks", None)
    ExecutionLogger.add_data(request_id, result_dump_time=(result_dump_timer.elapsed))
    if network_name is not None:
        output["task_name"] = network_name
    if should_attach_debug_data(output, testing):
        if uds_trace is not None:
            output.setdefault("debug", {})["uds_trace"] = uds_trace
        with utils.Timer() as iris_data_attach_timer:
            if network_name is not None:
                exit_code = output.get("results", {}).get("exit_code")
                iris_data = utils.get_iris_data(network_name, exit_code) or {}
                output.setdefault("debug", {})["connectors"] = iris_data.get("connectors", [])
        ExecutionLogger.add_data(request_id, iris_data_attach_time=(iris_data_attach_timer.elapsed))
    try:
        if "traceback" in output["error"]:
            if await is_fused():
                log.info("Removing traceback from response:\n{}".format(output["error"]["traceback"]))
                output["error"]["traceback"] = ""
    except (AttributeError, KeyError, TypeError):
        pass

    try:
        output["error"]["ecu_name"] = results.error.exception_object.ecu_name
    except (AttributeError, KeyError):
        pass

    return output


async def run_network_with_retries(request_id: str, network: Network, metadata: Optional[comments.TaskInfo]=None, kw: Optional[dict]=None, testing: Optional[dict]=None, retries: int=0, pause_between_retries: int=0, global_timeout: int=0, network_name: Optional[str]=None) -> dict:
    failed_attempts = []
    if metadata is not None:
        retries = retries or metadata.default_retries.value or 0
        pause_between_retries = pause_between_retries or metadata.default_pause_between_retries.value or 0
        global_timeout = global_timeout or metadata.default_global_timeout.value or 0
    try:
        with async_timeout.timeout(global_timeout / 1000.0 if global_timeout else None):
            for i in range(retries + 1):
                results = await run_network(request_id, network, kw, testing, network_name)
                if results.get("results", {}).get("exit_code", 0) == 0:
                    break
                elif i < retries:
                    failed_attempts.append(results)
                if pause_between_retries:
                    await asyncio.sleep(pause_between_retries / 1000.0)

    except asyncio.TimeoutError:
        include_traceback = not await is_fused()
        results = utils.make_exception_report(HTTPRequestTimeout(reason="Command timed out"),
          include_traceback=include_traceback)
        if network_name is not None:
            results["task_name"] = network_name

    if failed_attempts:
        results.setdefault("debug", {})["failed_attempts"] = failed_attempts
    return results


async def execute_network(context, name=None, kw=None, testing=None, retries=0, pause_between_retries=0, global_timeout=0):
    await async_syslog("START {} Executing network".format(name))
    network_object = context.pop("loaded_network")
    network_meta_data = context.get("network_meta_data")
    kw = kw or {}
    kw["execution_options"] = context
    async with orchestrator_runner.pause_orchestrator(resume_delay=5):
        results = await run_network_with_retries((context.get("guid", "")),
          network_object,
          network_meta_data,
          kw=kw,
          testing=testing,
          retries=retries,
          pause_between_retries=pause_between_retries,
          global_timeout=global_timeout,
          network_name=name)
    if results.get("error") is None:
        keyword = "PASS" if results.get("results", {}).get("exit_code") == 0 else "FAIL"
        await async_syslog("{} {} Finished executing network".format(keyword, name))
    else:
        error_code = results.get("error").get("error_code", 500)
        await async_syslog("ERROR {} Executing network resulted in error ({})".format(name, error_code))
    patch = loader.get_active_patch_signature()
    if patch:
        results["patch"] = patch
    return results


@engine_command(security_checks=(
 security.authenticated_permission,
 security.execute_check),
  safety_checks=(
 safety.vehicle_state_allowed,),
  blocking=True)
@utils.with_exception_report
async def execute(context, name=None, kw=None, testing=None, retries=0, pause_between_retries=0, global_timeout=0):
    return await execute_network(context, name, kw, testing, retries, pause_between_retries, global_timeout)


@engine_command(security_checks=(
 security.post_fusing_execute_check,),
  safety_checks=(
 safety.vehicle_state_allowed,),
  token_required=False,
  blocking=True)
@utils.with_exception_report
async def post_fusing_execute(context, name=None, kw=None, testing=None, retries=0, pause_between_retries=0, global_timeout=0):
    return await execute_network(context, name, kw, testing, retries, pause_between_retries, global_timeout)


@engine_command(security_checks=(security.engineering_check,))
async def available_tasks(context: dict, networks: Optional[List[str]]=None) -> dict:
    tasks = networks if networks else await utils.get_platform_tasks()
    compatible_tasks = await utils.filter_tasks_for_compatibility(tasks)
    return {"networks": compatible_tasks}


@engine_command(security_checks=(security.evaluate_check,), blocking=True)
@utils.with_exception_report
async def evaluate(context, network=None, kw=None, testing=None, retries=0, pause_between_retries=0, global_timeout=0, references=None):
    await async_syslog("START Evaluating custom network")
    kw = kw or {}
    if references is None:
        network_object = context.pop("loaded_network") if "loaded_network" in context else await utils.load_network(network=network)
    else:
        network_object = await load_network_with_references(network, references)
    kw["execution_options"] = context
    results = await run_network_with_retries((context.get("guid", "")),
      network_object,
      (context.get("network_meta_data")),
      kw=kw,
      testing=testing,
      retries=retries,
      pause_between_retries=pause_between_retries,
      global_timeout=global_timeout)
    return results


def get_context_tasks(context: dict) -> List[TaskInfo]:
    handler = context.get("message_handler")
    if handler:
        request_id = context.get("guid")
        all_tasks = list(handler.running_tasks.values()) + handler.pending_tasks
        all_tasks = [t for t in all_tasks if t.request_id() != request_id]
        return all_tasks


@engine_command(security_checks=(security.authenticated_permission,))
async def get_connectors(context: dict, name: str) -> dict:
    iris_data = utils.get_iris_data(name)
    if not iris_data:
        raise HTTPNotFound(reason=("No connector data found for network '{}'".format(name)))
    return {"connectors": (iris_data.get("connectors", []))}


@engine_command(token_required=False)
async def get_vin(context: dict) -> str:
    from odin.core import cid
    try:
        return await cid.interface.get_vin()
    except Exception as exc:
        raise RuntimeError("Vehicle failed to provide VIN: {}".format(getattr(exc, "message", repr(exc))))


@engine_command(security_checks=(security.authenticated_permission,))
async def list_requests(context: dict) -> dict:
    handler = context.get("message_handler")
    current_request_id = context.get("guid")
    if handler:
        tasks_dict = handler.describe_current_tasks()
        if current_request_id in tasks_dict:
            del tasks_dict[current_request_id]
        return {'tasks':tasks_dict, 
         'active_lock':handler.locked_task_group()}
    else:
        return {}


@engine_command(security_checks=(
 security.lock_permission,
 security.lock_check))
@utils.with_exception_report
async def lock(context, task_group, timeout=5.0):
    handler = context.get("message_handler")
    handler.set_task_group_lock(task_group=task_group, timeout=timeout)
    return {'results':{"exit_code": 0},  'error':None}


@engine_command()
@utils.with_exception_report
async def orchestrator_status(context: dict) -> dict:
    status_results = await orchestrator_runner.orchestrator_status()
    return {"results": {'exit_code':0,  'status':status_results}}


@engine_command(security_checks=(security.authenticated_permission,))
async def read_dtcs(context: dict, node_names: list=None) -> dict:
    request_id = context.get("guid")
    output = {}
    for node_name, node in sorted(uds.nodes.items()):
        if not node_names or node_name in node_names:
            msg = StatusUpdate(request_id, "Reading {}...".format(node_name))
            await messagebox.outbox.put({"message": msg})
            try:
                dtcs = await uds.read_dtcs(node)
            except Exception as exc:
                log.exception("Failed to read dtcs.")
                output[node_name] = {'error':{"description": (str(exc))}, 
                 'dtcs':[]}

            output[node_name] = {'error':None, 
             'dtcs':[{'code':dtc,  'value':value,  'text':", ".join(str(uds.DTCMask(value)).split(".")[1].split("|"))} for dtc, value in dtcs.items()]}

    return output


@engine_command(security_checks=(security.authenticated_permission,))
async def read_signals(context, signal_names, bus_name='ETH'):
    signals = await can.signal.read_by_names(signal_names, bus_name)
    return {"signals": signals}


@engine_command(token_required=False)
@utils.with_exception_report
async def start_orchestrator_fused(context: dict, jobs: Optional[str]='fuse-jobs', auto_start: bool=False, already_running_ok: bool=False):
    was_already_running = False
    try:
        await orchestrator_runner.start_orchestrator_fused(context, jobs, auto_start)
    except orchestrator_exceptions.OrchestratorAlreadyRunning:
        if not already_running_ok:
            raise
        was_already_running = True

    return {'results':{'exit_code':0,  'was_already_running':was_already_running},  'error':None}


@engine_command(security_checks=(security.authenticated_permission,
 security.orchestrator_check))
@utils.with_exception_report
async def start_orchestrator(context: dict, jobs: Union[(None, str, dict)]=None, auto_start: bool=False, already_running_ok: bool=False):
    was_already_running = False
    try:
        await orchestrator_runner.start_orchestrator(context, jobs, auto_start)
    except orchestrator_exceptions.OrchestratorAlreadyRunning:
        if not already_running_ok:
            raise
        was_already_running = True

    return {'results':{'exit_code':0,  'was_already_running':was_already_running},  'error':None}


@engine_command(security_checks=(security.authenticated_permission,))
async def status(context: dict) -> dict:
    from odin.core import cid
    checks = {'buffer':False, 
     'carserver':True, 
     'das':True}
    checks["buffer"] = True
    try:
        vin = await cid.interface.get_vin()
    except asyncio.TimeoutError:
        log.debug("Timed out getting VIN")
        vin = ""
        checks["carserver"] = False

    try:
        fw_version = await cid.interface.get_fw_version()
    except asyncio.TimeoutError:
        log.debug("Timed out getting FW version")
        fw_version = ""
        checks["carserver"] = False

    if checks["carserver"] and not odin.options["core"]["onboard"]:
        try:
            platform = await detect_platform()
        except odin.exceptions.OdinException:
            log.error("unknown platform, cannot autoconfigure")

    elif isinstance(platform, str):
        odin.configure_as(platform, fw_version)
    else:
        log.error("unknown platform, cannot autoconfigure")
    versions = {'odin':odin.__version__, 
     'firmware':fw_version, 
     'patch':loader.get_active_patch_signature()}
    states = {"gated": None}
    if odin.options["core"]["onboard"]:
        if get_gateway_interface() == "Gen3":
            command = "gw-diag GET_GATED_STATUS"
            try:
                resp = await asyncio.wait_for(odin.core.cid.interface.run_command(command=command), timeout=0.5)
            except Exception as exc:
                log.exception("Failed to get gated status")

            gated_status_raw = resp.get("stdout").rstrip()
            states["gated"] = True if gated_status_raw == "01" else False
    return {'status':int(not all(checks.values())),  'product_id':vin, 
     'platform':odin.__platform__, 
     'versions':versions, 
     'checks':checks, 
     'states':states}


@engine_command(token_required=False)
@utils.with_exception_report
async def clear_orchestrator(context: dict):
    if orchestrator_runner.orchestrator_is_running():
        raise HTTPBadRequest(reason="Cannot clear Orchestrator results while it's running.")
    await orchestrator_memory.clear_all_results()
    return {'results':{"exit_code": 0},  'error':None}


@engine_command(token_required=False)
@utils.with_exception_report
async def stop_orchestrator(context: dict):
    await orchestrator_runner.stop_orchestrator()
    return {'results':{"exit_code": 0},  'error':None}


@engine_command(security_checks=(security.authenticated_permission,
 security.orchestrator_check))
@utils.with_exception_report
async def trigger_orchestrator(context: dict, trigger: Union[(list, str)]):
    triggers = [trigger] if isinstance(trigger, str) else trigger
    await orchestrator_triggers.set_triggers(triggers)
    return {'results':{"exit_code": 0},  'error':None}


@engine_command(security_checks=(security.lock_permission,))
@utils.with_exception_report
async def unlock(context: dict, task_group: str) -> dict:
    handler = context.get("message_handler")
    handler.clear_task_group_lock(task_group)
    return {'results':{"exit_code": 0},  'error':None}


def setup_testing_instance(testing_args: dict, session_id: str=DEFAULT_RUN_ID) -> None:
    create_record_playback_instance(testing_args, run_id=(session_id or DEFAULT_RUN_ID))


def get_uds_trace(session_id: str=DEFAULT_RUN_ID) -> list:
    recorder = get_recorder_instance(session_id)
    uds_trace = None
    if recorder is not None:
        from odin.testing.gateway.recorder.linear_recorder import LinearGatewayRecorder
        uds_trace = LinearGatewayRecorder.compact_log(recorder.dump_logged())
    return uds_trace


def should_attach_debug_data(result: dict, test_arg: dict=None) -> bool:
    if odin.options.get("testing", {}).get("debug_data_enabled", False):
        log.info("debug_data_enabled via config file")
        return True
    else:
        error_out = result.get("error") is not None
        failed = isinstance(result.get("results"), dict) and "exit_code" in result.get("results") and result.get("results").get("exit_code") != 0
        record_explicitly_turned_on = test_arg is not None and test_arg.get("record") is not None
        return_debug_data = error_out or failed or record_explicitly_turned_on
        log.debug("Debug Data Return={}, reason: NetworkRun error_out={}, failed={}, Recorder Explicitly turned on={}".format(return_debug_data, error_out, failed, record_explicitly_turned_on))
        return return_debug_data


def cleanup_testing_instance(session_id: str=DEFAULT_RUN_ID) -> None:
    clear_record_replay_instance(session_id)


def is_blocking_command(payload: dict) -> bool:
    return payload.get("command") in blocking_commands
