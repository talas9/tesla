# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/engine/plugins/service.py
import asyncio
from aiohttp import web
from functools import partial
import json, logging, os
from typing import Optional, Set
from architect.workflows.encoder import DatatypeEncoder
from odin import get_resource_path
import odin.core.can.signal
from odin.core.cid.interface import factory_mode, filesystem, get_data_value, is_fused
from odin.core.engine.plugins import history
from odin.core.gateway import gtw_config
from odin.core.orchestrator import helpers, locks, runner, security, tracking
log = logging.getLogger(__name__)
_COOLANT_STATUS_SIGNAL_NAME = "VCFRONT_coolantFillRoutineStatus"
_REFRIGERANT_STATUS_SIGNAL_NAME = "VCFRONT_refrigFillRoutineStatus"
_task_active = False
_service_jobs_tasks = None
_action_task_status = None

async def index(request: web.Request) -> web.FileResponse:
    return web.FileResponse(get_resource_path("service_ui/index.html"))


async def status(request: web.Request) -> web.Response:
    tab = request.query.get("tab")
    if not isinstance(tab, str):
        tab = None
    orchestrator_status, gateway_status, ui_status, tab_status, task_status = await asyncio.gather(runner.orchestrator_status(), _get_gateway_status(), _get_ui_status(), _get_tab_status(tab), _get_action_task_status())
    response_dict = {
     'orchestrator_status': orchestrator_status, 
     'gateway_status': gateway_status, 
     'ui_status': ui_status, 
     'tasks_status': task_status}
    if tab_status is not None:
        response_dict[tab + "_tab_status"] = tab_status
    return web.json_response(response_dict)


async def taskinfo(request: web.Request) -> web.Response:
    job = request.query.get("job")
    task = request.query.get("task")
    if not isinstance(job, str) or not isinstance(task, str):
        return web.json_response({"error": "task and job must be provided"}, status=400)
    else:
        results = await helpers.get_task_result(job, task)
        if results is None:
            return web.json_response({"error": "no results available"}, status=400)
        return web.json_response({"raw": results})


async def runtask(request: web.Request) -> web.Response:
    try:
        task_name = (await request.json()).get("task")
    except (AttributeError, json.JSONDecodeError):
        task_name = None
    except Exception:
        log.exception("Unexpected exception while parsing task input")
        task_name = None

    if not isinstance(task_name, str):
        return web.json_response({"error": "task must be provided"}, status=400)
    if not await _task_allowed(task_name):
        return web.json_response({"error": "unsupported task"}, status=406)
    if _task_is_active():
        return web.json_response({'success':False,  'reason':"busy"}, status=409)
    message_handler = helpers.get_message_handler()
    if message_handler:
        if message_handler.has_blocking_task():
            return web.json_response({'success':False,  'reason':"busy_external"}, status=409)
    if not await security.gateway_unlocked():
        return web.json_response({"error": "unauthorized"}, status=401)
    _update_task_running(task_name, True)
    try:
        try:
            success, raw_results = await helpers.execute_task(task_name)
            _update_task_success(task_name, success)
            return web.json_response({'success':success, 
             'raw':raw_results},
              dumps=partial((json.dumps), cls=DatatypeEncoder))
        except Exception:
            _update_task_success(task_name, False)
            raise

    finally:
        _update_task_running(task_name, False)


@locks.timed_cache(2)
async def _get_thermal_status() -> dict:
    try:
        signal_values = await odin.core.can.signal.read_by_names([
         _COOLANT_STATUS_SIGNAL_NAME,
         _REFRIGERANT_STATUS_SIGNAL_NAME])
        coolant_fill_status = signal_values.get(_COOLANT_STATUS_SIGNAL_NAME)
        refrigerant_fill_status = signal_values.get(_REFRIGERANT_STATUS_SIGNAL_NAME)
    except RuntimeError:
        log.exception("Error reading fill routine status")
        coolant_fill_status = None
        refrigerant_fill_status = None

    return {'coolant_fill_status':coolant_fill_status, 
     'refrigerant_fill_status':refrigerant_fill_status}


async def _get_factory_status() -> dict:
    return {'task_history':list(reversed(history.history.values())), 
     'help_text':tracking.get_help_text()}


async def _get_gateway_status() -> dict:
    level, remaining_secs = await security.get_gateway_status()
    return {'platform':odin.__platform__, 
     'level':level, 
     'remaining_seconds':remaining_secs}


@locks.timed_cache(5)
async def _get_ui_status() -> dict:
    try:
        service_mode_plus = await get_data_value("GUI_serviceModePlus") == "true"
    except Exception:
        service_mode_plus = False
        log.exception("Failed to read Service Mode Plus")

    try:
        if await is_fused():
            factory_mode_enabled = False
        else:
            factory_mode_enabled = await factory_mode()
    except Exception:
        factory_mode_enabled = False
        log.exception("Failed to read Factory Mode")

    return {'service_mode_plus':service_mode_plus, 
     'factory_mode':factory_mode_enabled}


async def _get_tab_status(page: Optional[str]) -> Optional[dict]:
    _TAB_TO_METHOD = {
     'systemchecks': None, 
     'actions': None, 
     'thermal': _get_thermal_status, 
     'factory': _get_factory_status}
    tab_method = _TAB_TO_METHOD.get(page)
    if tab_method is None:
        return
    else:
        return await tab_method()


async def _task_allowed(task_name: str) -> bool:
    all_tasks = await _get_service_jobs_tasks()
    all_tasks.update(await _get_action_tasks())
    return task_name in all_tasks or not await is_fused()


async def _get_service_jobs_tasks() -> Set[str]:
    global _service_jobs_tasks
    if _service_jobs_tasks is None:
        try:
            _service_jobs_tasks = await helpers.get_fused_jobs_tasks("service-jobs")
        except (FileNotFoundError, ValueError, json.JSONDecodeError):
            log.exception("Failed to load service-jobs")
            _service_jobs_tasks = set()

    return _service_jobs_tasks


async def _gtw_config_filter_matches(gtw_config_filter: dict) -> bool:
    if not isinstance(gtw_config_filter, dict) or len(gtw_config_filter) < 1:
        return True
    else:
        try:
            await gtw_config.assert_gtw_config_match(gtw_config_filter, hash_value=True)
        except (gtw_config.GatewayConfigKeyUndefined, gtw_config.GatewayConfigMismatch):
            return False
        except Exception:
            log.exception("Unexpected exception when checking gateway configs")

        return True


async def _get_action_tasks() -> Set[str]:
    task_status = await _get_action_task_status()
    return set(task_status.keys())


async def _get_action_task_status() -> dict:
    global _action_task_status
    if _action_task_status is None:
        service_actions_path = os.path.join(odin.get_metadata_path(), "service-actions.json")
        try:
            actions_to_gtw_config_filter = await filesystem.load_json(service_actions_path)
        except (FileNotFoundError, ValueError, json.JSONDecodeError):
            log.exception("Failed to load service-actions")
            actions_to_gtw_config_filter = dict()

        _action_task_status = dict()
        for t, gtw_config_filter in actions_to_gtw_config_filter.items():
            _action_task_status[t] = {'is_running':False,  'last_run_successful':None, 
             'is_applicable':await _gtw_config_filter_matches(gtw_config_filter)}

    return _action_task_status


def _update_task_running(task: str, is_running: bool):
    global _task_active
    _task_active = is_running
    try:
        _action_task_status[task]["is_running"] = is_running
    except KeyError:
        pass


def _update_task_success(task: str, success: bool):
    try:
        _action_task_status[task]["last_run_successful"] = success
    except KeyError:
        pass


def _task_is_active() -> bool:
    return _task_active


def includeme(app):
    app.router.add_get("/service/api/status", status)
    app.router.add_get("/service/api/taskinfo", taskinfo)
    app.router.add_post("/service/api/runtask", runtask)
    asset_directory = get_resource_path("service_ui")
    if os.path.exists(asset_directory):
        app.router.add_get("/service{tail:/?}", index)
        app.router.add_static("/service", asset_directory)
    else:
        log.warning("Service UI bundle cannot be found")

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/engine/plugins/service.pyc
