# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/engine/security_context.py
import asyncio, logging
from typing import List
import odin
from odin.core.cid import interface
from odin.core.engine.task_metadata import get_metadata_for_task
log = logging.getLogger(__name__)

class SecurityContext(dict):

    def __init__(self, *args, **kw):
        self._SecurityContext__read_only = False
        (super().__init__)(*args, **kw)
        self._SecurityContext__read_only = True

    def __setitem__(self, key, value):
        if self._SecurityContext__read_only:
            raise RuntimeError("SecurityContext is read-only.")
        super().__setitem__(key, value)


async def make_security_context(request_context, command, vehicle_context=None, user_context=None):
    return SecurityContext({'command':command,  'platform':odin.__platform__} if not _require_authorization(command) else await _gather_request_and_vehicle_context(request_context,
      command, vehicle_context=vehicle_context, user_context=user_context))


def _require_authorization(command: callable) -> bool:
    return hasattr(command, "security_checks") and bool(command.security_checks)


async def _gather_request_and_vehicle_context(request_context, command, vehicle_context=None, user_context=None):
    is_execute = True if command.__name__.endswith("execute") else False
    is_fused = await safe_is_fused()
    return ({**{'command':command, 
     'platform':odin.__platform__, 
     'remote_request':request_context.get("remote_request")}, **await make_network_context(request_context["network_name"], is_execute), **vehicle_context or await make_vehicle_context(is_fused), **user_context or await make_user_context(request_context,
      is_fused=is_fused)})


async def make_network_context(network_name: str, is_execute: bool=True) -> dict:
    is_task = name_is_task(network_name)
    if not is_execute or not network_name:
        return {'network_permissions':[],  'network_remote_execution_permissions':[],  'task_network':is_task, 
         'network_post_fusing_allowed':False}
    else:
        meta = await get_metadata_for_task(network_name)
        return {'network_permissions':meta["principals"], 
         'network_remote_execution_permissions':meta["remote_execution_permissions"], 
         'task_network':is_task, 
         'network_post_fusing_allowed':meta["post_fusing_allowed"]}


async def make_user_context(request_context: dict, is_fused: bool=None) -> dict:
    is_fused = is_fused if is_fused is not None else await safe_is_fused()
    return {"principals": (_get_principals_from_token(request_context, is_fused))}


def name_is_task(network_name):
    return "tasks" in network_name.split("/")


async def make_vehicle_context(is_fused: bool=None) -> dict:
    return {"fused": (is_fused if is_fused is not None else await safe_is_fused())}


async def safe_is_fused() -> bool:
    try:
        return await interface.is_fused()
    except asyncio.TimeoutError:
        log.error("Failed to read fused state. Security Context is set as fused")
        return True


def _get_principals_from_token(request_context: dict, is_fused: bool) -> List[str]:
    principals = request_context.get("tokenv2", {}).get("principals") or []
    if is_fused:
        return principals
    else:
        return principals + ["authenticated", "tbx-manufacturing", "tbx-internal"]

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/engine/security_context.pyc
