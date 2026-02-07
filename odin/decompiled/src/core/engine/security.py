# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/engine/security.py
import logging
from typing import List, Optional
from aiohttp.web import HTTPForbidden
from aiohttp.web import HTTPPreconditionFailed
from aiohttp.web import HTTPException
from odin.core.engine.security_context import SecurityContext
log = logging.getLogger(__name__)

async def authorize(security_context: SecurityContext):
    command = security_context["command"]
    if hasattr(command, "security_checks"):
        if command.security_checks:
            for check in command.security_checks:
                security_exception = check(security_context)
                if isinstance(security_exception, HTTPException):
                    raise security_exception


def authenticated_permission(security_context: SecurityContext) -> Optional[HTTPForbidden]:
    return _check_permissions(["authenticated"], security_context)


def lock_permission(security_context: SecurityContext) -> Optional[HTTPForbidden]:
    return _check_permissions(["tbx-engineering", "tbx-manufacturing"], security_context)


def internal_permission(security_context: SecurityContext) -> Optional[HTTPForbidden]:
    return _check_permissions(["tbx-internal"], security_context)


def _check_permissions(permissions: List, security_context) -> Optional[HTTPForbidden]:
    if permissions:
        if not _principals_overlap_permissions(permissions, security_context["principals"]):
            log.debug("principals={} command_permission={}".format(security_context["principals"], permissions))
            return HTTPForbidden(reason="You do not have command permission to perform this task")


def _principals_overlap_permissions(permissions: List, principals: List) -> bool:
    return bool(set(permissions) & set(principals))


def lock_check(security_context: SecurityContext) -> Optional[HTTPForbidden]:
    return _unfused(security_context)


def _unfused(security_context: SecurityContext) -> Optional[HTTPForbidden]:
    if security_context["fused"]:
        return HTTPPreconditionFailed(reason="You do not have permission to perform this task on a fused car")


def _perform_checks(security_context: SecurityContext, checks: List) -> Optional[HTTPException]:
    for check in checks:
        result = check(security_context)
        if isinstance(result, HTTPException):
            return result


def execute_check(security_context: SecurityContext) -> Optional[HTTPException]:
    checks = [
     _execute_lib_network_allowed,
     _execute_network_allowed,
     _execute_remote_network_allowed]
    return _perform_checks(security_context, checks)


def post_fusing_execute_check(security_context: SecurityContext) -> Optional[HTTPException]:
    if not security_context["network_post_fusing_allowed"]:
        return HTTPForbidden(reason="Task is not an allowed post-fusing task")


def _execute_lib_network_allowed(security_context: SecurityContext) -> Optional[HTTPForbidden]:
    if security_context["task_network"] or not security_context["fused"] and _principals_overlap_permissions(["tbx-manufacturing"], security_context["principals"]):
        return
    else:
        return HTTPForbidden(reason="You do not have execution permission to perform this lib network")


def _execute_network_allowed(security_context: SecurityContext) -> Optional[HTTPForbidden]:
    network_perm = []
    local_permissions = security_context["network_permissions"]
    if isinstance(local_permissions, list):
        network_perm.extend(local_permissions)
    remote_permissions = security_context["network_remote_execution_permissions"]
    if isinstance(remote_permissions, list):
        network_perm.extend(remote_permissions)
    if network_perm:
        if not _principals_overlap_permissions(network_perm, security_context["principals"]):
            return HTTPForbidden(reason="You do not have network permission to perform this task")


def _execute_remote_network_allowed(security_context: SecurityContext) -> Optional[HTTPForbidden]:
    if not security_context["fused"] or not security_context["remote_request"]:
        return
    if not _principals_overlap_permissions(security_context["network_remote_execution_permissions"], security_context["principals"]):
        return HTTPForbidden(reason="You do not have remote execution permission to perform this task")


def evaluate_check(security_context: SecurityContext) -> Optional[HTTPForbidden]:
    if _principals_overlap_permissions(["tbx-engineering", "tbx-manufacturing"], security_context["principals"]):
        if not security_context["fused"]:
            return
    return HTTPForbidden(reason="You do not have permission to evaluate")


def orchestrator_check(security_context: SecurityContext) -> Optional[HTTPForbidden]:
    return _unfused(security_context)


def engineering_check(security_context: SecurityContext) -> Optional[HTTPForbidden]:
    if not security_context["fused"] or _principals_overlap_permissions(["tbx-engineering"], security_context["principals"]):
        return
    else:
        return HTTPForbidden(reason="You do not have permission for this task")


def local_engineering_check(security_context: SecurityContext) -> Optional[HTTPForbidden]:
    if security_context["remote_request"]:
        return HTTPForbidden(reason="This task can only be performed with local connection")
    else:
        return engineering_check(security_context)

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/engine/security.pyc
