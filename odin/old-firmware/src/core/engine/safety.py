# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/engine/safety.py
from typing import Optional
from typing import List
from aiohttp.web import HTTPPreconditionFailed
from odin.core import gateway
from odin.core.engine.task_metadata import get_metadata_for_task

async def check_command_safety(command: callable, request_context: dict) -> None:
    await run_safety_checks(request_context, getattr(command, "safety_checks", []))


async def run_safety_checks(request_context: dict, checks: List[callable]) -> None:
    if not checks:
        return
    safety_context = await make_safety_context(request_context)
    for check in checks:
        result = check(safety_context)
        if result:
            raise result


async def make_safety_context(request_context: dict) -> dict:
    metadata = await get_metadata_for_task(request_context["network_name"])
    return {'vehicle_state':await gateway.interface.get_vehicle_state_str(), 
     'allowed_vehicle_states':metadata["valid_states"]}


def vehicle_state_allowed(safety_context: dict) -> Optional[HTTPPreconditionFailed]:
    if safety_context["vehicle_state"] not in safety_context["allowed_vehicle_states"]:
        return HTTPPreconditionFailed(reason=(make_vehicle_state_reason(safety_context)))


def make_vehicle_state_reason(safety_context: dict) -> str:
    return "Current gear state {} is not allowed. Valid states: {}".format(safety_context["vehicle_state"], " ".join(safety_context["allowed_vehicle_states"]))

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/engine/safety.pyc
