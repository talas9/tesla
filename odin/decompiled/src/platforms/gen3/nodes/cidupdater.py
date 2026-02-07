# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/platforms/gen3/nodes/cidupdater.py
import asyncio
from architect.core.node import Node
from architect.core.ops.input import Input
from architect.core.ops.output import Output
from architect.core.ops.signal import Signal
from architect.core.ops.slot import slot
from odin.core.cid import updater
from ..enum import UpdaterCommandType
COMMAND_TYPE_ENUM = [(cmd_type.name, cmd_type.name) for cmd_type in UpdaterCommandType]
_ROUTINE_DATA = {(UpdaterCommandType.FACTORY): {'command':"m3-factory-deploy", 
                                'status':"success", 
                                'tag':"fwhashpicker"}, 
 
 (UpdaterCommandType.SERVICE): {'command':"service-redeploy", 
                                'status':"redeploy", 
                                'tag':"fw-m3-service-redeploy"}, 
 
 (UpdaterCommandType.CANREDEPLOY): {'command':"can-redeploy", 
                                    'status':"started", 
                                    'tag':None}}

class FirmwareUpdate(Node):
    command_type = Input("String", enum=COMMAND_TYPE_ENUM, default="FACTORY")
    hwidacq_component_list = Input("List")
    timeout = Input("Int", default=300)
    update_component_list = Input("List")
    vehicle_job_id = Input("String")
    results = Output("Dict")
    done = Signal()

    @slot()
    async def run(self):
        command_type_str, hwidacq_component_list, timeout, update_component_list, vehicle_job_id = await asyncio.gather(self.command_type(), self.hwidacq_component_list(), self.timeout(), self.update_component_list(), self.vehicle_job_id())
        command_type = UpdaterCommandType(command_type_str)
        data = _ROUTINE_DATA[command_type]
        params = dict()
        if command_type == UpdaterCommandType.FACTORY:
            params["hwidacq_component_list"] = ",".join(hwidacq_component_list)
            params["update_component_list"] = ",".join(update_component_list)
        elif command_type == UpdaterCommandType.SERVICE:
            params["firmware_download_url"] = "empty"
            params["hwidacq_component_list"] = "^~@"
            params["modules_to_skip"] = ",".join(["ape", "192.168.90.105"])
            params["verify_in_chunks"] = "false"
        elif command_type == UpdaterCommandType.CANREDEPLOY:
            pass
        else:
            raise RuntimeError("Unknown command type: {}".format(command_type_str))
        if data["tag"] is not None:
            if not vehicle_job_id:
                vehicle_job_id = await updater.create_fw_redeploy_job(data["tag"])
            if vehicle_job_id:
                params["vehicle_job_status_url"] = updater.get_job_status_url(int(vehicle_job_id))
        results = await updater.fw_update((data["command"]), handshake_params=params, timeout=timeout)
        updater.raise_for_status(command_type_str, results, data["status"])
        self.results.value = results
        await self.done()

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/platforms/gen3/nodes/cidupdater.pyc
