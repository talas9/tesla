# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/nodes/uds.py
__authors__ = [
 "Ines Swenson"]
__author__ = ",".join(__authors__)
__email__ = "inkoch@teslamotors.com"
__copyright__ = "Copyright Tesla Motors Inc. 2017"
import asyncio, logging
from typing import List
from architect import Node, Input, Output, Signal, slot, output
from odin.core import uds
from odin.core.uds import tester_present_context, uds_node_lock_context
from odin.core.uds.datatypes import DTCMask
log = logging.getLogger(__name__)
RESET_TYPE = [(r.name, r.name) for r in uds.Reset]
SECURITY_LEVEL = [(r.name, r.name) for r in uds.SecurityLevel]
UDS_CONTROL_TYPES = [(m.name, m.name) for m in uds.IoControl]
UDS_SESSION_TYPES = [(m.name, m.name) for m in uds.SessionType]
UDS_ROUTINE_TYPES = [(m.name, m.name) for m in uds.RoutineControl]
DTC_MASK = [(r.name, r.name) for r in iter(uds.DTCMask)]
NODE_NAMES_FUNC = lambda: [
 ('', '')] + [

class UdsClearDtcs(Node):
    node_name = Input("String", enum_func=NODE_NAMES_FUNC)
    dtc_mask = Input("String", default="NONE", enum=([('NONE', 'NONE')] + DTC_MASK))
    done = Signal()

    @slot()
    async def run(self) -> None:
        node_name, dtc_mask = await asyncio.gather(self.node_name(), self.dtc_mask())
        node = uds.nodes[node_name]
        await uds.clear_diagnostic_information(node)
        await self.done()


class UdsControlDtc(Node):
    node_name = Input("String", enum_func=NODE_NAMES_FUNC)
    setting_type = Input("Int")
    input_payload = Input("Bytes")
    response_required = Input("Bool")
    done = Signal()

    @slot()
    async def run(self) -> None:
        node_name, setting_type, input_payload, response_required = await asyncio.gather(self.node_name(), self.setting_type(), self.input_payload(), self.response_required())
        node = uds.nodes[node_name]
        await uds.control_dtc_setting(node=node,
          setting_type=setting_type,
          input_payload=input_payload,
          response_required=response_required)
        await self.done()


class UdsDTCMaskRepr(Node):
    dtc_mask_value = Input("Int")

    @output("String")
    async def dtc_mask_repr(self) -> str:
        return repr(DTCMask(await self.dtc_mask_value()))


class UdsDiagnosticSession(Node):
    node_name = Input("String", enum_func=NODE_NAMES_FUNC)
    session_type = Input("String", default="DEFAULT_SESSION", enum=UDS_SESSION_TYPES)
    response_required = Input("Bool", default=False)
    done = Signal()

    @slot()
    async def run(self) -> None:
        node_name, session_type, response_required = await asyncio.gather(self.node_name(), self.session_type(), self.response_required())
        node = uds.nodes[node_name]
        session_type = uds.SessionType[session_type]
        await uds.diagnostic_session(node=node,
          session_type=session_type,
          response_required=response_required)
        await self.done()


class UdsEcuReset(Node):
    node_name = Input("String", enum_func=NODE_NAMES_FUNC)
    reset_type = Input("String", default="SOFT_RESET", enum=RESET_TYPE)
    response_required = Input("Bool", default=False)
    done = Signal()

    @slot()
    async def run(self) -> None:
        node_name, reset_type, response_required = await asyncio.gather(self.node_name(), self.reset_type(), self.response_required())
        node = uds.nodes[node_name]
        reset_type = uds.Reset[reset_type]
        await uds.ecu_reset(node, reset_type=reset_type, response_required=response_required)
        await self.done()


class UdsIOControl(Node):
    node_name = Input("String", enum_func=NODE_NAMES_FUNC)
    control_id = Input("Hex")
    control_type = Input("String", enum=UDS_CONTROL_TYPES)
    input_payload = Input("Bytes")
    output_length = Input("Int", default=1024)
    output_payload = Output("Bytes")
    done = Signal()

    @slot()
    async def run(self) -> None:
        node_name, control_id, control_type, input_payload, output_length = await asyncio.gather(self.node_name(), self.control_id(), self.control_type(), self.input_payload(), self.output_length())
        node = uds.nodes[node_name]
        control_type = uds.IoControl[control_type]
        control_result = await uds.io_control(node=node,
          control_id=control_id,
          control_type=control_type,
          input_payload=input_payload,
          output_length=output_length)
        self.output_payload.value = control_result
        await self.done()


class UdsNodeLockContext(Node):
    node_name = Input("String", enum_func=NODE_NAMES_FUNC)
    body = Signal()
    done = Signal()

    @slot()
    async def run(self) -> None:
        async with uds_node_lock_context(node_name=node_name):
            await self.body()
        await self.done()


class UdsNodeInfo(Node):
    node_name = Input("String", enum_func=NODE_NAMES_FUNC)

    @output("String")
    async def bus_name(self) -> str:
        node_name = await self.node_name()
        node = uds.nodes[node_name]
        return node.bus.name

    @output("String")
    async def boot_message(self) -> str:
        node_name = await self.node_name()
        node = uds.nodes[node_name]
        return node.boot_message_name

    @output("String")
    async def request_message(self) -> str:
        node_name = await self.node_name()
        node = uds.nodes[node_name]
        return node.request_message_name

    @output("String")
    async def response_message(self) -> str:
        node_name = await self.node_name()
        node = uds.nodes[node_name]
        return node.response_message_name


class UdsNodes(Node):

    @output("List")
    async def node_names(self) -> List[str]:
        return NODE_NAMES_FUNC()


class UdsReadData(Node):
    node_name = Input("String", enum_func=NODE_NAMES_FUNC)
    data_id = Input("Hex")
    output_length = Input("Int", default=1024)
    output_payload = Output("Bytes")
    done = Signal()

    @slot()
    async def run(self) -> None:
        node_name, data_id, output_length = await asyncio.gather(self.node_name(), self.data_id(), self.output_length())
        node = uds.nodes[node_name]
        output = await uds.read_data_by_id(node=node,
          data_id=data_id,
          output_length=output_length)
        self.output_payload.value = output
        await self.done()


class UdsReadDtcs(Node):
    node_name = Input("String", enum_func=NODE_NAMES_FUNC)
    dtc_mask = Input("Hex", default=1)
    output_length = Input("Int", default=1024)
    dtcs = Output("Dict")
    done = Signal()

    @slot()
    async def run(self) -> None:
        node_name, dtc_mask, output_length = await asyncio.gather(self.node_name(), self.dtc_mask(), self.output_length())
        node = uds.nodes[node_name]
        dtcs = await uds.read_dtcs(node=node, dtc_mask=dtc_mask)
        self.dtcs.value = dtcs
        await self.done()


class UdsRoutineControl(Node):
    node_name = Input("String", enum_func=NODE_NAMES_FUNC)
    routine_id = Input("Hex")
    routine_type = Input("String", enum=[(m.name, m.name) for m in uds.RoutineControl])
    input_payload = Input("Bytes", default=b'')
    output_length = Input("Int", default=1024)
    output_payload = Output("Bytes")
    done = Signal()

    @slot()
    async def run(self) -> None:
        node_name, routine_id, routine_type, input_payload, output_length = await asyncio.gather(self.node_name(), self.routine_id(), self.routine_type(), self.input_payload(), self.output_length())
        node = uds.nodes[node_name]
        routine_type = uds.RoutineControl[routine_type]
        output = await uds.routine_control(node,
          routine_id=routine_id,
          routine_type=routine_type,
          input_payload=input_payload,
          output_length=output_length)
        self.output_payload.value = output
        await self.done()


class UdsReadMemory(Node):
    node_name = Input("String", enum_func=NODE_NAMES_FUNC)
    memory_address = Input("Hex")
    memory_size = Input("Int")
    output_length = Input("Int")
    output_payload = Output("Bytes")
    done = Signal()

    @slot()
    async def run(self) -> None:
        node_name, memory_address, memory_size, output_length = await asyncio.gather(self.node_name(), self.memory_address(), self.memory_size(), self.output_length())
        node = uds.nodes[node_name]
        output = await uds.read_memory_by_address(node=node,
          memory_address=memory_address,
          memory_size=memory_size)
        self.output_payload.value = output
        await self.done()


class UdsSecurityAccess(Node):
    node_name = Input("String", enum_func=NODE_NAMES_FUNC)
    security_level = Input("String", default="LOCKED", enum=SECURITY_LEVEL)
    done = Signal()

    @slot()
    async def run(self) -> None:
        node_name, security_level = await asyncio.gather(self.node_name(), self.security_level())
        node = uds.nodes[node_name]
        security_level = uds.SecurityLevel[security_level]
        await uds.security_access(node=node,
          security_level=security_level)
        await self.done()


class UdsTesterPresent(Node):
    node_name = Input("String", enum_func=NODE_NAMES_FUNC)
    response_required = Input("Bool", default=True)
    done = Signal()

    @slot()
    async def run(self) -> None:
        node_name, response_required = await asyncio.gather(self.node_name(), self.response_required())
        node_name = uds.nodes[node_name]
        await uds.tester_present(node_name, response_required=response_required)
        await self.done()


class UdsTesterPresentContext(Node):
    interval = Input("Float", default=0.1)
    node_name = Input("String", enum_func=NODE_NAMES_FUNC)
    body = Signal()
    done = Signal()

    @slot()
    async def run(self) -> None:
        interval, node_name = await asyncio.gather(self.interval(), self.node_name())
        async with tester_present_context(node_name, interval):
            await self.body()
        await self.done()


class UdsWriteData(Node):
    node_name = Input("String", enum_func=NODE_NAMES_FUNC)
    data_id = Input("Hex")
    input_payload = Input("Bytes")
    done = Signal()

    @slot()
    async def run(self) -> None:
        node_name, data_id, input_payload = await asyncio.gather(self.node_name(), self.data_id(), self.input_payload())
        node_name = uds.nodes[node_name]
        await uds.write_data_by_id(node_name, data_id, input_payload)
        await self.done()


class UdsWriteMemory(Node):
    node_name = Input("String", enum_func=NODE_NAMES_FUNC)
    memory_address = Input("Hex")
    input_payload = Input("Bytes")
    done = Signal()

    @slot()
    async def run(self) -> None:
        node_name, memory_address, input_payload = await asyncio.gather(self.node_name(), self.memory_address(), self.input_payload())
        node_name = uds.nodes[node_name]
        await uds.write_memory_by_address(node_name, memory_address, input_payload)
        await self.done()

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/nodes/uds.pyc
