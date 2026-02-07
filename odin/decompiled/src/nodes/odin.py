# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/nodes/odin.py
import asyncio, logging
from architect import Output
from architect import Node
from architect import Input
from architect import Signal
from architect import slot
from architect import output
from odin import config
from odin.config import options
from odin.core import cid
from odin.core.engine.handlers import commands
from odin.services.data_upload import data_upload
from odin.services.data_upload import request_history
from odin.platforms.platform_switch import switch_platform_to
log = logging.getLogger(__name__)

class CancelAllTasks(Node):
    status = Output("Dict")
    done = Signal()

    @slot()
    async def cancel(self):
        ctxt = self._root()._context()
        execution_options = ctxt.get("execution_options", {})
        self.status.output = await commands.cancel_all_requests(execution_options)
        await self.done()


class CancelTask(Node):
    request_id = Input("String")
    status = Output("Dict")
    done = Signal()

    @slot()
    async def cancel(self):
        request_id = await self.request_id()
        ctxt = self._root()._context()
        execution_options = ctxt.get("execution_options", {})
        self.status.value = await commands.cancel_request(execution_options, request_id)
        await self.done()


class CancelTaskByName(Node):
    name = Input("String")
    status = Output("Dict")
    done = Signal()

    @slot()
    async def cancel(self):
        name = await self.name()
        ctxt = self._root()._context()
        execution_options = ctxt.get("execution_options", {})
        self.status.value = await commands.cancel_by_name(execution_options, name)
        await self.done()


class ChangeConfig(Node):
    new_config = Input("Dict")
    done = Signal()

    @slot()
    async def run(self):
        global options
        if await cid.interface.is_fused():
            raise NotImplementedError("")
        new_config = await self.new_config()
        options = config.merge_dict(options, new_config)
        await self.done()


class Configure(Node):
    model_enums = [(p, p.replace("_", " ").title()) for p in set(options["core"]["supported_platforms"].values())]
    platform = Input("String", enum=model_enums)
    finished = Signal()

    @slot()
    async def configure(self):
        platform = await self.platform()
        switch_platform_to(platform)
        await self.finished()


class StartDataUploadService(Node):
    done = Signal()

    @slot()
    async def enable(self):
        asyncio.ensure_future(data_upload.start_service())
        await self.done()


class GetDataUploadHistory(Node):

    @output("Dict")
    async def history(self):
        return request_history.get_history()


class GetMostRecentDataUploadHistory(Node):

    @output("Dict")
    async def recent(self):
        return request_history.get_most_recent_from_history()


class ClearDataUploadHistory(Node):

    @output("Bool")
    async def clear(self):
        return request_history.clear_history()


class WithTransport(Node):
    transport_name = Input("String", enum=[
     ('gateway', 'Gateway')])
    bus_id = Input("String", enum=[
     ('default', 'default')])
    run = Signal()

    @slot()
    async def activate(self):
        from odin.core.uds import GatewayTransport
        if await self.transport_name() == "gateway":
            transport_cls = GatewayTransport
        else:
            transport_cls = GatewayTransport
        transport = transport_cls()
        transport.enable()
        self.run()

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/nodes/odin.pyc
