# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/nodes/reporting.py
import asyncio, datetime, logging
from odin.core import uds
from architect.core.node import Node
from architect.core.ops.input import Input
from architect.core.ops.output import output
from architect.core.ops.signal import Signal
from architect.core.ops.slot import slot
from architect.nodes.networks import NetworkPlugNode
from ..core.utils import metrics
from odin.platforms import common
log = logging.getLogger(__name__)
RESULT_CODE_ENUM = [(k.value, k.name.lower()) for k in metrics.MetricResult.__members__.values()]

class CaptureMetric(Node):
    metric_name = Input("String")
    ecu_name = Input("String", enum_func=(lambda: [), default=None)
    critical = Input("Bool", default=False)
    value = Input()
    result_code = Input("Int", enum=RESULT_CODE_ENUM, default=(metrics.MetricResult.Skip))
    expected_value = Input()
    low_limit = Input("Number")
    high_limit = Input("Number")
    metadata = Input("Dict")
    done = Signal()

    @Node.on_set_parent
    def add_network_plug(self, old_parent, new_parent):
        if new_parent is not None:
            self._plug = new_parent._root().outputs.add_child(name="metrics", default=[])
        elif old_parent is not None:
            old_parent._root().outputs.remove_child(self._plug._name)

    @slot(run_local=True)
    async def capture(self):
        capture_time = datetime.datetime.now()
        self._plug.value = self._plug.value or []
        metric = metrics.create_metric(name=(await self.metric_name()),
          value=(await self.value()),
          capture_time=capture_time,
          ecu_name=(await self.ecu_name()),
          critical=(await self.critical()),
          expected_value=(await self.expected_value()),
          result=(await self.result_code()),
          low_limit=(await self.low_limit()),
          high_limit=(await self.high_limit()),
          metadata=(await self.metadata()))
        self._plug.value.append(metric)
        await self.done()


class CaptureConnectorInfoLookup(Node):
    exit_code = Input("Int")
    file_name = Input("String")
    done = Signal()

    @Node.on_set_parent
    def add_network_plug(self, old_parent, new_parent):
        if new_parent is not None:
            self._plug = new_parent._root().outputs.add_child(name="metrics", default=[])
        elif old_parent is not None:
            old_parent._root().outputs.remove_child(self._plug)

    @slot(run_local=True)
    async def capture(self):
        capture_time = datetime.datetime.now()
        self._plug.value = self._plug.value or []
        exit_code, file_name = await asyncio.gather(self.exit_code(), self.file_name())
        result = metrics.MetricResult.Skip
        if exit_code is not None:
            result = metrics.MetricResult.Fail if exit_code != 0 else metrics.MetricResult.Pass
        try:
            data = common.connector_info[file_name][exit_code]
        except KeyError:
            log.error("Failed getting connector info for exit code {} from {}".format(exit_code, file_name))
            data = {}

        metric = metrics.create_connector_info(capture_time=capture_time,
          error_description=(data.get("error_description")),
          connectors=(data.get("connectors")),
          result=result)
        self._plug.value.append(metric)
        await self.done()


class BoolToResultCode(Node):
    input = Input("Bool")

    @output("Int")
    async def result_code(self):
        if await self.input():
            return metrics.MetricResult.Pass
        else:
            return metrics.MetricResult.Fail


class DebugPrint(Node):
    data = Input("String")

    @slot()
    async def run(self):
        self._plug.value = self._plug.value or ""
        print_data = await self.data()
        log.debug(print_data)
        self._plug.value += "{}\n".format(print_data)

    @Node.on_set_parent
    def add_network_plug(self, old_parent, new_parent):
        if new_parent is not None:
            if "debug_lines" not in new_parent._root().outputs._children:
                new_parent._root().outputs.add_child(name="debug_lines", value="\n")
            self._plug = new_parent._root().outputs._children["debug_lines"]
        elif old_parent is not None:
            old_parent._root().outputs.remove_child(self._plug)


class FileOutput(NetworkPlugNode):
    file_name = Input("String")
    encoding = Input("String")
    mime_type = Input("String")
    data = Input()
    finished = Signal()

    @Node.on_set_parent
    def add_output_plug(self, old_parent, new_parent):
        if new_parent is not None:
            self._output_plug = new_parent._root().outputs.add_child(name="file_outputs", default=[])
        elif old_parent is not None:
            old_parent._root().outputs.remove_child(self._output_plug._name)

    @slot()
    async def set(self):
        file_name, encoding, mime_type, data = await asyncio.gather(self.file_name(), self.encoding(), self.mime_type(), self.data())
        self._output_plug.value = self._output_plug.value or []
        self._output_plug.value.append({
         'file_name': file_name, 
         'encoding': encoding, 
         'mime_type': mime_type, 
         'data': data})
        await self.finished()

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/nodes/reporting.pyc
