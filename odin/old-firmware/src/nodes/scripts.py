# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/nodes/scripts.py
import string
from architect import slot
from architect import Node
from architect.nodes import Signal
from architect.nodes.networks import NetworkPlugNode
from architect.nodes.control import ErrorHandlingNode
from architect.core.attr import Attr
from architect.core.ops.input import Input
from architect.core.ops.output import Output
from architect.core.ops.multi import Multi
from architect import Datatype
from ..core.cid.interface import is_fused
from ..scripting import safe_run_code
from ..scripting import safe_run_script
from ..scripting.input_output_validate import walk_and_validate, RESERVED_OUTPUT_NAMES
_jail_patch = None

class ScriptName(Datatype):
    accepts = [
     str]
    outputs = str

    def typecast_value(self, value):
        return value


class PythonCode(Datatype):
    accepts = [
     str]
    outputs = str

    def typecast_value(self, value):
        return value


class ScriptBase:
    script_name = Attr("ScriptName")
    _code = Attr("PythonCode")
    inputs = Multi(Input)
    outputs = Multi(Output)
    exit_code = Output("Int")
    done = Signal()


class ScriptTest(ScriptBase, NetworkPlugNode, ErrorHandlingNode):

    @slot(hidden=True)
    async def run(self):
        script_inputs = await {script_input_op._name: await script_input_op() for script_input_op in self.inputs}
        walk_and_validate(script_inputs)
        if self._code:
            await assert_unfused()
            result = await safe_run_code(self, (self._code), inputs=script_inputs, name=(self.script_name))
        else:
            result = await safe_run_script(self, self.script_name, script_inputs)
        self._reset_error()
        if self._output_plug:
            self._output_plug.value = result
        self.exit_code = result
        await self.done()

    @Node.on_set_parent
    def update_plugs_on_parent(self, old_parent, new_parent):
        if new_parent is not None:
            self._output_plug = self._plugs.add_output(new_parent,
              "exit_code", datatype="Int")
        if old_parent is not None:
            self._plugs.remove_output(old_parent, self._output_plug._name)


class RunScriptTest(ScriptTest):

    @Node.on_set_parent
    def update_plugs_on_parent(self, old_parent, new_parent):
        if new_parent is not None:
            self._output_plug = self._plugs.add_output(new_parent,
              "exit_code", datatype="Int")
            self._run_slot = self._plugs.add_slot(new_parent,
              name="run", func=(self.run))
        if old_parent is not None:
            self._plugs.remove_output(old_parent, self._output_plug._name)
            self._plugs.remove_slot(old_parent, self._run_slot._name)


async def assert_unfused():
    if await is_fused():
        raise RuntimeError("Script Nodes may only be run on un-fused vehicles.")

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/nodes/scripts.pyc
