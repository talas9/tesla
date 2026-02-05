# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/scripting/node_to_coro.py
from typing import Coroutine
from architect import Node
from architect.workflows.node_factory import NodeFactory
from architect.core.ops.signal import SignalOp
from .input_output_validate import is_output_name_allowed

def node_to_coro(parent, node_class_name, posargs=None):

    async def coro_wrapper(*args, **kw):
        kw = parse_args(args, kw, posargs)
        node = NodeFactory().create(node_class_name)
        name = "node_to_coro_" + node_class_name
        parent._children[name] = node
        set_node_inputs(node, kw)
        replace_node_signals(node)
        await get_plug_to_await(node)()
        return get_output_values(node)

    return coro_wrapper


def parse_args(args, kw, posargs):
    if not posargs:
        return kw
    else:
        if len(args) != len(posargs):
            raise ValueError("Coro expects {} positional arguments but got {}.".format(len(posargs), len(args)))
        kw = kw.copy()
        kw.update(dict(zip(posargs, args)))
        return kw


def set_node_inputs(node, kw):
    for input_name, input_value in kw.items():
        if node._registered_name == "networks.SetOutput":
            if input_name == "key":
                is_output_name_allowed(input_value)
                node.update_output_plug_name(old_name=None, new_name=input_value)
                continue
        getattr(node, input_name).value = input_value


def replace_node_signals(node):
    for name, _ in node._signature.signals():
        node._children[name] = MockSignal()


class MockSignal(SignalOp):

    def __init__(self, *args, **kw):
        (super().__init__)(*args, **kw)
        self.value = False

    async def _run(self, *args, **kw):
        self.value = True


def get_plug_to_await(node):
    slots = get_slots(node)
    if len(slots) == 1:
        return slots[0][1]
    if len(slots) > 1:
        raise RuntimeError("Node class has too many slots to be used as a coroutine.")
    outputs = get_outputs(node)
    if len(outputs) == 1:
        return outputs[0][1]
    raise RuntimeError("Node must have exactly one slot or one output to be used as a coroutine.")


def get_slots(node):
    return node._signature.slots()


def get_outputs(node):
    return node._signature.outputs()


def get_signals(node):
    return node._signature.signals()


def get_output_values(node):
    values = {}
    for name, output in get_outputs(node) + get_signals(node):
        values[name] = output.value

    return values

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/scripting/node_to_coro.pyc
