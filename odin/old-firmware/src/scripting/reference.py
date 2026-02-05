# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/scripting/reference.py
from asyncio import gather
import types
from architect import make_network
from architect import Node
from architect.core.network import Network
from architect.core.exceptions import CONTROL_EXCEPTIONS
from odin.platforms import architect_client_port

def make_run_reference(parent: Node) -> callable:

    async def run_reference(name, **kw):
        subnetwork = make_network()
        parent._children["subnetwork_{}".format(name)] = subnetwork
        await load_network_onto(name, subnetwork)
        set_network_inputs(subnetwork, kw)
        mock_network_signals(subnetwork)
        await run_slots(subnetwork)
        outputs = await evaluate_outputs(subnetwork)
        return ({**get_network_signals(subnetwork), **outputs})

    return run_reference


async def load_network_onto(name: str, parent: Network):
    client = architect_client_port()
    await client.asset_manager.load(name, network=parent)


def set_network_inputs(network: Network, kw: dict):
    for key, value in kw.items():
        network.inputs[key].value = value


def mock_network_signals(network: Network):
    for signal in network.signals:
        signal.value = False
        signal._run = types.MethodType(make_mock_run(), signal)


def make_mock_run() -> callable:

    async def run(self, *args, **kw):
        self.value = True

    return run


async def run_slots(network: Node):
    try:
        await gather(*[slot() for slot in network.slots])
    except CONTROL_EXCEPTIONS:
        pass


async def evaluate_outputs(network: Node):
    futures = [output() for output in network.outputs]
    names = [output._name for output in network.outputs]
    try:
        results = await gather(*futures)
        return dict(zip(names, results))
    except CONTROL_EXCEPTIONS:
        return {}


def get_network_signals(network: Network) -> dict:
    return {signal._name: signal.value for signal in network.signals}

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/scripting/reference.pyc
