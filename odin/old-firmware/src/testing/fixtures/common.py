# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/testing/fixtures/common.py
import contextlib, os, pytest
from attrdict import AttrDict
from mock import Mock
from odin.platforms.platform_switch import switch_platform_to

@pytest.fixture()
def mock_gateway():
    from odin.core import gateway

    @contextlib.contextmanager
    def _mock_gateway(*args, **kw):
        gtw = (gateway.testing.MockGateway)(*args, **kw)
        curr = gateway.interface
        gateway.interface = gtw
        yield gtw
        gateway.interface = curr

    return _mock_gateway


@pytest.fixture
def mock_node(model_s_config):
    from odin.core.uds.node import node_factory
    from odin.core import can
    node = node_factory("IC",
      bus=(can.Bus.ETH),
      request_message=(AttrDict({'bus_id':(can.Bus.ETH).value,  'message_id':1})),
      response_message=(AttrDict({'bus_id':(can.Bus.ETH).value,  'message_id':2})))
    return node


@pytest.fixture
def mock_node3(model_3_config):
    from odin.core.uds.node import node_factory
    from odin.core import can
    node = node_factory("VCLEFT",
      bus=(can.Bus.ETH),
      request_message=(AttrDict({'bus_id':(can.Bus.ETH).value,  'message_id':1})),
      response_message=(AttrDict({'bus_id':(can.Bus.ETH).value,  'message_id':2})))
    return node


@pytest.fixture()
def mock_frozen():
    import os, sys, odin
    curr_meipass = getattr(sys, "_MEIPASS", None)
    curr_frozen = getattr(sys, "frozen", None)
    setattr(sys, "_MEIPASS", os.path.dirname(odin.__file__))
    setattr(sys, "frozen", True)
    yield sys
    setattr(sys, "_MEIPASS", curr_meipass)
    setattr(sys, "frozen", curr_frozen)


@pytest.fixture()
def environment_config():
    switch_platform_to(os.environ.get("ODIN_PLATFORM", "model_3"))


@pytest.fixture
def option(option_keys: list, value):
    from odin.config import options
    orig_option = options
    for key in option_keys[:-1]:
        orig_option = orig_option[key]

    orig_value = orig_option[option_keys[-1]]
    orig_option[option_keys[-1]] = value
    yield
    orig_option[option_keys[-1]] = orig_value


@pytest.fixture
def onboard():
    from odin.config import options
    orig_option = options["core"]["onboard"]
    options["core"]["onboard"] = True
    yield
    options["core"]["onboard"] = orig_option


@pytest.fixture
def offboard():
    from odin.config import options
    orig_option = options["core"]["onboard"]
    options["core"]["onboard"] = False
    yield
    options["core"]["onboard"] = orig_option


@pytest.fixture
def mock_callable(side_effect_value):
    return Mock(side_effect=(side_effect_value if isinstance(side_effect_value, Exception) else [
     side_effect_value]))


@pytest.fixture
def coro_side_effect(mock_callable):

    async def side_effect(*args, **kw):
        return mock_callable(*args, **kw)

    return side_effect

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/testing/fixtures/common.pyc
