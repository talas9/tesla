# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/scripting/api.py
from architect import Node
from .api_definitions import get_node_classes_for_api
from .node_to_coro import node_to_coro
from .reference import make_run_reference
from odin.core.engine.messagebox import inbox
from odin.core.power import power_context
from odin.core.uds.context import tester_present_context, uds_node_lock_context
from odin.core.utils.metrics import MetricResult
from odin.core.utils.VCSEC_pb2 import FromVCSECMessage
OVERRIDEN_NODES = [
 (
  "messages.Listen", inbox.listening),
 (
  "vehiclecontrols.PowerContext", power_context),
 (
  "uds.UdsNodeLockContext", uds_node_lock_context),
 (
  "uds.UdsTesterPresentContext", tester_present_context)]

def make_public_api(parent: Node) -> type:

    class OdinPublicApi:

        class subnetwork:
            run_reference = make_run_reference(parent)

    add_node_classes_to_api(OdinPublicApi, parent)
    return OdinPublicApi


def add_node_classes_to_api(public_api: type, parent):
    from odin.core.power import interface
    setattr(public_api, "power_state_enum", interface.power_state_enum())
    setattr(public_api, "metric_result", MetricResult)
    setattr(public_api, "FromVCSECMessage", FromVCSECMessage)
    for class_name, kw in get_node_classes_for_api().items():
        group_class = ensure_group_class_exists(public_api, class_name)
        add_coro_to_group(parent, group_class, class_name, kw)


def ensure_group_class_exists(public_api: type, class_name: str):
    group_name = class_name.split(".")[0]
    if not hasattr(public_api, group_name):
        setattr(public_api, group_name, type(group_name, (object,), {}))
    return getattr(public_api, group_name)


def add_coro_to_group(parent, group_class, class_name, kw):
    coro_name = class_name_to_coro_name(class_name)
    for override_name, override_function in OVERRIDEN_NODES:
        if class_name == override_name:
            setattr(group_class, coro_name, override_function)
            break
    else:
        setattr(group_class, coro_name, node_to_coro(parent, class_name, **kw))


def class_name_to_coro_name(class_name: str) -> str:
    coro_name = class_name.split(".")[1]
    return camelcase_to_underscore(coro_name)


def camelcase_to_underscore(word: str) -> str:
    return "".join([next_letter(prev, curr, next_) for prev, curr, next_ in triples(word)])


def next_letter(prev, curr, next_):
    if is_start_of_word(prev, curr, next_):
        return "_" + curr.lower()
    else:
        return curr.lower()


def is_start_of_word(prev, curr, next_):
    if prev is None or next_ is None:
        return False
    else:
        return prev.isalpha() and curr.isalpha() and curr.isupper() and next_.isalpha() and not next_.isupper()


def triples(l: list) -> list:
    for i, current in enumerate(l):
        yield (
         get_index(l, i - 1), current, get_index(l, i + 1))


def get_index(l: list, i: int) -> object:
    if i < len(l):
        if i >= 0:
            return l[i]
    return

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/scripting/api.pyc
