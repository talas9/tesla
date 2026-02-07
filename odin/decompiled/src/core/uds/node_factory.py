# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/uds/node_factory.py
import re
from attrdict import AttrDict
from .node import Node

def node_factory(library: AttrDict) -> AttrDict:
    request_re = re.compile("^UDS_([a-zA-Z0-9]+)(Request)$")
    response_re = re.compile("^([a-zA-Z0-9]+)_uds(Response)$")
    boot_re = re.compile("^([a-zA-Z0-9]+)_(boot)ID$")
    nodes = AttrDict()
    for msg_name, msgs in library.messages.items():
        req_match = request_re.match(msg_name)
        resp_match = response_re.match(msg_name)
        boot_match = boot_re.match(msg_name)
        if req_match or resp_match or boot_match:
            for bus_name, bus_msg in msgs.items():
                msg_nodes = bus_msg["senders"] if resp_match or boot_match else (set.union)(*[set(sig["receivers"]) for sig_name, sig in bus_msg["signals"].items()])
                for node_name in msg_nodes:
                    node_name = node_name.upper()
                    node = nodes.get(node_name, Node(name=node_name))
                    if req_match:
                        node.request_message_name = msg_name
                    elif resp_match:
                        node.response_message_name = msg_name
                    else:
                        if boot_match:
                            node.boot_message_name = msg_name
                    nodes[node_name] = node

    return nodes

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/uds/node_factory.pyc
