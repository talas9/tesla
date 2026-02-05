# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/uds/utils.py
import logging
from array import array
from functools import wraps
from typing import Callable, Dict
from odin.core import uds
from .exceptions import UdsError, UdsTransportError, UdsTransportErrorRegistry, UdsEcuError, UdsEcuErrorRegistry, UdsProtocolError, UdsProtocolErrorRegistry
log = logging.getLogger(__name__)
NIBBLE = 4
LO_NIB = 15
HI_NIB = 240
MAX_BYTE_LOG = 256
BYTE_ARRAY_LEN = 8

def node_lock(request: Callable, node: uds.Node=None) -> Callable:

    @wraps(request)
    async def locked_request(*args, **kwargs):
        nonlocal node
        if node is None:
            node = kwargs.get("node") or args[0]
        node = kwargs.get("node") or args[0]
        if not isinstance(node, uds.Node):
            return await request(*args, **kwargs)
        log.debug("UDS {}: node: {}, locked: {}".format(request.__name__, node.name, node.lock.locked()))
        async with node.lock:
            return await request(*args, **kwargs)

    return locked_request


def raise_for_status(raw_response: int):
    if not raw_response:
        return
    else:
        check = raw_response & 3840
        if check == 0:
            raise UdsTransportErrorRegistry.get(raw_response, UdsTransportError)(raw_response)
        elif check == 256:
            raise UdsEcuErrorRegistry.get(raw_response, UdsEcuError)(raw_response)
        elif check == 512 or check == 768:
            raise UdsProtocolErrorRegistry.get(raw_response, UdsProtocolError)(raw_response)
        else:
            raise UdsError(raw_response)


def parse_dtc_data(raw_data: bytes) -> Dict:

    def chunks(l, n):
        for i in range(1, len(l), n):
            yield l[i:i + n]

    return {"DTC_{0}".format(array("B", x[:-1]).tobytes().hex().upper()): x[-1] for x in chunks(raw_data, 4)}

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/uds/utils.pyc
