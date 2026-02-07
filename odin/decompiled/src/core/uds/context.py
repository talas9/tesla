# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/uds/context.py
import asyncio, logging
from typing import AsyncGenerator
from asyncio_extras import async_contextmanager
from odin.core import uds
from odin.core.utils.context import periodic_context
log = logging.getLogger(__name__)

@async_contextmanager
async def tester_present_context(uds_node_name: str, interval: float=0.1) -> AsyncGenerator[(asyncio.Future, None)]:

    async def tester_present():
        await uds.tester_present(uds_node)

    uds_node = uds.nodes[uds_node_name]
    async with periodic_context(periodic_func=tester_present, interval=interval):
        yield


@async_contextmanager
async def uds_node_lock_context(node_name: str) -> AsyncGenerator[(asyncio.Future, None)]:
    node = uds.nodes[node_name]
    log.debug("uds_node_lock_context: node: {}, locked: {}".format(node.name, node.lock.locked()))
    async with node.lock:
        yield

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/uds/context.pyc
