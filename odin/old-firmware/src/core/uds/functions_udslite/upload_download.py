# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/uds/functions_udslite/upload_download.py
import logging
from odin.core.uds import Node
from odin.core.uds.utils import node_lock
from .udslite import get_udsclient_with_datalink, translate_udslite_exception
log = logging.getLogger(__name__)

@node_lock
@translate_udslite_exception
async def data_upload(node, memory_address, memory_size, data_format_identifier=0, length_memory_size_and_address=68):
    client, datalink = get_udsclient_with_datalink(node)
    async with datalink.active():
        return await client.upload(memory_address, memory_size)

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/uds/functions_udslite/upload_download.pyc
