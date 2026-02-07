# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/uds/functions_odin/stored_data.py
import struct
from typing import Dict
from odin.core.uds import UdsServices, Node, DTCReportType
from odin.core.uds.utils import node_lock, parse_dtc_data
from .service import uds_request_response

@node_lock
async def clear_diagnostic_information(node: Node) -> None:
    await uds_request_response(node=node, sid=(UdsServices.CLEAR_DIAGNOSTIC_INFORMATION),
      payload=(bytes([255] * 3)),
      expected_payload_size=0)


@node_lock
async def read_dtcs(node: Node, dtc_mask: int=255) -> Dict:
    payload = await uds_request_response(node=node, sid=(UdsServices.READ_DTC_INFORMATION),
      sfid=(struct.pack("!B", DTCReportType.DTCByStatusMask)),
      payload=(struct.pack("!B", dtc_mask)))
    output_dict = parse_dtc_data(payload)
    return output_dict

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/uds/functions_odin/stored_data.pyc
