# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/uds/functions_udslite/__init__.py
from .data_transmission import read_data_by_id, read_memory_by_address, write_data_by_id, write_memory_by_address
from .diagnostic_communication_management import control_dtc_setting, diagnostic_session, ecu_reset, security_access, tester_present
from .input_output_control import io_control
from .remote_routines import routine_control
from .stored_data import clear_diagnostic_information, read_dtcs
from .upload_download import data_upload
from odin.core import uds

def init_uds_interface():
    uds.read_data_by_id = read_data_by_id
    uds.write_data_by_id = write_data_by_id
    uds.read_memory_by_address = read_memory_by_address
    uds.write_memory_by_address = write_memory_by_address
    uds.control_dtc_setting = control_dtc_setting
    uds.diagnostic_session = diagnostic_session
    uds.ecu_reset = ecu_reset
    uds.security_access = security_access
    uds.tester_present = tester_present
    uds.io_control = io_control
    uds.routine_control = routine_control
    uds.clear_diagnostic_information = clear_diagnostic_information
    uds.read_dtcs = read_dtcs
    uds.data_upload = data_upload

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/uds/functions_udslite/__init__.pyc
