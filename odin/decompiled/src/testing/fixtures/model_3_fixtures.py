# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/testing/fixtures/model_3_fixtures.py
import pytest
from odin.platforms.platform_switch import switch_platform_to

@pytest.fixture()
def model_3_config():
    switch_platform_to("model_3")


@pytest.fixture
def model_3_uds_nodes():
    return {
     'RCM', 
     'OCS', 
     'ESP', 
     'IBST', 
     'EPAS', 
     'HVBMS', 
     'HVP', 
     'PCS', 
     'CP', 
     'TPMS', 
     'PARK', 
     'CMP', 
     'TAS', 
     'VCLEFT', 
     'VCRIGHT', 
     'EPBL', 
     'EPBR', 
     'PTC', 
     'RADAR', 
     'VCSEC', 
     'VCFRONT', 
     'SCCM'}

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/testing/fixtures/model_3_fixtures.pyc
