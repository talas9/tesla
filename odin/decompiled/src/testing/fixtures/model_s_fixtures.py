# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/testing/fixtures/model_s_fixtures.py
import pytest
from odin.platforms.platform_switch import switch_platform_to

@pytest.fixture()
def model_s_config():
    switch_platform_to("model_s")


@pytest.fixture
def model_s_uds_nodes():
    return {'BCCEN', 'BDY', 'BMS', 'CHG', 'CHGPH1', 
     'CHGPH2', 'CHGPH3', 
     'CHGRLY', 'CHGS', 'CHGSPH1', 
     'CHGSPH2', 'CHGSPH3', 'CHGSVI', 
     'CHGVI', 'CMP', 
     'CP', 'CTPMS', 'DAS', 'DCDC', 'DDM', 
     'DHFD', 
     'DHFP', 'DHRD', 'DHRP', 'DI', 'DIS', 'EFUSE', 
     'EPAS', 
     'EPAS2', 'EPAS3S', 'EPAS3P', 'EPB', 'EPBM', 
     'ESP', 'ESP2', 
     'ESPCAL', 'IBST', 'IBSTCAL', 'IC', 'LFT', 
     'MSM', 'MSMD', 
     'MSMP', 'OCS', 'PARK', 'PARK2', 'PDM', 
     'PLCRLY', 'PM', 
     'PMS', 'PTC', 'RADC', 'RADRL', 'RADRR', 
     'RCCM', 'RCM', 
     'RLSCAL', 'SDM', 'SEC', 'SUN', 'TAS', 'THC', 
     'TPMS', 
     'TUNER', 'WC'}

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/testing/fixtures/model_s_fixtures.pyc
