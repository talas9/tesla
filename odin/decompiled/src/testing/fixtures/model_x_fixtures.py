# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/testing/fixtures/model_x_fixtures.py
import pytest
from odin.platforms.platform_switch import switch_platform_to

@pytest.fixture()
def model_x_config():
    switch_platform_to("model_x")


@pytest.fixture
def model_x_uds_nodes():
    return {'BCFALCD', 'BCFALCP', 'BCS2C', 'BCS2L', 'BCS2R', 'PTCR', 'SNSCLL1', 'SNSCLR1', 
     'SNSCUL1', 
     'SNSCUR1', 'BCCEN', 'BCFDM', 'BCFPM', 'BCFRONT', 'BCRDM', 'BCREAR', 
     'BCRPM', 
     'BDY', 'BMS', 'CHG', 'CHGPH1', 'CHGPH2', 'CHGPH3', 'CHGRLY', 'CHGS', 
     'CHGSPH1', 
     'CHGSPH2', 'CHGSPH3', 'CHGSVI', 'CHGVI', 'CMP', 'CP', 'CTPMS', 
     'DAS', 
     'DCDC', 'DI', 'DIS', 'EFUSE', 'EPAS', 'EPAS2', 'EPAS3S', 'EPAS3P', 
     'EPB', 
     'EPBM', 'ESP', 'ESP2', 'ESPCAL', 'IBST', 'IBSTCAL', 'IC', 'MSM', 
     'MSMD', 
     'MSMP', 'OCS', 'PARK', 'PARK2', 'PLCRLY', 'PM', 'PMS', 'PTC', 
     'RADC', 
     'RADRL', 'RADRR', 'RCCM', 'RCM', 'RLSCAL', 'TAS', 'THC', 'TPMS', 
     'TUNER', 
     'VCSEATD', 'VCSEATP', 'WC'}

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/testing/fixtures/model_x_fixtures.pyc
