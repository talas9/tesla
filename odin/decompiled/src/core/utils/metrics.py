# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/utils/metrics.py
import datetime
from enum import IntEnum
from typing import Dict, List, Union, Optional

class MetricResult(IntEnum):
    Pass = 0
    Fail = 1
    Skip = 2


def create_metric(name: str, value: Union[(int, float, str)], capture_time: datetime.datetime, critical: bool=False, ecu_name: Optional[str]=None, expected_value: Union[(int, float, str, None)]=None, result: Union[(MetricResult, int)]=MetricResult.Pass, low_limit: Union[(int, float, None)]=None, high_limit: Union[(int, float, None)]=None, metadata: Optional[dict]=None) -> Dict:
    return {'type':"metric", 
     'name':name, 
     'value':value, 
     'expected_value':expected_value, 
     'result':MetricResult(result).name.lower(), 
     'low_limit':low_limit, 
     'high_limit':high_limit, 
     'metadata':metadata, 
     'capture_time':capture_time.strftime("%Y-%m-%dT%H:%M:%S"), 
     'module':ecu_name, 
     'critical':critical}


def create_connector_info(capture_time: datetime.datetime, error_description: str="", connectors: List[Dict]=None, result: Union[(MetricResult, int)]=MetricResult.Fail) -> Dict:
    return {'type':"metric", 
     'name':"connector_info", 
     'value':error_description, 
     'result':MetricResult(result).name.lower(), 
     'metadata':{"connectors": connectors}, 
     'capture_time':capture_time.strftime("%Y-%m-%dT%H:%M:%S")}

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/utils/metrics.pyc
