# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/services/utils/request_limit.py
import time
from collections import defaultdict
MAX_REQ_PERIOD = 86400
MAX_UPLOAD_COUNT = 10
request_collection = defaultdict()

def within_request_limit(node: str, max_upload_per_day: int=MAX_UPLOAD_COUNT) -> bool:
    global request_collection
    last = request_collection.setdefault(node, {'time':0,  'count':0})
    if time.time() - last["time"] > MAX_REQ_PERIOD:
        last["count"] = 0
        last["time"] = time.time()
    last["count"] += 1
    return last["count"] <= max_upload_per_day

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/services/utils/request_limit.pyc
