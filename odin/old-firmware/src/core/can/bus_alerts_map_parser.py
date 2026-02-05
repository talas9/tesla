# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/can/bus_alerts_map_parser.py


def add_to_library(mapping_data: dict, library: dict) -> dict:
    alert_map_info = {'salt':mapping_data["s"], 
     'hashed_map':mapping_data["c"]}
    if "hashed" not in library:
        library["hashed"] = {}
    library["hashed"]["bus_alerts_map"] = alert_map_info

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/can/bus_alerts_map_parser.pyc
