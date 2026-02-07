# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/scripting/api_definitions.py
from architect.core.register_meta import RegisterNodeMeta
EXCLUDED_CLASSES = []
KW_OVERRIDES = {"reporting.DebugPrint": {"posargs": ["data"]}}
ALLOWED_ARCHITECT_NODES = [
 "networks.SetOutput"]

def get_node_classes_for_api() -> dict:
    names = {}
    for name, definition in RegisterNodeMeta.subclasses.items():
        if should_use_class(name, definition):
            names[name] = KW_OVERRIDES.get(name, {})

    return names


def should_use_class(name: str, definition: object) -> bool:
    if name in EXCLUDED_CLASSES:
        return False
    else:
        if definition.__module__.startswith("architect"):
            if name not in ALLOWED_ARCHITECT_NODES:
                return False
        return True

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/scripting/api_definitions.pyc
