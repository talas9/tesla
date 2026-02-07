# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/scripting/input_output_validate.py
import string
from odin.core.utils.payload import validate_safe_string
ALLOWED_TYPES = (str, int, float, bool, dict, list)
ALLOWED_CHARS = string.ascii_letters + string.digits + "_-"
RESERVED_OUTPUT_NAMES = [
 "exit_code", "metrics", "debug_lines"]

def walk_and_validate(node):
    if isinstance(node, str):
        validate_safe_string(node, ALLOWED_CHARS)
    elif isinstance(node, dict):
        for input_key, input_value in node.items():
            walk_and_validate(input_key)
            walk_and_validate(input_value)

    elif isinstance(node, list):
        for item in node:
            walk_and_validate(item)

    elif node:
        pass
    if type(node) not in ALLOWED_TYPES:
        raise ValueError(f"ScriptTest inputs and outputs must be {ALLOWED_TYPES}")


def is_output_name_allowed(name):
    if name in RESERVED_OUTPUT_NAMES:
        raise ValueError(f"Script node outputs cannot be named {RESERVED_OUTPUT_NAMES}")

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/scripting/input_output_validate.pyc
