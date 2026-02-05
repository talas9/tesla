# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/nodes/comments.py
from architect import Node as CommentNode, Input

class TaskInfo(CommentNode):
    title = Input("String")
    description = Input("String")
    steps_to_test = Input("String")
    steps_to_fix = Input("String")
    additional_info = Input("String")
    engineering_notes = Input("String")
    principals = Input("List")
    owner_ids = Input("List")
    valid_states = Input("List")
    constraints = Input("List")
    dependencies = Input("Dict")
    exit_code_connectors = Input("Dict")
    ota_enabled = Input("Bool", default=True)
    can_mark_passed = Input("Bool", default=False)
    can_mark_failed = Input("Bool", default=False)
    expected_duration = Input("Int", default=0)
    default_retries = Input("Int", default=0)
    default_pause_between_retries = Input("Int", default=0)
    default_global_timeout = Input("Int", default=0)
    cancelable = Input("Bool", default=False)
    remote_execution_permissions = Input("List", default=[])
    post_fusing_allowed = Input("Bool", default=False)
    build_scopes = Input("List", default=["prod"])

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/nodes/comments.pyc
