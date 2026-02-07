# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/engine/task_metadata.py
from ...platforms import architect_client_port
from ...languages import get_locstring, NO_SUCH_STRING_KEY_PREFIX

async def get_task_definition(task_name: str) -> dict:
    task_data = await get_task_data(task_name)
    metadata = await get_metadata_for_task(task_name, task_data)
    return ({**filter_external_fields(metadata), **await get_sx_metadata_for_task(task_name, task_data), **{'message':await get_message_for_task(task_name, task_data), 
     'name':basename(task_name), 
     'inputs':await get_task_inputs(task_name, task_data)}})


def filter_external_fields(metadata: dict) -> dict:
    filtered_keys = [
     "principals", "remote_execution_permissions"]
    return {k: v for k, v in metadata.items() if k not in filtered_keys}


def basename(task_name: str) -> str:
    return task_name.split("/")[-1]


async def get_message_for_task(task_name: str, task_data: dict=None):
    return {'command':"execute", 
     'args':{"name": task_name}}


async def get_sx_metadata_for_task(task_name: str, task_data: dict=None) -> dict:
    data = await get_task_data(task_name, task_data)
    meta = {}
    if data.get("can_mark_failed"):
        meta["canMarkFailed"] = get_metadata(data, "can_mark_failed", True)
    if data.get("can_mark_passed"):
        meta["canMarkPassed"] = get_metadata(data, "can_mark_passed", True)
    return meta


async def get_task_data(task_name: str, task_data: dict=None) -> dict:
    if task_data is not None:
        return task_data
    else:
        if not task_name:
            return {}
        client = architect_client_port()
        raw_string = await client.asset_manager.storage.load_string_from_basename_and_version(task_name)
        return client.asset_manager.loader.load_port.loads(raw_string)


async def get_metadata_for_task(task_name: str, task_data: dict=None) -> dict:
    data = await get_task_data(task_name, task_data)
    meta = get_one_taskinfo(data)
    extracted = extract_fields_with_defaults(meta, [
     (
      "title", task_name),
     ('description', ''),
     ('dependencies', ''),
     ('cancelable', False),
     (
      "principals", ["tbx-internal"]),
     (
      "remote_execution_permissions", []),
     (
      "valid_states", ["StandStill|Parked"]),
     ('post_fusing_allowed', False)])
    extracted["title"] = get_localized_title(task_name, extracted["title"])
    return extracted


def extract_fields_with_defaults(metadata: dict, fields_and_defaults: list) -> dict:
    ret_val = {}
    for field, default in fields_and_defaults:
        ret_val[field] = get_metadata(metadata, field, default)

    return ret_val


def get_metadata(metadata: dict, key: str, default=None) -> object:
    value = metadata.get(key)
    if isinstance(value, dict):
        return value["value"]
    else:
        if value is None:
            return default
        return value


def get_localized_title(task_name, default_title):
    task_basename = (task_name or "").split("/")[-1].strip().upper()
    str_key = "STRKEY.TASKS." + task_basename
    return get_locstring(str_key, default_title)


def get_one_taskinfo(container: dict) -> dict:
    taskinfos = get_nodes_by_type(container, "comments.TaskInfo")
    if taskinfos:
        return list(taskinfos.values())[0]
    else:
        return {}


def get_nodes_by_type(container: dict, node_type: str) -> dict:
    if not isinstance(container, dict):
        return {}
    else:
        return {k: v for k, v in container.items() if type_matched(v, node_type)}


def type_matched(node: dict, node_type: str) -> bool:
    return node.get("type") == node_type


async def get_task_inputs(task_name: str, task_data: dict=None) -> dict:
    data = await get_task_data(task_name, task_data)
    return make_task_inputs(data)


def make_task_inputs(container: dict) -> dict:
    return {k: make_input(v) for k, v in get_nodes_by_type(container, "networks.Input").items()}


def make_input(container: dict) -> dict:
    return {'datatype':get_input_datatype(container), 
     'default':get_input_default(container)}


def get_input_default(container: dict):
    default = container.get("default")
    if isinstance(default, dict):
        return default.get("value")
    else:
        return default


def get_input_datatype(container: dict) -> str:
    return datatype_from_field(container.get("default")) or datatype_from_field(container.get("value"))


def datatype_from_field(value: object) -> str:
    if isinstance(value, dict):
        return value.get("datatype")

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/engine/task_metadata.pyc
