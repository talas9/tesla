# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/orchestrator/memory.py
import hashlib, json, logging, os
from typing import Optional
from architect.workflows.encoder import DatatypeEncoder
from odin.core.cid.interface import filesystem
from . import settings
log = logging.getLogger(__name__)
_RESULTS_DIR = os.path.join(settings._ORCHESTRATOR_ROOT_SETTINGS_DIR, "results")
_FINAL_STATE_FILE = os.path.join(_RESULTS_DIR, "final")
_reload_final_state = True
_cached_final_state = None

def _get_task_result_path(job_name: str, task_name: str) -> str:
    job_task_str = job_name + task_name
    task_hash = hashlib.sha1(job_task_str.encode()).hexdigest()
    return os.path.join(_RESULTS_DIR, task_hash)


async def set_task_result(job_name, task_name, result):
    task_file = _get_task_result_path(job_name, task_name)
    await filesystem.mkdir(_RESULTS_DIR, parents=True, exist_ok=True)
    await filesystem.write_json(task_file, result, cls=DatatypeEncoder)
    await filesystem.sync()


async def get_task_result(job_name: str, task_name: str) -> Optional[dict]:
    task_file = _get_task_result_path(job_name, task_name)
    try:
        return await filesystem.load_json(task_file)
    except (FileNotFoundError, json.decoder.JSONDecodeError):
        return


async def has_final_state() -> bool:
    return await filesystem.exists(_FINAL_STATE_FILE)


async def set_final_state(state: dict):
    global _cached_final_state
    global _reload_final_state
    _reload_final_state = True
    _cached_final_state = None
    await filesystem.mkdir(_RESULTS_DIR, parents=True, exist_ok=True)
    await filesystem.write_json(_FINAL_STATE_FILE, state)
    await filesystem.sync()


async def get_final_state() -> Optional[dict]:
    global _cached_final_state
    global _reload_final_state
    if _reload_final_state:
        try:
            _cached_final_state = await filesystem.load_json(_FINAL_STATE_FILE)
        except (FileNotFoundError, json.decoder.JSONDecodeError):
            _cached_final_state = None

        _reload_final_state = False
    return _cached_final_state


async def clear_all_results():
    global _cached_final_state
    global _reload_final_state
    _reload_final_state = True
    _cached_final_state = None
    await filesystem.remove_dir(_RESULTS_DIR, recursive=True, doesnt_exist_ok=True)
    await filesystem.sync()

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/orchestrator/memory.pyc
