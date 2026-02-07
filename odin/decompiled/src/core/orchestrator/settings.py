# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/orchestrator/settings.py
from typing import Optional, Union
import os, odin
from odin.core.cid.interface import filesystem
CUSTOM_JOBS_AUTO_START_IDENTIFIER = "custom"
_ORCHESTRATOR_ROOT_SETTINGS_DIR = "/var/spool/odin/orchestrator/"
_ORCHESTRATOR_FUSED_JOBS_SUBDIR = "jobs"
_AUTO_START_SENTINEL_FILE = os.path.join(_ORCHESTRATOR_ROOT_SETTINGS_DIR, "autostart")
_CUSTOM_JOBS_FILE = os.path.join(_ORCHESTRATOR_ROOT_SETTINGS_DIR, "jobs.json")

def power_management_enabled() -> bool:
    return bool(odin.config.options["orchestrator"]["power_management"]["enabled"])


def power_management_keep_alive_minutes() -> int:
    return int(odin.config.options["orchestrator"]["power_management"]["keep_alive_minutes"])


def power_management_hold_time() -> float:
    return float(odin.config.options["orchestrator"]["power_management"]["seconds_spent_holding"])


def power_management_seconds_between_holds() -> float:
    return float(odin.config.options["orchestrator"]["power_management"]["seconds_between_holds"])


async def get_auto_start_jobs() -> Optional[str]:
    try:
        auto_start_text = await filesystem.read_text(_AUTO_START_SENTINEL_FILE)
        return auto_start_text.strip()
    except FileNotFoundError:
        return


async def set_auto_start_jobs(jobs_file: str):
    await filesystem.mkdir(_ORCHESTRATOR_ROOT_SETTINGS_DIR, parents=True, exist_ok=True)
    await filesystem.write_text(_AUTO_START_SENTINEL_FILE, jobs_file)
    await filesystem.sync()


async def remove_auto_start():
    await filesystem.remove_file(_AUTO_START_SENTINEL_FILE, doesnt_exist_ok=True, symlink_ok=True)
    await filesystem.sync()


async def load_jobs(jobs_file: Union[(None, str)]) -> object:
    if jobs_file in [None, "", CUSTOM_JOBS_AUTO_START_IDENTIFIER]:
        return await filesystem.load_json(_CUSTOM_JOBS_FILE)
    else:
        return await load_fused_jobs(jobs_file)


async def load_fused_jobs(jobs_file: str) -> object:
    if not isinstance(jobs_file, str):
        raise ValueError("Invalid fused jobs file provided: must be a string")
    else:
        if len(jobs_file) < 1:
            raise ValueError("Invalid fused jobs file provided: jobs file is empty")
    actual_jobs_file = "{}.json".format(jobs_file)
    if os.path.basename(actual_jobs_file) != actual_jobs_file:
        raise ValueError("Invalid fused jobs file provided: {}".format(jobs_file))
    metadata_path = odin.get_metadata_path()
    fused_jobs_path = os.path.join(os.path.join(metadata_path, _ORCHESTRATOR_FUSED_JOBS_SUBDIR), actual_jobs_file)
    return await filesystem.load_json(fused_jobs_path)


async def write_jobs(jobs: dict):
    await filesystem.mkdir(_ORCHESTRATOR_ROOT_SETTINGS_DIR, parents=True, exist_ok=True)
    await filesystem.write_json(_CUSTOM_JOBS_FILE, jobs)
    await filesystem.sync()

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/orchestrator/settings.pyc
