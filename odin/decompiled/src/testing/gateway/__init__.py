# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/testing/gateway/__init__.py
import logging
from .recorder import AbstractGatewayRecorder
from .playback import AbstractGatewayPlayback
from ...config import options
log = logging.getLogger(__name__)
DEFAULT_RUN_ID = "global"
INSTANCES = {}

def is_testing_enabled() -> bool:
    return options["testing"]["gateway_testing_enabled"]


def is_tracing_enabled() -> bool:
    return options["testing"]["error_tracing_enabled"]


def clear_record_replay_instance(run_id: str=DEFAULT_RUN_ID):
    if run_id in INSTANCES:
        INSTANCES.pop(run_id)


def get_playback_instance(run_id: str=DEFAULT_RUN_ID) -> AbstractGatewayPlayback:
    instance_type, instance_object = INSTANCES.get(run_id) or ('playback', None)
    if instance_type == "playback":
        return instance_object
    else:
        return


def get_recorder_instance(run_id: str=DEFAULT_RUN_ID) -> AbstractGatewayRecorder:
    instance_type, instance_object = INSTANCES.get(run_id) or ('recorder', None)
    if instance_type == "recorder":
        return instance_object
    else:
        return


def create_record_playback_instance(test_args: dict, run_id: str=DEFAULT_RUN_ID):
    if test_args is None and is_tracing_enabled() or test_args.get("record") and isinstance(test_args["record"], dict):
        record_args = test_args["record"] if test_args is not None else {}
        recorder_type = record_args.get("type") or "linear"
        recorder_filepath = record_args.get("filepath") or None
        INSTANCES[run_id] = ("recorder", AbstractGatewayRecorder.factory(recorder_type, logfile=recorder_filepath))
        log.debug("Recorder enabled for run_id={}. Type={}, filepath={}".format(run_id, recorder_type, recorder_filepath))
        return
    else:
        if test_args.get("playback") and isinstance(test_args["playback"], dict) and is_testing_enabled():
            playback_type = test_args["playback"].get("type") or "linear"
            playback_file = test_args["playback"].get("filepath")
            playback_content = test_args["playback"].get("content")
            playback_instance = AbstractGatewayPlayback.factory(playback_type)
            if playback_file:
                playback_instance.load_fixture_from_file(playback_file)
            elif playback_content:
                playback_instance.load_fixture_from_csv_list(playback_content)
            else:
                raise RuntimeError("No playback content or file specified!")
            INSTANCES[run_id] = ("playback", playback_instance)
            log.debug("Playback enabled for run_id={}. Type={}, filepath={}, content={}".format(run_id, playback_type, playback_file, playback_content))

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/testing/gateway/__init__.pyc
