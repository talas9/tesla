# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/scripting/run.py
from inspect import iscoroutinefunction
import os
from logging import getLogger
from .api import make_public_api
from .jail import exec_with_scripting_jail
from .jail import import_with_scripting_jail
log = getLogger(__name__)

class ScriptSanityCheck(Exception):
    return


class ScriptReturnValueError(ValueError):
    return


class ScriptNameError(ValueError):
    return


async def safe_run_code(parent, code, inputs, name=None):
    script = exec_with_scripting_jail(code, name=name)
    return await check_and_run_script(parent, script, inputs)


async def safe_run_script(parent, script_name, inputs):
    sanity_check_script_name(script_name)
    log.info("Running script {}".format(script_name))
    script = await import_with_scripting_jail(script_name, name=script_name)
    return await check_and_run_script(parent, script, inputs)


def sanity_check_script_name(name):
    if not name:
        raise ScriptNameError("Script name cannot be empty or None.")
    elif os.path.isabs(name):
        raise ScriptNameError("Scripts may not reference absolute paths.")
    else:
        if os.path.splitext(name)[1]:
            raise ScriptNameError("Script should not include extension.")
    return name


async def check_and_run_script(parent, script, inputs):
    return await get_and_check_result(parent, sanity_check_script(script, inputs), inputs)


def sanity_check_script(script, inputs):
    if not hasattr(script, "odin_script_test"):
        raise ScriptSanityCheck("Script must contain a coroutine named odin_script_test")
    else:
        if not iscoroutinefunction(script.odin_script_test):
            raise ScriptSanityCheck('odin_script_test must be a coroutine. Add "async" before "def" of function')
    return script


async def get_and_check_result(parent, script, inputs):
    return sanity_check_result(await (script.odin_script_test)(
     (make_public_api(parent)), **inputs))


def sanity_check_result(result):
    if type(result) is not int:
        raise ScriptReturnValueError("Script return value must be int.")
    return result

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/scripting/run.pyc
