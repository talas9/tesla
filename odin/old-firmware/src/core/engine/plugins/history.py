# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/engine/plugins/history.py
import logging, apis
from aiohttp import web
from odin.core.utils.history import History
from odin.core.orchestrator import tracking
log = logging.getLogger(__name__)
history = History(maxsize=1024)

def write_to_history(entry: dict):
    history[str(entry.get("test", "UNKNOWN")) + str(entry.get("date", "NODATE")) + str(entry.get("started", "NOSTART"))] = entry


@apis.route("/api/v1/task_history", method="GET")
async def results(request: web.Request) -> web.Response:
    response = web.json_response({'history':list(history.values()), 
     'help_text':tracking.get_help_text()})
    return response


def includeme(app):
    app["odin.core.engine.plugins.history"] = True

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/engine/plugins/history.pyc
