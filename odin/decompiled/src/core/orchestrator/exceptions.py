# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/orchestrator/exceptions.py
from aiohttp.web import HTTPConflict, HTTPUnauthorized

class InvalidJobsDefinition(Exception):
    return


class OrchestratorAlreadyRunning(HTTPConflict):

    def __init__(self):
        super().__init__(reason="Orchestrator is already running")


class OrchestratorUnauthorized(HTTPUnauthorized):

    def __init__(self):
        super().__init__(reason="Not authorized to run given jobs file")

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/orchestrator/exceptions.pyc
