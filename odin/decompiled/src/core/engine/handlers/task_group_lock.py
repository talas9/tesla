# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/engine/handlers/task_group_lock.py
import time
from typing import Optional

class TaskGroupLock:

    def __init__(self):
        self._timeout = 0
        self._last_reset_time = time.time()
        self._task_group = None

    def get_task_group(self, check_if_expired: bool=True) -> Optional[str]:
        if check_if_expired:
            if self._is_expired():
                self._task_group = None
        return self._task_group

    def _is_expired(self) -> bool:
        seconds_since_last_reset = time.time() - self._last_reset_time
        return seconds_since_last_reset >= self._timeout

    def lock(self, task_group: str, timeout: float=5):
        self._timeout = timeout
        self._task_group = task_group
        self.refresh()

    def refresh(self):
        self._last_reset_time = time.time()

    def unlock(self):
        self._timeout = 0
        self._last_reset_time = time.time()
        self._task_group = None

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/engine/handlers/task_group_lock.pyc
