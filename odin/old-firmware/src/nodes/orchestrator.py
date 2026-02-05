# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/nodes/orchestrator.py
import logging, asyncio
from architect.nodes import Attr, Input, Node, Signal, slot
from odin.core.utils import locks
from odin.core.orchestrator import job
log = logging.getLogger(__name__)

class Lock(Node):
    lock_name = Input("String")
    is_global = Attr("Bool", default=False)
    body = Signal()
    released = Signal()

    @slot()
    async def acquire(self):
        name = await self.lock_name()
        if not name:
            raise ValueError("Lock name required")
        context = self._root()._context() if self.is_global else self._context()
        lock = locks.get_lock(context, name)
        async with lock:
            await self.body()
        await self.released()


class OrchestratorJob(Node):
    tasks = Input("List")
    uds_dependencies = Input("List")
    signal_dependencies = Input("List")
    trigger_dependencies = Input("List")
    forced_triggers = Input("List")
    execute_concurrently = Input("Bool", default=False)
    failure = Signal()
    success = Signal()
    done = Signal()

    @slot()
    async def run(self):
        tasks, uds_dependencies, signal_dependencies, trigger_dependencies, forced_triggers, execute_concurrently = await asyncio.gather(self.tasks(), self.uds_dependencies(), self.signal_dependencies(), self.trigger_dependencies(), self.forced_triggers(), self.execute_concurrently())
        job_name = self._name
        context = self._root()._context()
        condition_satisfied = await job.wait_for_dependencies(job_name, uds_dependencies, signal_dependencies, trigger_dependencies, forced_triggers)
        if condition_satisfied:
            all_tasks_passed = await job.execute_tasks(job_name, context, tasks, execute_concurrently)
        else:
            all_tasks_passed = False
        if all_tasks_passed:
            await asyncio.gather(self.success(), self.done())
        else:
            await asyncio.gather(self.failure(), self.done())

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/nodes/orchestrator.pyc
