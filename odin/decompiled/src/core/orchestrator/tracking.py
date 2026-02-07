# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/orchestrator/tracking.py
from collections import OrderedDict
import logging
from typing import Optional
log = logging.getLogger(__name__)

class TrackedTask:

    def __init__(self, name: str):
        self.name = name
        self.status = "Inactive"
        self.gtw_config_qualifiers = {}


class TrackedSignal:

    def __init__(self, name: str, help_text: Optional[str]):
        self.name = name
        self.status = "--"
        self.help_text = help_text


class TrackedUds:

    def __init__(self, node_name: str, component_name: str, help_text: Optional[str]):
        self.name = component_name
        self.ecu = node_name
        self.status = "--"
        self.help_text = help_text


class TrackedJob:

    def __init__(self, name: str):
        self.name = name
        self.job_dependencies = []
        self.signal_dependencies = OrderedDict()
        self.signal_status = "Inactive"
        self.uds_dependencies = OrderedDict()
        self.uds_status = "Inactive"
        self.trigger_dependencies = []
        self.trigger_status = "Inactive"
        self.forced_triggers = []
        self.tasks = OrderedDict()
        self.tasks_status = "Inactive"
        self.forcedly_triggered = False

    def get_task(self, task_name: str) -> TrackedTask:
        return self.tasks.setdefault(task_name, TrackedTask(task_name))

    def get_signal(self, signal_name: str) -> TrackedSignal:
        return self.signal_dependencies.setdefault(signal_name, TrackedSignal(signal_name, None))

    def get_uds(self, node_name: str, component_name: str) -> TrackedUds:
        return self.uds_dependencies.setdefault((node_name, component_name), TrackedUds(node_name, component_name, None))

    def set_task_status(self, task_name: str, status: str):
        self.get_task(task_name).status = status

    def set_signal_status(self, signal_name: str, status: str):
        self.get_signal(signal_name).status = status

    def set_uds_status(self, node_name: str, component_name: str, status: str):
        self.get_uds(node_name, component_name).status = status

    def add_task(self, task_name: str, gtw_config_qualifiers: dict):
        task = TrackedTask(task_name)
        task.gtw_config_qualifiers = gtw_config_qualifiers
        self.tasks[task_name] = task

    def add_signal(self, signal_name: str, help_text: str):
        signal = TrackedSignal(signal_name, help_text)
        self.signal_dependencies[signal_name] = signal

    def add_uds(self, node_name: str, component_name: str, help_text: str):
        uds_signal = TrackedUds(node_name, component_name, help_text)
        self.uds_dependencies[(node_name, component_name)] = uds_signal


_tracked_jobs = OrderedDict()

def _job_to_str(job: TrackedJob):
    lines = list()
    lines.append("\n{0} ({1})".format(job.name, get_job_status(job)))
    jobs = [_tracked_jobs[job_name] for job_name in job.job_dependencies]
    job_text = ", ".join(["{0} ({1})".format(j.name, get_job_status(j)) for j in jobs])
    lines.append("\tjob dependencies: {0}".format(job_text))
    signal_parts = []
    for signal_name, tracked_signal in job.signal_dependencies.items():
        signal_parts.append("{0} ({1})".format(signal_name, tracked_signal.status))

    signal_text = ", ".join(signal_parts)
    lines.append("\tsignal dependencies: {0}".format(signal_text))
    uds_parts = []
    for uds_dep, tracked_uds in job.uds_dependencies.items():
        node_name, component_name = uds_dep
        uds_parts.append("{0}: {1} ({2})".format(node_name, component_name, tracked_uds.status))

    uds_text = ", ".join(uds_parts)
    lines.append("\tuds dependencies: {0}".format(uds_text))
    lines.append("\ttrigger dependencies: {0}".format(", ".join(job.trigger_dependencies)))
    lines.append("\tforced triggers: any of {0}".format(", ".join(job.forced_triggers)))
    lines.append("\ttasks:")
    for task in job.tasks.values():
        lines.append("\t\t- {0} ({1})".format(task.name, task.status))
        if task.gtw_config_qualifiers:
            lines.append("\t\t\tgateway config qualifiers:")
            lines.extend(["\t\t\t\t{}: {}".format(key, value) for key, value in task.gtw_config_qualifiers.items()])

    return "\n".join(lines)


def log_job(job_name: str):
    global _tracked_jobs
    log.info(_job_to_str(_tracked_jobs[job_name]))


def log_all_jobs():
    all_jobs_text = "\n".join([_job_to_str(tracked_job) for tracked_job in _tracked_jobs.values()])
    log.info(all_jobs_text)


def clear_jobs():
    _tracked_jobs.clear()


def get_job(job_name: str) -> TrackedJob:
    return _tracked_jobs.setdefault(job_name, TrackedJob(job_name))


def add_job(job_name, job_dependencies, tasks, signals, triggers, uds_signals, forced_triggers):
    tracked_job = TrackedJob(job_name)
    tracked_job.job_dependencies = job_dependencies
    tracked_job.trigger_dependencies = triggers
    tracked_job.forced_triggers = forced_triggers
    for task in tasks:
        tracked_job.add_task(task.get("task"), task.get("gtw_config_qualifiers", {}))

    for signal in signals:
        tracked_job.add_signal(signal.get("name"), signal.get("help_text"))

    for uds_signal in uds_signals:
        tracked_job.add_uds(uds_signal.get("node_name"), uds_signal.get("component_name"), uds_signal.get("help_text"))

    _tracked_jobs[job_name] = tracked_job


def set_job_forcedly_triggered(job_name: str):
    get_job(job_name).forcedly_triggered = True
    log.info("job={0}, forcedly triggered".format(job_name))


def set_job_status(job_name, signal_status=None, uds_status=None, trigger_status=None, tasks_status=None):
    job = get_job(job_name)
    if signal_status:
        job.signal_status = signal_status
    if uds_status:
        job.uds_status = uds_status
    if trigger_status:
        job.trigger_status = trigger_status
    if tasks_status:
        job.tasks_status = tasks_status
    log.info("job={0}, job_status={1}".format(job_name, get_job_status(job)))


def get_job_status(job: TrackedJob) -> str:
    return "signal:{0} | uds:{1} | trigger:{2} | tasks:{3}".format(job.signal_status, job.uds_status, job.trigger_status, job.tasks_status)


def set_signal_status(job_name: str, signal_name: str, signal_status: str):
    get_job(job_name).set_signal_status(signal_name, signal_status)
    log.info("job={0}, signal_name={1}, signal_status={2}".format(job_name, signal_name, signal_status))


def set_uds_status(job_name, node_name, component_name, uds_status):
    get_job(job_name).set_uds_status(node_name, component_name, uds_status)
    log.info(f"job={job_name}, node_name={node_name}, component_name={component_name}, uds_status={uds_status}")


def set_task_status(job_name: str, task_name: str, task_status: str):
    get_job(job_name).set_task_status(task_name, task_status)
    log.info("job={0}, task_name={1}, task_status={2}".format(job_name, task_name, task_status))


def log_task_error(job_name: str, task_name: str, error: str):
    log.error("job={0}, task_name={1}, error={2}".format(job_name, task_name, error))


def log_task_debug(job_name: str, task_name: str, info: str):
    log.debug("job={0}, task_name={1}, info={2}".format(job_name, task_name, info))


def get_current_state() -> dict:
    state = {}
    for job in _tracked_jobs.values():
        tasks = []
        for task in job.tasks.values():
            tasks.append({'name':task.name,  'status':task.status})

        state[job.name] = {'status':get_job_status(job), 
         'tasks':tasks}

    return state


def get_help_text() -> list:
    PENDING_STATUS = "Waiting"
    help_text = set()
    for tracked_job in _tracked_jobs.values():
        for signal in tracked_job.signal_dependencies.values():
            if signal.status != PENDING_STATUS:
                pass
            elif signal.help_text is not None:
                help_text.add(signal.help_text)
            else:
                help_text.add("Waiting for {}".format(signal.name))

        for uds_dep in tracked_job.uds_dependencies.values():
            if uds_dep.status != PENDING_STATUS:
                pass
            elif uds_dep.help_text is not None:
                help_text.add(uds_dep.help_text)
            else:
                help_text.add("Waiting for {}".format(uds_dep.name))

    return list(help_text)

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/orchestrator/tracking.pyc
