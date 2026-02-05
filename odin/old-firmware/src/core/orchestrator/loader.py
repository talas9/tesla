# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/orchestrator/loader.py
from architect import make_network
from architect.core.network import Network
from odin.core import gateway
from . import tracking
from .exceptions import InvalidJobsDefinition
DEPENDENCY_TYPES = {'SUCCESS':"success", 
 'FAILED':"failure", 
 'COMPLETED':"done"}

def construct_network_from_jobs(jobs: dict) -> Network:
    network = make_network()
    job_nodes = _make_job_nodes(network, jobs)
    split_nodes = _add_split_nodes(network, job_nodes)
    merge_nodes = _add_merge_nodes(network, job_nodes)
    _connect_dependencies(split_nodes, merge_nodes, jobs)
    _add_enter_node(network, merge_nodes)
    return network


def _add_job_to_logging(job_name: str, job: dict):
    job_dependencies = list(job.get("job_dependencies", {}).keys())
    tasks = job.get("tasks", [])
    signal_dependencies = job.get("signal_dependencies", [])
    trigger_dependencies = job.get("trigger_dependencies", [])
    uds_dependencies = job.get("uds_dependencies", [])
    forced_triggers = job.get("forced_triggers", [])
    tracking.add_job(job_name, job_dependencies, tasks, signal_dependencies, trigger_dependencies, uds_dependencies, forced_triggers)


def _assert_valid_job(name: str, job: dict):
    if "job_dependencies" not in job:
        raise InvalidJobsDefinition("job '{0}' has no job_dependencies defined".format(name))
    else:
        if not isinstance(job["job_dependencies"], dict):
            raise InvalidJobsDefinition("job_dependencies in job '{0}' must be a dictionary".format(name))
    if "signal_dependencies" not in job:
        raise InvalidJobsDefinition("job '{0}' has no signal_dependencies defined".format(name))
    else:
        if not isinstance(job["signal_dependencies"], list):
            raise InvalidJobsDefinition("signal_dependencies in job '{0}' must be a list".format(name))
    if "tasks" not in job:
        raise InvalidJobsDefinition("job '{0}' has no tasks defined".format(name))
    else:
        if not isinstance(job["tasks"], list):
            raise InvalidJobsDefinition("tasks in job '{0}' must be a list".format(name))
    for task in job["tasks"]:
        try:
            gateway.gtw_config_options.validate_gtw_config_qualifiers(task.get("gtw_config_qualifiers", {}))
        except KeyError as err:
            raise InvalidJobsDefinition("{}".format(err))


def _make_job_nodes(network: Network, jobs: dict) -> dict:
    tracking.clear_jobs()
    nodes = {}
    for job_name, job in jobs.items():
        _assert_valid_job(job_name, job)
        _add_job_to_logging(job_name, job)
        nodes[job_name] = _make_job_node(network, job_name, job)

    return nodes


def _make_job_node(network, name, job):
    node = network.add_node("orchestrator.OrchestratorJob", name)
    node.tasks = job["tasks"]
    node.signal_dependencies = job.get("signal_dependencies", [])
    node.trigger_dependencies = job.get("trigger_dependencies", [])
    node.uds_dependencies = job.get("uds_dependencies", [])
    node.forced_triggers = job.get("forced_triggers", [])
    node.execute_concurrently = job.get("run_tasks_concurrently", False)
    return node


def _add_split_nodes(network: Network, job_nodes: dict) -> dict:
    split_nodes = {}
    for node_name, node in job_nodes.items():
        for port in DEPENDENCY_TYPES.values():
            split_name = "{}_split_{}".format(node_name, port)
            split_node = network.add_node("control.MultiSplit", split_name)
            getattr(node, port).connection = split_node.run
            split_nodes[split_name] = split_node

    return split_nodes


def _add_merge_nodes(network: Network, job_nodes: dict) -> dict:
    merge_nodes = {}
    for node_name, node in job_nodes.items():
        merge_name = "{}_merge_run".format(node_name)
        merge_node = network.add_node("control.MultiMerge", merge_name)
        merge_node.done.connection = node.run
        merge_nodes[merge_name] = merge_node

    return merge_nodes


def _connect_dependencies(split_nodes: dict, merge_nodes: dict, jobs: dict):
    for job_name, job in jobs.items():
        for dep_name, dep_type in job.get("job_dependencies", {}).items():
            _connect_dependency(split_nodes, merge_nodes, job_name, dep_name, dep_type)


def _connect_dependency(split_nodes, merge_nodes, job_name, dep_name, dep_type):
    split_node = split_nodes[dep_name + "_split_" + DEPENDENCY_TYPES[dep_type]]
    merge_node = merge_nodes[job_name + "_merge_run"]
    split_port = split_node.branches.add_child()
    merge_port = merge_node.dependencies.add_child()
    split_port.connection = merge_port


def _add_enter_node(network: Network, merge_nodes: dict):
    enter_split = _make_enter_and_split(network)
    for node in _root_merge_nodes(merge_nodes):
        _connect_enter_signal(enter_split, node)


def _make_enter_and_split(network: Network) -> object:
    enter_node = network.add_node("networks.Enter")
    enter_split = network.add_node("control.MultiSplit", "enter_split")
    enter_node.start.connection = enter_split.run
    return enter_split


def _root_merge_nodes(merge_nodes: dict):
    for node in merge_nodes.values():
        if len(node.dependencies) == 0:
            yield node


def _connect_enter_signal(enter_split, node):
    slot = node.dependencies.add_child()
    signal = enter_split.branches.add_child()
    signal.connection = slot

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/orchestrator/loader.pyc
