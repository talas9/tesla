# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/testing/utils.py
import hashlib, json, os, time

def delay_rerun_1sec(*args):
    time.sleep(1)
    return True


def generate_recording_file_path(record_root, parameters, network_name):
    filename = generate_fixture_filename(network_name, parameters)
    return os.path.join(record_root, filename)


def generate_fixture_filename(network_name, parameters):
    return "{0}-{1}.yaml".format(network_name, generate_hash_for_parameters(parameters))


def generate_hash_for_parameters(parameters):
    ordered_list = []
    for k, v in parameters.items():
        ordered_list.append((k, v))

    ordered_list = sorted(ordered_list, key=(lambda item: item[0]))
    return hashlib.sha1(json.dumps(ordered_list).encode()).hexdigest()


def extract_parameters(network_data):
    data = json.loads(network_data)
    parameters = {}
    for node_name, node_def in data.items():
        if node_def.get("type") == "networks.Input" and node_def.get("default") and node_def.get("default").get("value") is not None:
            parameters[node_name] = node_def.get("default").get("value")

    return parameters


def find_fixture_file_matching_parameter_hash(file_dir, parameter_hash):
    for file in os.listdir(file_dir):
        if file.endswith("{}.yaml".format(parameter_hash)):
            return os.path.join(file_dir, file)

    return

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/testing/utils.pyc
