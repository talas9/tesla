# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/config.py
import collections, os, sys, yaml
from odin.core.utils import arch
INCLUDE_KEYWORD = "includes"
IMPORTED_YAMLS = []

def assets_location():
    if getattr(sys, "frozen", False) or arch.is_tegra():
        return os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))), "core", "engine", "assets")
    else:
        return os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))), "odin", "core", "engine", "assets")


def get_supported_platforms_map() -> dict:
    platform_file_path = os.environ.get("ODIN_PLATFORMS_YAML_PATH")
    if not platform_file_path:
        if getattr(sys, "frozen", False) or arch.is_tegra():
            platform_file_path = os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))), "platforms.yaml")
        else:
            platform_file_path = os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))), "..", "platforms.yaml")
    if os.path.exists(platform_file_path):
        with open(platform_file_path, "r") as fp:
            content = yaml.safe_load(fp)
        if isinstance(content, dict):
            return content.get("supported_platforms", {})
    raise RuntimeError("Unable to load {}!".format(platform_file_path))


options = {'buffer':{"log_traffic": False}, 
 'core':{'platform':os.environ.get("ODIN_PLATFORM", ""), 
  'fw_version':os.environ.get("ODIN_FW_VERSION", ""), 
  'artifacts_path':os.environ.get("ODIN_ARTIFACTS_PATH", "/opt/odin"), 
  'metadata_path':os.environ.get("ODIN_METADATA_PATH", ""), 
  'network_module':os.environ.get("ODIN_NETWORK_MODULE", ""), 
  'network_path':os.environ.get("ODIN_NETWORK_PATH", ""), 
  'resource_path':os.environ.get("ODIN_RESOURCE_PATH", ""), 
  'certificate_dir':os.environ.get("ODIN_CERTIFICATE_DIR", assets_location()), 
  'transport':"gateway", 
  'onboard':True, 
  'release_file':"/etc/product-release", 
  'supported_platforms':get_supported_platforms_map(), 
  'read_can_from_cid':False, 
  'max_workers_thread_pool':20, 
  'cid':{"ip": "127.0.0.1"}}, 
 'orchestrator':{"power_management": {
                       'enabled': True, 
                       'seconds_between_holds': 10, 
                       'seconds_spent_holding': 5, 
                       'keep_alive_minutes': 13}}, 
 'editor':{'allow_external_connection':False, 
  'external_ip':"127.0.0.1", 
  'odin_token':os.environ.get("ODIN_TOKEN", None)}, 
 'engine':{"permanent_send_topics": (set())}, 
 'logging':{'version':1, 
  'disable_existing_loggers':False, 
  'loggers':{"": {'level':"ERROR", 
        'propagate':True, 
        'handlers':[
         "console"]}}, 
  'handlers':{"console": {'class':"logging.StreamHandler", 
               'stream':"ext://sys.stdout", 
               'formatter':"general"}}, 
  'individual_log_level':{},  'formatters':{"general": {"format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"}}}, 
 'scripting':{"script_path": (os.environ.get("ODIN_SCRIPT_PATH", ""))}, 
 'services':{'hrl_ecu':{"daily_upload_limit_mb": None}, 
  'hrl_game_mode':{"daily_upload_limit_mb": 128}}, 
 'storage_handler':{'/home/odin/data_upload/archive':{"max_dir_size_bytes": 1048576}, 
  '/home/odin/HRL/udp_hrl':{"max_dir_size_bytes": 268435456}, 
  '/home/odin/HRL/ecu_hrl':{"max_dir_size_bytes": 67108864}, 
  '/home/odin/HRL/game_mode_hrl':{"max_dir_size_bytes": 134217728}}, 
 'testing':{'debug_data_enabled':False, 
  'gateway_testing_enabled':False, 
  'error_tracing_enabled':True}}

def import_yaml_config(file_location):
    global IMPORTED_YAMLS
    global options
    if file_location in IMPORTED_YAMLS:
        return
    else:
        with open(file_location, "r") as fp:
            file_config = yaml.safe_load(fp.read())
        IMPORTED_YAMLS.append(file_location)
        if INCLUDE_KEYWORD in file_config:
            for yaml_file_name in file_config[INCLUDE_KEYWORD]:
                import_location = os.path.join(os.path.dirname(file_location), yaml_file_name)
                import_yaml_config(import_location)

        options = merge_dict(options, file_config)
        if options["core"]["onboard"]:
            options["core"]["cid"]["ip"] = "127.0.0.1"


def merge_dict(d, u, depth=1):
    for k, v in u.items():
        if depth == 1:
            if k == INCLUDE_KEYWORD:
                continue
            if isinstance(v, collections.Mapping):
                if isinstance(d.get(k), set):
                    r = d[k].union(set(v))
                else:
                    r = merge_dict(d.get(k, {}), v, depth + 1)
                d[k] = r
        else:
            d[k] = u[k]

    return d

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/config.pyc
