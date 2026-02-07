# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/platforms/platform_switch.py
import logging, os, yaml
from architect.core.register_meta import RegisterNodeMeta, REGISTER_WITH_NAME
from odin.exceptions import OdinException
from typing import Optional
log = logging.getLogger(__name__)

def get_gateway_interface_lower(platform: Optional[str]) -> Optional[str]:
    from odin import get_metadata_path
    if not platform:
        return
    root_path = get_metadata_path(platform)
    info_path = os.path.join(root_path, "interfaces.yaml")
    with open(info_path, "r") as f:
        info = yaml.safe_load(f)
    gw_int = info.get("gateway_interface")
    if gw_int:
        return gw_int.lower()


def _get_name_of_class(new_class):
    if hasattr(new_class, REGISTER_WITH_NAME):
        return getattr(new_class, REGISTER_WITH_NAME)
    else:
        module_name = new_class.__module__.rsplit(".")[-1]
        return "{}.{}".format(module_name, new_class.__name__)


def _get_fqname_of_class(new_class):
    if hasattr(new_class, REGISTER_WITH_NAME):
        return getattr(new_class, REGISTER_WITH_NAME)
    else:
        module_name = new_class.__module__
        return "{}.{}".format(module_name, new_class.__name__)


def _rekey_classes(prefix, func_name):
    rekey_items = [(k, v) for k, v in RegisterNodeMeta.subclasses.items() if v.__module__.startswith(prefix)]
    for k, v in rekey_items:
        del RegisterNodeMeta.subclasses[k]
        RegisterNodeMeta.subclasses[func_name(v)] = v


def _toggle_classes(push_prefix: str, pop_prefix: str):
    _rekey_classes(push_prefix, _get_fqname_of_class)
    _rekey_classes(pop_prefix, _get_name_of_class)


def toggle_platform_nodes(target_platform: str):
    import odin
    if not odin.__platform__:
        return
    else:
        current_gw = get_gateway_interface_lower(odin.__platform__)
        target_gw = get_gateway_interface_lower(target_platform)
        if current_gw and target_gw:
            if target_gw != current_gw:
                module_prefix = "odin.platforms.{}.nodes."
                _toggle_classes(module_prefix.format(current_gw), module_prefix.format(target_gw))
        else:
            OdinException("Invalid platform switching from {}(gateway: {}) to {}(gateway: {})".format(odin.__platform__, current_gw, target_platform, target_gw))


def switch_platform_to(target_platform: str, fw_version: str='') -> bool:
    from odin import configure_as
    from odin import exceptions
    try:
        toggle_platform_nodes(target_platform)
    except exceptions.MissingData:
        log.exception("Failed to toggle platform, ODIN will not function properly")
        return False
    else:
        return configure_as(target_platform, fw_version)

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/platforms/platform_switch.pyc
