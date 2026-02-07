# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/gateway/gtw_config.py
import hashlib, logging
from typing import Dict, List
from odin.core.cid.interface import get_cached_cfg_from_vitals
from odin.core import gateway
log = logging.getLogger(__name__)

class GatewayConfigMismatch(Exception):
    return


class GatewayConfigKeyUndefined(Exception):
    return


async def assert_gtw_config_match(gtw_config_qualifiers: Dict[(str, List[str])], hash_value: bool=False):
    if not gtw_config_qualifiers:
        return
    formatted_qualifiers = gateway.gtw_config_options.format_gtw_config_qualifiers_for_vitals(gtw_config_qualifiers)
    try:
        current_gtw_configs = await get_cached_cfg_from_vitals()
    except KeyError as err:
        raise GatewayConfigKeyUndefined("Undefined Gateway config: {}".format(repr(err)))

    for config_name, valid_gtw_configs_values in formatted_qualifiers.items():
        current_value = current_gtw_configs[config_name]
        if hash_value:
            current_value = hashlib.sha256(current_value.encode("utf-8")).hexdigest()
        if current_value not in valid_gtw_configs_values:
            msg = f"Mismatch for {config_name}: config_value={current_value}, valid_values={valid_gtw_configs_values}"
            raise GatewayConfigMismatch(msg)

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/gateway/gtw_config.pyc
