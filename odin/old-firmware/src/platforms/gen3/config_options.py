# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/platforms/gen3/config_options.py
import hashlib, json, logging
from typing import Dict, List, Union
from ..common.config_options import DefaultConfigOptions
log = logging.getLogger(__name__)

class Gen3ConfigOptions(DefaultConfigOptions):
    FILE_NAME = "config-options.json"
    VITALS_PREFIX = "cfg_"
    SALT_KEY = "s"
    CONTENT_KEY = "c"

    def __init__(self):
        self.salt = None
        self.is_encoded_json = False
        super().__init__(self.FILE_NAME)

    def format_gtw_config_qualifiers_for_vitals(self, gtw_config_qualifiers: Dict) -> Dict:
        return {self.VITALS_PREFIX + config_key.lower(): config_values for config_key, config_values in gtw_config_qualifiers.items()}

    def load(self) -> Dict:
        config_options_path = self.config_path()
        try:
            with open(config_options_path, "r") as file:
                data = file.read()
                json_data = json.loads(data)
            if isinstance(json_data, dict):
                self.salt = json_data.get(self.SALT_KEY, None)
            if not self.salt:
                self.is_encoded_json = False
                log.info("Loaded {} is NOT encoded.".format(config_options_path))
                return self._walk_and_reformat(json_data)
            else:
                self.is_encoded_json = True
                return json_data.get(self.CONTENT_KEY, {})
        except FileNotFoundError:
            log.error("Could not find: {}".format(config_options_path))
        except json.JSONDecodeError:
            log.error("Corrupted file: {}".format(config_options_path))

        return {}

    def _walk_and_reformat(self, node: Union[(List, Dict)]) -> Dict:
        if isinstance(node, list):
            node = self._format_dict(node)
        for key, item in node.items():
            if isinstance(item, list):
                node[key] = self._format_dict(item)
            if isinstance(item, dict):
                self._walk_and_reformat(item)

        return node

    @staticmethod
    def _generate_sha256(data) -> str:
        bytes_data = data.encode() if isinstance(data, str) else data
        return hashlib.sha256(bytes_data).hexdigest()

    @staticmethod
    def _format_dict(list_to_format: List) -> Dict:
        return {option.pop("codeKey"): option for option in list_to_format if "codeKey" in option}

    def validate_gtw_config_qualifiers(self, qualifiers: dict):
        if not qualifiers:
            return
        for key, enum_values in qualifiers.items():
            self._validate_values(key, enum_values)

    def _validate_values(self, config_key: str, enum_values: List[str]):
        check_key = self._generate_keyhash(config_key) if self.is_encoded_json else config_key
        valid_key = check_key in self.config_options
        if not valid_key:
            raise KeyError("Invalid config option key: {}({})".format(config_key, check_key))
        valid_values = self.config_options[check_key]
        if valid_values:
            for value in enum_values:
                if self.is_encoded_json:
                    hashed_value = self._generate_valuehash(config_key, value)
                    if hashed_value not in valid_values:
                        raise KeyError("Invalid value: {}({}) for key {}".format(value, hashed_value, config_key))
                    else:
                        valid_enums = valid_values["content"]["enums"]
                        if value not in valid_enums:
                            raise KeyError("Invalid value: {}. Available values for key {}: {}".format(value, config_key, list(valid_enums.keys())))

    def _generate_keyhash(self, key: str) -> str:
        return self._generate_sha256("{}{}".format(key, self.salt))

    def _generate_valuehash(self, key: str, value: str) -> str:
        return self._generate_sha256("{}{}{}".format(value, key, self.salt))

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/platforms/gen3/config_options.pyc
