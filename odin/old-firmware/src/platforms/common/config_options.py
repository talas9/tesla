# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/platforms/common/config_options.py
import os, logging, odin
from typing import Dict, Optional
log = logging.getLogger(__name__)

class DefaultConfigOptions:

    def __init__(self, file_name: Optional[str]=None):
        self.file_name = file_name
        self.config_options = self.load()

    def config_path(self):
        root_path = odin.get_metadata_path()
        if self.file_name is None:
            raise NotImplementedError("Undefined file name")
        return os.path.abspath(os.path.join(root_path, self.file_name))

    @staticmethod
    def format_gtw_config_qualifiers_for_vitals(gtw_config_qualifiers: Dict) -> Dict:
        return gtw_config_qualifiers

    def load(self) -> Dict:
        return {}

    def validate_gtw_config_qualifiers(self, qualifiers: dict):
        return

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/platforms/common/config_options.pyc
