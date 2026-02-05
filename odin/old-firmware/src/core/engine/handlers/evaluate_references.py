# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/engine/handlers/evaluate_references.py
import json
from logging import getLogger
from architect.core.network import Network
from architect.adapters.module_storage import ModuleStorageAdapter
from architect.adapters.client import SimpleClient
from architect.adapters.client import ModuleSimpleClient
from architect.adapters.simple_fs_storage import SimpleFSStorage
from architect.ports.client import ClientPort
from architect.ports.storage import StoragePort
from architect.workflows.path_resolver import RawPathResolver
import odin
log = getLogger(__name__)

class ReferenceSimpleClientAdapter(SimpleClient):

    def __init__(self, root, references=None, **kw):
        self.references = references or {}
        (super().__init__)(root, **kw)

    def create_storage_port(self) -> StoragePort:
        return ReferencesSotrageAdapter.create_port((self.root), references=(self.references))


class ReferencesSotrageAdapter(SimpleFSStorage):

    def __init__(self, root, references=None, **kw):
        (super().__init__)(root, **kw)
        self.path_resolver = RawPathResolver()
        self.references = references or {}

    async def load_string_from_basename_and_version(self, name, version=None):
        if name in self.references:
            return json.dumps(self.references[name])
        else:
            return await super().load_string_from_basename_and_version(name, version=version)


class ReferencesModuleSimpleClientAdapter(ModuleSimpleClient):

    def __init__(self, root, references=None, **kw):
        self.references = references or {}
        (super().__init__)(root, **kw)

    def create_storage_port(self) -> StoragePort:
        return ReferencesModuleStorageAdapter.create_port((self.root), references=(self.references))


class ReferencesModuleStorageAdapter(ModuleStorageAdapter):

    def __init__(self, root, references=None, **kw):
        (super().__init__)(root, **kw)
        self.references = references or {}

    async def load_string_from_basename_and_version(self, name, version=None):
        task_name = name.replace(self.root + "/", "")
        if task_name in self.references:
            return self.references[task_name]
        else:
            return await json.loads(super().load_string_from_basename_and_version(name, version=version))


async def load_network_with_references(network_data: dict, references: dict) -> Network:
    client = make_references_client(references)
    return await client.asset_manager.load_from_data(network_data)


def make_references_client(references: dict) -> ClientPort:
    network_module = odin.get_network_module()
    if network_module:
        return ReferencesModuleSimpleClientAdapter.create_port(network_module, references=references)
    else:
        return ReferenceSimpleClientAdapter.create_port((odin.get_network_path()), references=references)

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/engine/handlers/evaluate_references.pyc
