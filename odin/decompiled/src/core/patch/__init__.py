# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/patch/__init__.py
import os
from odin import config
PATCH_HOME = os.path.join("/", "home", "odin", "patch")
ODIN_ROOT = os.path.join("/", "opt", "odin")
ODIN_KEYS = os.path.join(config.assets_location(), "keys")

class PatchInfo(RuntimeError):
    return


class PatchNotInstalled(PatchInfo):
    return


class PatchAlreadyMounted(PatchInfo):
    return


class PatchNonPersist(PatchInfo):
    return


class PatchError(RuntimeError):
    return


class PatchStillMounted(PatchError):
    return


class PatchFirmwareSignatureNotFound(PatchError):
    return


class SigResError(PatchError):
    return


class InsufficientFilesystemStorage(PatchError):
    return

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/patch/__init__.pyc
