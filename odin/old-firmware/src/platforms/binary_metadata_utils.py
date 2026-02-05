# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/platforms/binary_metadata_utils.py
import base64, pickle
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
C = b'Y21mdHVieGk3d2x2bWgxd21ienowMHZmMXppcWV6ZjY='

def _get_key(salt, p):
    p = base64.b64decode(p)
    kdf = PBKDF2HMAC(algorithm=(hashes.SHA256()),
      length=32,
      salt=salt,
      iterations=123456,
      backend=(default_backend()))
    return base64.urlsafe_b64encode(kdf.derive(p))


def binary_metadata_reader(file_path):
    with open(file_path, "rb") as fp:
        content = fp.read()
    salt = content[:16]
    encoded = content[16:]
    key = _get_key(salt, C)
    return pickle.loads(Fernet(key).decrypt(encoded))

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/platforms/binary_metadata_utils.pyc
