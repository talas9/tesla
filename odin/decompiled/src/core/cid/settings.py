# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/cid/settings.py
from odin.config import options
IP = options["core"]["cid"]["ip"]
DEFAULT_TIMEOUT = 10
DEFAULT_LOG_SEARCH_PATH = "/var/log/*"
DEFAULT_LOG_SEARCH_ALLOWED_DIRS = ["/var/log/", "/home/tesla/.crashlogs/", "/home/tesla/.paniclogs/"]
HERMES_CERT_PATHS = ["/var/lib/car_creds", "/var/etc/openvpn"]
USERNAME = "root"
PASSWORD = "root"
PORTS = {
 'audiod': 4050, 
 'bluetooth': 4094, 
 'carserver': 7654, 
 'diag': 4035, 
 'netmanager': 4060, 
 'center_display': 4070, 
 'parrot': 4090, 
 'vehicle': 4030, 
 'carbrowser': 4140, 
 'cid_updater': 20564, 
 'cid_updater_telnet': 25956}

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/cid/settings.pyc
