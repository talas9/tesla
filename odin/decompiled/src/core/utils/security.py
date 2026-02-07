# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/utils/security.py
import logging, os, string, sys
from odin.core.utils import payload
log = logging.getLogger(__name__)
FILE_BLACKLIST = frozenset(["/var/etc/.pseudonym",
 "/etc/shadow"])
PREFIX_BLACKLIST = frozenset(["/var/lib/connman/wifi_",
 "/var/etc/saccess",
 "/var/lib/car_creds/",
 "/var/etc/openvpn/"])
ALLOWED_CREDS = frozenset(["/var/lib/car_creds/car.crt",
 "/var/lib/car_creds/ca.crt",
 "/var/etc/openvpn/car.crt",
 "/var/etc/openvpn/ca.crt"])

def file_blacklisted(filename: str):
    actual_path = os.path.abspath(os.path.realpath(filename))
    if actual_path in FILE_BLACKLIST:
        return True
    else:
        for prefix in PREFIX_BLACKLIST:
            if actual_path.startswith(prefix):
                if actual_path not in ALLOWED_CREDS:
                    return True

        return False


def demote(user: str='odin_script'):

    def result():
        try:
            from pwd import getpwnam
        except ImportError:
            if sys.platform.startswith("win"):
                log.warning("Unable to change process user on {}".format(sys.platform))
                return
            raise ImportError

        if os.getgid() == 0:
            os.setgid(getpwnam(user).pw_gid)
        if os.getuid() == 0:
            os.setuid(getpwnam(user).pw_uid)

    return result


def validate_authored_popup_id(s: str):
    allowed_chars = string.ascii_letters + string.digits + "_-"
    payload.validate_safe_string(s, allowed_chars)

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/utils/security.pyc
