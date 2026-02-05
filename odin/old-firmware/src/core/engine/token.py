# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/engine/token.py
from aiohttp.web import HTTPForbidden
from aiohttp.web import HTTPUnauthorized
from cryptography.x509 import Certificate
from cryptography.x509.oid import NameOID
from cryptography.exceptions import InvalidSignature
from dateutil.parser import parse
import datetime, logging
from jwt.exceptions import InvalidSignatureError
from .cert import verify_cert_against_master
from .cert import cert_from_data
from .cert import decode_with_cert
from .cert import safe_get_vin
from ..cid.interface import is_fused, get_fw_build_date
log = logging.getLogger(__name__)
KNOWN_SECURITY_EXCEPTIONS = (
 HTTPForbidden,
 HTTPUnauthorized,
 InvalidSignature,
 InvalidSignatureError)

class RemoteExternalForbidden(HTTPForbidden):
    return


async def validate_and_decode_message(message: dict, remote: bool=False) -> dict:
    try:
        return ({**message, **{"tokenv2": (await decode_token_using_intermediate_cert(message, remote))}})
    except RemoteExternalForbidden as exc:
        raise HTTPUnauthorized(reason=(exc.reason))
    except KNOWN_SECURITY_EXCEPTIONS as exc:
        if await is_fused():
            raise
        return ({**message})


async def decode_token_using_intermediate_cert(message: dict, remote: bool) -> dict:
    assert_require_tokenv2(message)
    intermediate_cert = await get_and_verify_intermediate_cert(message, remote)
    token = decode_token(message, intermediate_cert)
    await assert_valid_token(token)
    return token


def assert_require_tokenv2(message: dict):
    if not message.get("tokenv2"):
        raise HTTPForbidden(reason="Token 2.0 not found.")


async def get_and_verify_intermediate_cert(message: dict, remote: bool) -> Certificate:
    intermediate_cert = get_intermediate_cert(message)
    assert_not_expired(intermediate_cert)
    assert_not_remote_and_external(intermediate_cert, remote)
    await verify_cert_against_master(intermediate_cert)
    return intermediate_cert


def get_intermediate_cert(message: dict) -> Certificate:
    return cert_from_data(bytes(message["tokenv2"]["intermediate_certificate"], "utf-8"))


def assert_not_expired(cert: Certificate):
    if datetime.datetime.utcnow() > cert.not_valid_after:
        raise HTTPUnauthorized(reason="Intermediate certificate has expired.")


def assert_not_remote_and_external(cert: Certificate, remote: bool):
    if remote:
        if subject_contains(cert, "external"):
            log.warning("Remote request from external sources detected!")


def subject_contains(cert: Certificate, substring: str) -> bool:
    for subject in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
        if substring in subject.value:
            return True

    return False


def decode_token(message: dict, cert: Certificate) -> dict:
    return decode_with_cert(message["tokenv2"]["token"], cert)


async def assert_valid_token(token: dict) -> None:
    await assert_token_expiration(token)
    await assert_product_id(token)


async def assert_token_expiration(token: dict) -> None:
    expires_date = parse(token.get("expires_at"))
    if datetime.datetime.now() > expires_date:
        raise HTTPUnauthorized(reason="Bearer token has expired.")
    build_date = await get_fw_build_date()
    if build_date:
        if build_date > expires_date:
            raise HTTPUnauthorized(reason="Bearer token has expired by build date.")


async def assert_product_id(token: dict) -> None:
    product_id = token.get("product_id")
    if product_id == "current":
        raise RemoteExternalForbidden(reason='The product_id "current" is deprecated.')
    current_id = await safe_get_vin()
    if product_id != current_id:
        raise HTTPForbidden(reason="Invalid product id")

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/engine/token.pyc
