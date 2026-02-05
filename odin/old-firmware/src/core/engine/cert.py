# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/engine/cert.py
import jwt, os
from aiohttp.web import HTTPUnauthorized
from cryptography.exceptions import InvalidSignature
from cryptography.x509 import Certificate
from cryptography.x509 import load_pem_x509_certificate
from cryptography.x509 import ExtendedKeyUsage
from cryptography.x509.oid import NameOID
from cryptography.x509.oid import ObjectIdentifier
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from typing import List
from odin.config import options
from ..utils.singleton import make_singleton_getter
from ..cid.interface import get_vin, is_fused
CN_ISSUER_COMMON_NAME = "Tesla Motors GF3 Product Issuing CA"
ENCODING_ALGORITHM = "ES256"
CERTS = {'CN':{'issuer_cert':"TeslaMotorsGF3ProductIssuingCA.pem", 
  'eku_eng':"1.3.6.1.4.1.49279.2.4.6.1", 
  'eku_prod':"1.3.6.1.4.1.49279.2.5.6.1"}, 
 'US':{"issuer_cert": "tesla-services-command-ca.pem"}}

def load_cert_file(cert: str) -> Certificate:
    file_path = get_cert_path(cert)
    with open(file_path, "rb") as f:
        return cert_from_data(f.read())


def get_cert_path(cert: str) -> str:
    return os.path.join(options["core"]["certificate_dir"], cert)


def cert_from_data(data: bytes) -> Certificate:
    return load_pem_x509_certificate(data, default_backend())


get_cn_issue_cert = make_singleton_getter(load_cert_file, CERTS["CN"]["issuer_cert"])
get_us_issue_cert = make_singleton_getter(load_cert_file, CERTS["US"]["issuer_cert"])

async def verify_cert_against_master(cert: Certificate):
    cn_cert = is_cn_intermediate_cert(cert)
    issuer_cert = get_cn_issue_cert() if cn_cert else get_us_issue_cert()
    authenticate_cert(issuer_cert, cert)
    if cn_cert:
        await assert_is_cn_vin()
        await verify_cert_ekus(cert, cert_issuer="CN")


def is_cn_intermediate_cert(cert: Certificate):
    issuer_common_name = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    return issuer_common_name == CN_ISSUER_COMMON_NAME


def authenticate_cert(issuer_cert: Certificate, cert: Certificate):
    try:
        issuer_cert.public_key().verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))
    except InvalidSignature:
        raise HTTPUnauthorized(reason="Invalid certificate.")


async def assert_is_cn_vin():
    vin = await safe_get_vin()
    if not vin.startswith("LRW"):
        raise HTTPUnauthorized(reason="Prohibited CN Certificate")


async def safe_get_vin() -> str:
    try:
        return await get_vin()
    except Exception:
        raise HTTPUnauthorized(reason="Could not retrieve product id.")


async def verify_cert_ekus(cert: Certificate, cert_issuer: str):
    cert_ekus = list(cert.extensions.get_extension_for_class(ExtendedKeyUsage).value)
    if not await is_fused():
        valid_eng_eku = CERTS.get(cert_issuer, {}).get("eku_eng")
        if valid_eng_eku:
            if eku_dotted_string_match(cert_ekus, valid_eng_eku):
                return
    valid_prod_eku = CERTS.get(cert_issuer, {}).get("eku_prod")
    if valid_prod_eku:
        if eku_dotted_string_match(cert_ekus, valid_prod_eku):
            return
    raise HTTPUnauthorized(reason="Invalid Extended Key Usage attributes (certificate is bad)")


def eku_dotted_string_match(cert_ekus: List[ObjectIdentifier], valid_eku: str) -> bool:
    for eku in cert_ekus:
        if eku.dotted_string == valid_eku:
            return True

    return False


def decode_with_cert(data: bytes, cert: Certificate) -> dict:
    return jwt.decode(data,
      (public_key_from_cert(cert)),
      algorithms=[
     ENCODING_ALGORITHM])


def public_key_from_cert(cert: Certificate) -> bytes:
    return cert.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/engine/cert.pyc
