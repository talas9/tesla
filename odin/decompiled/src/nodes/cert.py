# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/nodes/cert.py
__authors__ = [
 "David Exe"]
__author__ = ",".join(__authors__)
__email__ = "dexe@teslamotors.com"
__copyright__ = "Copyright Tesla Motors Inc. 2017"
import asyncio, logging
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from architect.core.node import Node
from architect.core.ops.input import Input
from architect.core.ops.output import Output, output
from architect.core.ops.signal import Signal
from architect.core.ops.slot import slot
from binascii import unhexlify
log = logging.getLogger(__name__)

class CreateCSR(Node):
    country_name = Input("String", default="US")
    state_name = Input("String", default="CA")
    locality_name = Input("String", default="Palo Alto")
    org_name = Input("String", default="Tesla")
    org_unit_name = Input("String", default="Tesla Motors")
    vin_common_name = Input("String")
    csr = Output("Bytes")
    private_key = Output("Bytes")
    public_key = Output("Bytes")
    done = Signal()

    @slot()
    async def run(self):
        country_name, state_name, locality_name, org_name, org_unit_name, vin_common_name = await asyncio.gather(self.country_name(), self.state_name(), self.locality_name(), self.org_name(), self.org_unit_name(), self.vin_common_name())
        pkey = ec.generate_private_key(curve=(ec.SECP256R1()),
          backend=(default_backend()))
        self.public_key.value = pkey.public_key().public_numbers().encode_point()
        privateKeyHexString = "{:064x}".format(pkey.private_numbers().private_value)
        self.private_key.value = unhexlify(privateKeyHexString)
        csr_data = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
         x509.NameAttribute(NameOID.COUNTRY_NAME, country_name),
         x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state_name),
         x509.NameAttribute(NameOID.LOCALITY_NAME, locality_name),
         x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_name),
         x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, org_unit_name),
         x509.NameAttribute(NameOID.COMMON_NAME, vin_common_name)])).sign(pkey, hashes.SHA256(), default_backend())
        self.csr.value = csr_data.public_bytes(serialization.Encoding.PEM)
        await self.done()


class ConvertCert(Node):
    pem_csr = Input("Bytes")

    @output("Bytes")
    async def der_csr(self):
        pem_csr = await self.pem_csr()
        cert = x509.load_pem_x509_certificate(pem_csr, default_backend())
        return cert.public_bytes(encoding=(serialization.Encoding.DER))


class CreatePEMPKey(Node):
    private_value = Input("Bytes")

    @output("Bytes")
    async def PEMkey(self):
        private_value = await self.private_value()
        intPrivateValue = int.from_bytes(private_value, byteorder="big")
        pkey = ec.derive_private_key(private_value=intPrivateValue, curve=(ec.SECP256R1()),
          backend=(default_backend()))
        pem = pkey.private_bytes(encoding=(serialization.Encoding.PEM), format=(serialization.PrivateFormat.TraditionalOpenSSL),
          encryption_algorithm=(serialization.NoEncryption()))
        return pem


class GetPublicKey(Node):
    cert_type = Input("Int", default=0, enum=[
     (0, 'PEM'),
     (1, 'DER')])
    cert = Input("Bytes")

    @output("Bytes")
    async def PubKey(self):
        cert_type, cert = await asyncio.gather(self.cert_type(), self.cert())
        if cert_type == 0:
            loadedCert = x509.load_pem_x509_certificate(data=cert, backend=(default_backend()))
        else:
            if cert_type == 1:
                loadedCert = x509.load_der_x509_certificate(data=cert, backend=(default_backend()))
        return loadedCert.public_key().public_numbers().encode_point()

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/nodes/cert.pyc
