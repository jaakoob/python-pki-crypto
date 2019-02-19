import datetime
import uuid

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509 import NameOID

with open("ca.pem", "rb") as ca_key_file:
    ca_key = serialization.load_pem_private_key(
        ca_key_file.read(),
        password=b'password',
        backend=default_backend()
    )

with open("ca.crt", "rb") as ca_crt_file:
    ca_crt = x509.load_pem_x509_certificate(
        ca_crt_file.read(),
        backend=default_backend()
    )

with open("csr.pem", "rb") as csr_file:
    csr = x509.load_pem_x509_csr(
        csr_file.read(),
        backend=default_backend()
    )

lifetime = datetime.timedelta(days=180)

builder = x509.CertificateBuilder()
builder = builder.subject_name(csr.subject)
builder = builder.issuer_name(ca_crt.subject)
builder = builder.not_valid_before(datetime.datetime.now())
builder = builder.not_valid_after(datetime.datetime.now() + lifetime)
builder = builder.serial_number(int(uuid.uuid4()))
builder = builder.public_key(csr.public_key())
builder = builder.add_extension(extension=x509.KeyUsage(
    digital_signature=True,
    key_encipherment=True,
    content_commitment=True,
    data_encipherment=False,
    key_agreement=False,
    encipher_only=False,
    decipher_only=False,
    key_cert_sign=False,
    crl_sign=False
), critical=True)
builder = builder.add_extension(extension=x509.BasicConstraints(
    ca=False,
    path_length=None
), critical=True)
builder = builder.add_extension(extension=x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                                critical=False)
crt = builder.sign(private_key=ca_key,
                       algorithm=hashes.SHA256(),
                       backend=default_backend())

with open("key.crt", "wb") as f:
    f.write(crt.public_bytes(encoding=serialization.Encoding.PEM))