import datetime
import uuid

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import NameOID

lifetime = datetime.timedelta(days=365)

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()

certificate = x509.CertificateBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"My Test CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"MyOrg")
    ])).issuer_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"My Test CA")
    ])).not_valid_before(
        datetime.datetime.now()
    ).not_valid_after(
        datetime.datetime.now() + lifetime
    ).serial_number(
        int(uuid.uuid4())
    ).public_key(
        public_key
    ).add_extension(
        x509.BasicConstraints(
            ca=True,
            path_length=None
        ),
        critical=True
    ).add_extension(
        x509.NameConstraints(
            permitted_subtrees=(
                x509.DNSName("*.test.org"),
                x509.RFC822Name("*@*.test.org"),
                x509.RFC822Name("*@test.org")
            ),
            excluded_subtrees=(),
        ),
        critical=True
    ).sign(
        private_key=private_key,
        algorithm=hashes.SHA256(),
        backend=default_backend()
    )

with open("ca-name-restrict.pem", "wb") as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.BestAvailableEncryption(b"password")
    ))

with open("ca-name-restrict.crt", "wb") as f:
    f.write(certificate.public_bytes(
        encoding=serialization.Encoding.PEM
    ))