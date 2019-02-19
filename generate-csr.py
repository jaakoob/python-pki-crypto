from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization

with open("key.pem", "rb") as key_file:
    key = serialization.load_pem_private_key(
        key_file.read(),
        password = b"password",
        backend = default_backend()
    )

csr = x509.CertificateSigningRequestBuilder().subject_name(
    x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"DE"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"BY"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Munich"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'MyOrg'),
        x509.NameAttribute(NameOID.COMMON_NAME, 'mysite.org')
    ])).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(u"mysite.org"),
            x509.DNSName(u"mysite2.org")
        ]),
        critical=False,
    ).sign(key, hashes.SHA512(), default_backend())

with open("csr.pem", "wb") as f:
    f.write(csr.public_bytes(serialization.Encoding.PEM))