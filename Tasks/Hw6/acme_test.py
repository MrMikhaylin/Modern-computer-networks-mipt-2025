import pytest
import requests
import os
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

ACME_URL = os.getenv("ACME_URL", "http://127.0.0.1:3280")
ACME_SIGN_URL = f"{ACME_URL}/sign"
ACME_VERIFY_URL = f"{ACME_URL}/verify"
PHRASE = "d2caac68c555fa37e412171cd5240e2d0bb1bea23d4ccdb950157d37136ebcf46ed3263984d5ec5ffbb5cd4e7092b2c802b9d5a9c372c3492afa09eaf35fb9ac"
TEST_TIMEOUT = 100


def test_sign():
    response = requests.post(ACME_SIGN_URL, timeout=1)
    assert response.status_code == 400
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    response = requests.post(
        ACME_SIGN_URL,
        timeout=TEST_TIMEOUT,
        headers={
            "x-Public-Key": private_key.public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .hex()
        },
    )
    assert response.status_code == 401
    response = requests.post(
        ACME_SIGN_URL,
        timeout=TEST_TIMEOUT,
        headers={
            "x-Public-Key": private_key.public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .hex(),
            "Authorization": "0ab0ba",
        },
    )
    assert response.status_code == 403

    response = requests.post(
        ACME_SIGN_URL,
        timeout=TEST_TIMEOUT,
        headers={
            "x-Public-Key": private_key.public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .hex(),
            "Authorization": private_key.sign(
                PHRASE.encode(), padding.PKCS1v15(), algorithm=hashes.SHA1()
            ).hex(),
        },
    )
    assert response.status_code == 400
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "RU"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Moscow"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Moscow"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ISP RAS"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Tester"),
        ]
    )
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .sign(private_key, hashes.SHA256())
    )
    response = requests.post(
        ACME_SIGN_URL,
        timeout=TEST_TIMEOUT,
        data=csr.public_bytes(encoding=serialization.Encoding.PEM),
        headers={
            "x-Public-Key": private_key.public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .hex(),
            "Authorization": private_key.sign(
                PHRASE.encode(), padding.PKCS1v15(), algorithm=hashes.SHA1()
            ).hex(),
        },
    )
    assert response.status_code == 201
    x509.load_pem_x509_certificate(response.content)
    response = requests.post(
        ACME_SIGN_URL,
        timeout=TEST_TIMEOUT,
        data=csr.public_bytes(encoding=serialization.Encoding.PEM),
        headers={
            "x-Public-Key": private_key.public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .hex(),
            "Authorization": private_key.sign(
                PHRASE.encode(), padding.PKCS1v15(), algorithm=hashes.SHA1()
            ).hex(),
        },
    )
    assert response.status_code == 409


def test_verify():
    response = requests.get(ACME_VERIFY_URL, timeout=1)
    assert response.status_code == 400
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    response = requests.get(
        ACME_VERIFY_URL,
        timeout=TEST_TIMEOUT,
        headers={
            "x-Public-Key": private_key.public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .hex()
        },
    )
    assert response.status_code == 404
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "RU"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Moscow"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Moscow"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ISP RAS"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Tester"),
        ]
    )
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .sign(private_key, hashes.SHA256())
    )
    response = requests.post(
        ACME_SIGN_URL,
        timeout=TEST_TIMEOUT,
        data=csr.public_bytes(encoding=serialization.Encoding.PEM),
        headers={
            "x-Public-Key": private_key.public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .hex(),
            "Authorization": private_key.sign(
                PHRASE.encode(), padding.PKCS1v15(), algorithm=hashes.SHA1()
            ).hex(),
        },
    )
    response = requests.get(
        ACME_VERIFY_URL,
        timeout=TEST_TIMEOUT,
        headers={
            "x-Public-Key": private_key.public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .hex()
        },
    )
    assert response.status_code == 200 and response.content.decode() == 'TRUE'
