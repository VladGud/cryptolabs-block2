from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import NameOID
from cryptography.exceptions import InvalidSignature
import datetime


class CertificationAuthority:
    def __init__(self):
        self.certificates = []
        self.revoked_certificates = set()
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.root_certificate = self._create_root_certificate()

    def _create_root_certificate(self):
        builder = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Certificate Authority")]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Certificate Authority")]))
            .public_key(self.private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
        )
        return builder.sign(
            private_key=self.private_key, algorithm=hashes.SHA256(), backend=default_backend()
        )

    def sign_certificate(self, public_key, subject_name):
        for certificate in self.certificates:
            if certificate.subject.rfc4514_string() == subject_name:
                return None

        for _,  _, revoked_public_key in self.revoked_certificates:
            if public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo) == revoked_public_key:
                return None

        builder = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_name)]))
            .issuer_name(self.root_certificate.subject)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        )
        certificate = builder.sign(
            private_key=self.private_key, algorithm=hashes.SHA256(), backend=default_backend()
        )

        self.certificates.append(certificate)

        return certificate, self.root_certificate

    def revoke_certificate(self, certificate_serial):
        for i, certificate in enumerate(self.certificates):
            if certificate.serial_number == certificate_serial:
                self.certificates.pop(i)
                self.revoked_certificates.add((certificate_serial, datetime.datetime.utcnow(), certificate.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)))
                break


    def is_certificate_revoked(self, certificate_serial):
        return certificate_serial in self.revoked_certificates

    def get_revoked_certificates(self):
        crl_builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(self.root_certificate.issuer)
            .last_update(datetime.datetime.utcnow())
            .next_update(datetime.datetime.utcnow() + datetime.timedelta(days=1))
        )
        for serial_number, revoke_time, _ in self.revoked_certificates:
            crl_builder = crl_builder.add_revoked_certificate(
                x509.RevokedCertificateBuilder()
                .serial_number(serial_number)
                .revocation_date(revoke_time)
                .build()
            )
        crl = crl_builder.sign(
            private_key=self.private_key,
            algorithm=hashes.SHA256(),
            backend=default_backend()
        )
        return crl

    def validate_certificate(self, certificate):
        try:
            self.root_certificate.public_key().verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                padding.PKCS1v15(),
                certificate.signature_hash_algorithm,
            )
        except InvalidSignature:
            return False

        if self.is_certificate_revoked(certificate.serial_number):
            return False

        return True

    def process_certificate_request(self, csr):
        public_key = csr.public_key()

        try:
            public_key.verify(
                csr.signature,
                csr.tbs_certrequest_bytes,
                padding.PKCS1v15(),
                csr.signature_hash_algorithm,
            )
        except InvalidSignature:
            return None, None

        certificate = self.sign_certificate(public_key, csr.subject.rfc4514_string())
        return certificate


class User:
    def __init__(self, name, ca):
        self.name = name
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        self.certificate = None

        self.ca_root_certificate = ca.root_certificate
        self.ca = ca

    def generate_certificate_signing_request(self):
        builder = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, self.name)]))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(self.name)]), critical=False
            )
        )
        csr = builder.sign(
            private_key=self.private_key, algorithm=hashes.SHA256(), backend=default_backend()
        )
        return csr

    def generate_certificate_signing(self):
        csr = self.generate_certificate_signing_request()
        result_generate = self.ca.process_certificate_request(csr)
        if not result_generate:
            return False

        self.certificate, _ = result_generate
        return True

    def verify_certificate(self, certificate):
        try:
            crl = self.ca.get_revoked_certificates()
            
            # Проверяем подпись CRL с использованием открытого ключа корневого сертификата УЦ
            self.ca_root_certificate.public_key().verify(
                crl.signature,
                crl.tbs_certlist_bytes,
                padding.PKCS1v15(),
                crl.signature_hash_algorithm,
            )

            if crl.get_revoked_certificate_by_serial_number(certificate.serial_number) is not None:
                return False

            self.ca_root_certificate.public_key().verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                padding.PKCS1v15(),
                certificate.signature_hash_algorithm,
            )
            return True
        except InvalidSignature:
            return False

    def revoke_certificate(self):
        if self.certificate:
            self.ca.revoke_certificate(self.certificate.serial_number)


def generate_fake_certificate():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    subject = x509.Name([
           x509.NameAttribute(NameOID.COMMON_NAME, "Fake"),
    ])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
    )

    certificate = builder.sign(
        private_key=private_key,
        algorithm=hashes.SHA256(),
        backend=default_backend()
    )

    return certificate

def main_ca():
    print("Init CA, Bob and Alice...")
    ca = CertificationAuthority()
    alice = User("Alice", ca)
    bob = User("Bob", ca)
    print("Success init CA, Bob and Alice")

    print("\nGenerate Alice certificate...")
    if alice.generate_certificate_signing():
        print("Success Alice generate_certificate_signing")
    else:
        print("Failed Bob generate_certificate_signing")
        return

    print("\nGenerate Bob certificate...")
    if bob.generate_certificate_signing():
        print("Success Bob generate_certificate_signing")
    else:
        print("Failed Bob generate_certificate_signing")
        return

    print("\nVerify Alice and Bob certificate...")
    if bob.verify_certificate(alice.certificate) and alice.verify_certificate(bob.certificate):
        print("Certificates are valid.")

        print("\nRevoke Alice certificate...")
        alice.revoke_certificate()
        if not bob.verify_certificate(alice.certificate):
            print("Alice Certificate has been revoked")
        else:
            print("Alice Certificate has not been revoked")

        if not alice.generate_certificate_signing():
            print("Succes: fail to regenerate certificate")
        else:
            print("Failed: Alice can regenerate revoked certificate")
    else:
        print("Certificates are not valid.")

    print("\nVerify fake certificate...")
    if not bob.verify_certificate(generate_fake_certificate()):
        print("Found fake certificate") 

    # Получение объекта CRL
    crl = ca.get_revoked_certificates()

    # Распарсивание содержимого CRL
    parsed_crl = x509.load_pem_x509_crl(crl.public_bytes(serialization.Encoding.PEM), default_backend())

    # Извлечение серийных номеров отозванных сертификатов
    serial_numbers = [entry.serial_number for entry in parsed_crl]

    print("\nCRL")
    # Вывод серийных номеров отозванных сертификатов
    for serial_number in serial_numbers:
        print("Serial Number:", serial_number)

    print(crl.public_bytes(serialization.Encoding.PEM).decode())

if __name__ == '__main__':
    main_ca()
