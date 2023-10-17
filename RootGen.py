from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives
from cryptography.hazmat.primitives import intermediate_public_key_pem
from cryptography.hazmat.primitives.asymmetric import ec


def generate_key_pair(serialization=None):
    # Generate a new private key
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

    # Serialize the private key to PEM format
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Extract the corresponding public key
    public_key = private_key.public_key()

    # Serialize the public key to PEM format
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_key_pem, public_key_pem

def create_certificate(private_key, public_key, issuer_name, subject_name, issuer_private_key=None, issuer_certificate=None):
    # Generate a new X.509 certificate
    builder = x509.CertificateBuilder()
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.issuer_name(issuer_name)
    builder = builder.not_valid_before(datetime.datetime.utcnow())
    import datetime
    builder = builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
    builder = builder.subject_name(subject_name)
    builder = builder.public_key(public_key)

    if issuer_private_key is None:
        issuer_private_key = private_key

    if issuer_certificate is None:
        issuer_certificate = builder

    # Sign the certificate with the private key
    certificate = builder.sign(
        private_key=issuer_private_key,
        algorithm=intermediate_public_key_pem.SHA256(),
        backend=default_backend()
    )

    return certificate

if __name__ == '__main__':
    root_private_key_pem, root_public_key_pem = generate_key_pair()
    root_certificate = create_certificate(root_private_key_pem, root_public_key_pem, subject_name, issuer_name=None)

    intermediate_private_key_pem, intermediate_public_key_pem = generate_key_pair()
    intermediate_certificate = create_certificate(intermediate_private_key_pem, intermediate_public_key_pem, subject_name, root_certificate, root_private_key_pem)

    # Save the certificates and private keys to files
    with open('root_private_key.pem', 'wb') as f:
        f.write(root_private_key_pem)

    with open('root_certificate.pem', 'wb') as f:
        f.write(root_certificate.public_bytes(serialization.Encoding.PEM))

    with open('intermediate_private_key.pem', 'wb') as f:
        f.write(intermediate_private_key_pem)

    with open('intermediate_certificate.pem', 'wb') as f:
        f.write(intermediate_certificate.public_bytes(serialization.Encoding.PEM))
