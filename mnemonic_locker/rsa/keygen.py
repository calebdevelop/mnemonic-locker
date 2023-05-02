from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey
import os


def generate_rsa(key_size=2048):
    """
    Generate an RSA key pair with the specified length.
    By default, the length is 2048 bits.
    Returns a tuple (public key, private key).
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )

    public_key = private_key.public_key()

    return public_key, private_key


def save(public_key: RSAPublicKey, private_key: RSAPrivateKey, password: str = None, output_dir: str = None) -> str:
    if output_dir is None:
        output_dir = os.path.join(os.getcwd(), 'output')

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    if not password:
        encryption_algorithm = serialization.NoEncryption()
        print("No password provided.")
    else:
        encryption_algorithm = serialization.BestAvailableEncryption(password.encode())

    with open(os.path.join(output_dir, 'private_key.pem'), 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        ))

    with open(os.path.join(output_dir, 'public_key.pem'), 'wb') as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    return output_dir
