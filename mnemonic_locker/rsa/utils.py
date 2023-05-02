from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key


def encrypt_with_rsa_public_key(public_key: PublicKeyTypes, data: bytes) -> bytes:
    max_len = (public_key.key_size // 8) - hashes.SHA512().block_size - 2

    if len(data) > max_len:
        ciphertext_blocks = []
        for i in range(0, len(data), max_len):
            block = data[i:i + max_len]
            ciphertext_block = public_key.encrypt(
                block,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA512()),
                    algorithm=hashes.SHA512(),
                    label=None
                )
            )
            ciphertext_blocks.append(ciphertext_block)
        ciphertext = b''.join(ciphertext_blocks)
    else:
        # Encrypt the data with the public key using OAEP padding and SHA-512 hash function
        ciphertext = public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA512()),
                algorithm=hashes.SHA512(),
                label=None
            )
        )

    return ciphertext


def is_private_key_encrypted(path):
    with open(path, "rb") as key_file:
        private_key_bytes = key_file.read()
        try:
            load_pem_private_key(private_key_bytes, password=None, backend=default_backend())
        except (UnsupportedAlgorithm, ValueError):
            return True

    return False


def decrypt_with_rsa_private_key(private_key_path: str, password: str, ciphertext: bytes) -> bytes:
    # Load the private key from the file
    with open(private_key_path, "rb") as key_file:
        private_key_bytes = key_file.read()
        private_key = load_pem_private_key(private_key_bytes, password.encode(), default_backend())
        block_size = (private_key.key_size // 8)

        if len(ciphertext) % block_size == 0:
            num_blocks = len(ciphertext) // block_size
            plain_blocks = []
            for i in range(num_blocks):
                block = ciphertext[i * block_size:(i + 1) * block_size]
                plain_block = private_key.decrypt(
                    block,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA512()),
                        algorithm=hashes.SHA512(),
                        label=None
                    )
                )
                plain_blocks.append(plain_block)
            plaintext = b"".join(plain_blocks)
        else:
            # Decrypt the ciphertext using the private key
            plaintext = private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA512()),
                    algorithm=hashes.SHA512(),
                    label=None
                )
            )

        return plaintext


def is_private_key_protected(key_path):
    with open(key_path, 'rb') as key_file:
        key_data = key_file.read()
    try:
        load_pem_private_key(key_data, password=None, backend=default_backend())
    except ValueError as e:
        if 'encrypted' in str(e):
            return True
    return False
