import hashlib
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
from cryptography.hazmat.primitives import padding

from mnemonic_locker.EncodingTools.shuffler import Shuffler


class AESCipher:
    BLOCK_SIZE = 128

    def __init__(self, key: str):
        self.key = hashlib.sha256(key.encode("utf-8")).digest()[:self.BLOCK_SIZE]

    def encrypt(self, message: str):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        padder = padding.PKCS7(self.BLOCK_SIZE).padder()
        padded_message = padder.update(message.encode("utf-8")) + padder.finalize()
        encryptor = cipher.encryptor()
        ct = encryptor.update(padded_message) + encryptor.finalize()
        return base64.urlsafe_b64encode(iv + ct).decode()

    def decrypt(self, encoded_message: str):
        decoded = base64.urlsafe_b64decode(encoded_message.encode())
        iv = decoded[:16]
        ct = decoded[16:]
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(self.BLOCK_SIZE).unpadder()
        padded_message = decryptor.update(ct) + decryptor.finalize()
        message = unpadder.update(padded_message) + unpadder.finalize()
        return message.decode()


class PasswordGenerator:
    BLOCK_SIZE = 128

    def __init__(self, master_password: str, key: str):
        self.master_password = hashlib.sha256(master_password.encode("utf-8")).digest()
        self.key = hashlib.sha256(key.encode("utf-8")).digest()[:self.BLOCK_SIZE]
        shuffler = Shuffler(master_password)
        shuffled = shuffler.shuffle(key)
        self.iv = hashlib.sha256(shuffled.encode("utf-8")).digest()[:16]

    def generate(self):
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv), backend=default_backend())
        padder = padding.PKCS7(512).padder()
        padded_message = padder.update(self.master_password) + padder.finalize()
        encryptor = cipher.encryptor()
        ct = encryptor.update(padded_message) + encryptor.finalize()
        return base64.b85encode(self.iv + ct).decode()
