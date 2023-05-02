import hashlib

from mnemonic_locker.EncodingTools.ciphers import AESCipher
from mnemonic_locker.EncodingTools.shuffler import Shuffler


class TextEncoder:
    def __init__(self, password: str):
        hash_object = hashlib.sha256(password.encode('utf-8'))
        self.password = hash_object.hexdigest()

    def encode(self, text: str):
        shuffler = Shuffler(self.password)
        shuffled_text = shuffler.shuffle(text)
        cipher = AESCipher(self.password)
        return cipher.encrypt(shuffled_text)

    def decode(self, encoded_message: str):
        cipher = AESCipher(self.password)
        decoded_text = cipher.decrypt(encoded_message)
        shuffler = Shuffler(self.password)
        return shuffler.decode(decoded_text)

