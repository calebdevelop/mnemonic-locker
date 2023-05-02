import hmac
import hashlib
import random


class Shuffler:
    def __init__(self, password: str = None):
        self.password = password

    def generate_shuffled_indexes(self, text: str):
        # Hash the password with SHA-256 to get a 256-bit key
        key = hashlib.sha256(self.password.encode('utf-8')).digest()

        # sort text
        sorted_text = ''.join(sorted(text))

        # Generate a HMAC-SHA-256 for the text using the key
        hmac_digest = hmac.new(key, sorted_text.encode('utf-8'), hashlib.sha256).digest()

        # Convert the HMAC digest to a long integer
        hmac_int = int.from_bytes(hmac_digest, byteorder='big')

        # Use the HMAC integer as the seed for the random number generator
        random.seed(hmac_int)

        # Generate a list of integers from 0 to table_size-1.
        indexes = list(range(len(text)))

        # Shuffle the list of integers randomly.
        random.shuffle(indexes)

        return indexes

    def shuffle(self, text):
        indexes = self.generate_shuffled_indexes(text)

        # Create the shuffled recovery phrase
        shuffled_phrase = ''.join([text[i] for i in indexes])

        return shuffled_phrase

    def decode(self, scrambled_phrase: str):
        # Create the order of indexes using the function generate_shuffled_indexes.
        indexes = self.generate_shuffled_indexes(scrambled_phrase)

        # Create an empty list to store the letters in the correct order.
        decoded_phrase = [''] * len(scrambled_phrase)

        # Place each letter of the scrambled text in the correct order.
        for i, index in enumerate(indexes):
            decoded_phrase[index] = scrambled_phrase[i]

        # Return the decoded phrase as a string.
        return ''.join(decoded_phrase)
