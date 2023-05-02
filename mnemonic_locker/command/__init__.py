import base64
import os
import random

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from mnemonic_locker.EncodingTools.ciphers import PasswordGenerator
from mnemonic_locker.EncodingTools.text import TextEncoder
from mnemonic_locker.autocomplete import build_seed_phrase, verify_seed_phrase, clear_output
from mnemonic_locker.rsa.keygen import generate_rsa, save
import getpass
from colorama import Fore

from mnemonic_locker.rsa.utils import encrypt_with_rsa_public_key, decrypt_with_rsa_private_key, is_private_key_encrypted


def generate_rsa_command(args):
    password1 = getpass.getpass("Enter your password (leave blank if none): ")
    if len(password1):
        password12 = getpass.getpass("Confirm your password (leave blank if none): ")
    else:
        password12 = password1

    if password1 == password12:
        public_key, private_key = generate_rsa(args.key_size)
        output_dir = save(public_key, private_key, password1, args.out)
        print(Fore.GREEN + "Keys have been generated successfully.")
        print(f"Secret key : {output_dir}/private_key.pem")
        print(f"Public key : {output_dir}/public_key.pem")
    else:
        print("The two passwords do not match. Please try again.")
        generate_rsa_command(args)


def generate_password_command(args):
    master_password = input("Enter your master password: ")
    key = input("Enter your encryption key: ")
    generator = PasswordGenerator(master_password, key)
    print("Generated password : ")
    print(generator.generate())


def encrypt_command(args):
    walletType = input("Choose wallet type (12 or 24) : ")
    if walletType == "12" or walletType == "24":
        wordCount = int(walletType)
    else:
        print("Invalid choice. Please choose 12 or 24.")
        encrypt_command(args)
        return

    results = build_seed_phrase(wordCount)
    isValid = verify_seed_phrase(results)
    if not isValid:
        encrypt_command(args)

    print(Fore.GREEN + "Verification OK")

    password = None
    for i in range(3):
        password1 = getpass.getpass("Enter encryption password : ")
        password2 = getpass.getpass("Confirm encryption password : ")
        if password1 == password2:
            password = password1
            break
        elif i == 2:
            return

        print(Fore.RED + "Password does not match.")

    print(Fore.GREEN + "Encryption in progress ...")
    encoder = TextEncoder(password)
    text = encoder.encode(" ".join(results))
    output_dir = args.out
    if not args.public_key:
        ""
    else:
        public_key_path = args.public_key
        try:
            with open(public_key_path, "rb") as key_file:
                public_key = serialization.load_pem_public_key(key_file.read(), backend=default_backend())
        except FileNotFoundError:
            print(f"{args.public_key} does not exist")

    ciphertext = encrypt_with_rsa_public_key(public_key, text.encode('utf-8'))

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    save_encrypted_file(f'{output_dir}/encrypted_key.pem', ciphertext)

    print(Fore.GREEN + f"Encrypted file in : {output_dir}/encrypted_key.pem")


def save_encrypted_file(filename: str, ciphertext: bytes):
    with open(filename, 'w') as file:
        base64_str = base64.b64encode(ciphertext).decode()
        header = '-----BEGIN ENCRYPTION KEY-----\n'
        footer = '-----END ENCRYPTION KEY-----\n'
        key_str = ''
        for i in range(0, len(base64_str), 64):
            key_str += base64_str[i:i + 64] + '\n'

        file.write(header + key_str + footer)


def read_encrypted_file(file: bytes) -> bytes:
    pem_format = file.decode()
    lines = pem_format.splitlines()
    pem_format = ''.join(lines[1:-1])
    return base64.b64decode(pem_format)


def decrypt_command(args):
    file_path = args.file
    private_key_path = args.private_key
    output = args.out
    if not os.path.exists(file_path):
        print(Fore.RED + "File does not exist")
        return
    if not os.path.exists(private_key_path):
        print(Fore.RED + "Private key file does not exist")
        return

    if not os.path.exists(output):
        os.makedirs(output)

    if is_private_key_encrypted(file_path):
        password = getpass.getpass("Enter private key password : ")
        encryption_password = getpass.getpass("Enter encryption password : ")
    else:
        password = None
        encryption_password = None

    with open(file_path, "rb") as file:
        ciphertext = read_encrypted_file(file.read())
        plainText = decrypt_with_rsa_private_key(private_key_path, password, ciphertext)
        encoder = TextEncoder(encryption_password)
        seed = encoder.decode(plainText.decode()).split(' ')

        indexes = list(range(len(seed)))
        random.shuffle(indexes)

        print("Please verify your decrypted seed phrase before proceeding !")
        for index in indexes:
            print(f"Word #{index + 1} : " + seed[index], end='\r')
            input("\nPress enter to continue ")
            clear_output(2)
