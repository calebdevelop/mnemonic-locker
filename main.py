import argparse
from mnemonic_locker.command import generate_rsa_command, encrypt_command, decrypt_command, generate_password_command

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='RSA command line tool')
    subparsers = parser.add_subparsers(dest='command', help='sub-command help')

    generate_rsa_parser = subparsers.add_parser('generate_rsa', help='generate RSA key pair')
    generate_rsa_parser.add_argument('--key_size', type=int, default=2048, help='key size in bits')
    generate_rsa_parser.add_argument('--out', default="output", help='key size in bits')
    generate_rsa_parser.set_defaults(func=generate_rsa_command)

    generate_password = subparsers.add_parser('generate_password', help='generate password')
    generate_password.set_defaults(func=generate_password_command)

    encrypt_parser = subparsers.add_parser('encrypt', help='encrypt a message with RSA')
    encrypt_parser.add_argument('--public_key', type=str, help='public key to use for encryption')
    encrypt_parser.add_argument('--out', type=str, default="output", help='output dir')
    encrypt_parser.set_defaults(func=encrypt_command)

    decrypt_parser = subparsers.add_parser('decrypt', help='decrypt a message with RSA')
    decrypt_parser.add_argument('--file', type=str, required=True, help='File to decrypt')
    decrypt_parser.add_argument('--private_key', type=str, required=True, help='Private key to use for decryption')
    decrypt_parser.add_argument('--out', type=str, default="output", help='Output path')
    decrypt_parser.set_defaults(func=decrypt_command)

    args = parser.parse_args()

    if hasattr(args, 'func'):
        args.func(args)
    else:
        parser.print_help()
