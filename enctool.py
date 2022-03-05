from Crypto.Cipher import AES
import getpass
import hashlib
import typing
import pickle
import sys
import os


def generate_key() -> bytes:
    password = getpass.getpass("Enter the password to your file: ").encode()
    return hashlib.md5(password).digest()


def encrypt(key: bytes, data: bytes) -> typing.Tuple[bytes, bytes, bytes]:
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(data)

    return tag, nonce, ciphertext


def encrypt_file(key: bytes, filename: str) -> None:
    with open(filename, "r") as file:
        data = file.read().encode()

    with open(filename, "wb") as file:
        tag, nonce, ciphertext = encrypt(key, data)
        pickle.dump([tag, nonce, ciphertext], file)


def decrypt(key: bytes, tag: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    cipher.verify(tag)

    return plaintext


def decrypt_file(key: bytes, filename: str) -> None:
    with open(filename, "rb") as file:
        tag, nonce, ciphertext = pickle.load(file)

    decrypted = decrypt(key, tag, nonce, ciphertext)

    with open(filename, "wb") as file:
        file.write(decrypted)


def main(args: list) -> int:

    if len(args) < 3:  # first argument is the filename
        print("Action to perform and file name must be provided.")
        return -1

    if args[1] not in ["encrypt", "decrypt"]:
        print("Action to perform not found.")
        return -1

    key = generate_key()
    filename = args[2]

    if "encrypt" in args:
        encrypt_file(key, filename)

    if "decrypt" in args:
        try:
            decrypt_file(key, filename)
        except (ValueError, pickle.UnpicklingError):
            print("Password is incorrect or data was tampered with.")
            return -1

    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
