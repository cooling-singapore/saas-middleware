import os
import shutil

from cryptography.fernet import Fernet


def symmetric_encrypt(content, key=None):
    if key is None:
        key = Fernet.generate_key()
    cipher = Fernet(key)
    return cipher.encrypt(content), key


def symmetric_decrypt(content, key):
    cipher = Fernet(key)
    return cipher.decrypt(content)


def encrypt_file(source, destination=None, key=None, protect_key_with=None, delete_source=False, chunk_size=1024*1024):
    # if no key is provided, generate one
    if key is None:
        key = Fernet.generate_key()

    # determine the (temporary) location
    location = destination if destination else os.path.join(source, '.enc')

    # create the cipher and encrypt the source file
    cipher = Fernet(key)
    with open(location, 'wb') as f_out:
        with open(source, 'rb') as f_in:
            chunk = f_in.read(chunk_size)
            while chunk:
                chunk = cipher.encrypt(chunk)
                chunk_length = len(chunk)
                length_bytes = chunk_length.to_bytes(4, byteorder='big')

                f_out.write(length_bytes)
                f_out.write(chunk)

                chunk = f_in.read(chunk_size)

    # replace the source file?
    if destination is None:
        os.remove(source)
        shutil.move(location, source)

    # delete the source file (if flag is set)
    elif delete_source:
        os.remove(source)

    # do we need to protect the key?
    if protect_key_with is not None:
        key = protect_key_with.encrypt(key, base64_encoded=True).decode('utf-8')

    return key


def decrypt_file(source, destination, key):
    cipher = Fernet(key)
    with open(destination, 'wb') as f_out:
        with open(source, 'rb') as f_in:
            while True:
                length_bytes = f_in.read(4)
                if not length_bytes:
                    break

                chunk_size = int.from_bytes(length_bytes, 'big')
                chunk = f_in.read(chunk_size)
                chunk = cipher.decrypt(chunk)

                f_out.write(chunk)
