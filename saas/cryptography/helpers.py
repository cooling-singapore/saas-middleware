from cryptography.fernet import Fernet


def symmetric_encrypt(content, key=None):
    if key is None:
        key = Fernet.generate_key()
    cipher = Fernet(key)
    return cipher.encrypt(content), key


def symmetric_decrypt(content, key):
    cipher = Fernet(key)
    return cipher.decrypt(content)


def encrypt_file(source, destination, key=None, chunk_size=1024*1024):
    if key is None:
        key = Fernet.generate_key()
    cipher = Fernet(key)
    with open(destination, 'wb') as f_out:
        with open(source, 'rb') as f_in:
            chunk = f_in.read(chunk_size)
            while chunk:
                chunk = cipher.encrypt(chunk)
                chunk_length = len(chunk)
                length_bytes = chunk_length.to_bytes(4, byteorder='big')

                f_out.write(length_bytes)
                f_out.write(chunk)

                chunk = f_in.read(chunk_size)

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
