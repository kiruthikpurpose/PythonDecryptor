from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from base64 import urlsafe_b64decode
import os

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password)
    return key

def decrypt_message(encrypted_data, password):
    decoded_data = urlsafe_b64decode(encrypted_data)
    salt = decoded_data[:16]
    hmac_data = decoded_data[16:48]
    ciphertext = decoded_data[48:]

    key = derive_key(password.encode(), salt)

    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(ciphertext)
    h.verify(hmac_data)

    cipher = Cipher(algorithms.AES(key), modes.CFB(os.urandom(16)), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()

    # Use a more robust decoding approach
    try:
        return decrypted_message.decode('utf-8')
    except UnicodeDecodeError:
        return decrypted_message.decode('utf-8', errors='replace')

if __name__ == "__main__":
    encrypted_data_path = "C:\\Users\\kirut\\Desktop\\ENDE\\encrypted_data.txt"
    password = input("Enter the password: ")

    with open(encrypted_data_path, "rb") as file:
        encrypted_data = file.read()

    decrypted_message = decrypt_message(encrypted_data, password)
    print("Decrypted Message:", decrypted_message)
