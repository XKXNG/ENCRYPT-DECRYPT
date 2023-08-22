import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def generate_key(password):
    password = password.encode()
    salt = b'salt_'  # Change this to something unique for your application
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key

def decrypt_file(key, input_file):
    with open(input_file, 'rb') as file:
        encrypted_data = file.read()

    fernet = Fernet(key)
    decrypted_data = fernet.decrypt(encrypted_data)

    return decrypted_data.decode()

if __name__ == "__main__":
    password = input("Enter the encryption password: ")
    key = generate_key(password)
    input_file = input("Enter the name of the encrypted file: ")

    decrypted_content = decrypt_file(key, input_file)

    print("Decrypted content:")
    print(decrypted_content)
