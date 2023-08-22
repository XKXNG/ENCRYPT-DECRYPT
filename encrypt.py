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

def save_key(key, filename='key.key'):
    with open(filename, 'wb') as key_file:
        key_file.write(key)

def load_key(filename='key.key'):
    with open(filename, 'rb') as key_file:
        return key_file.read()

def encrypt_file(key, input_file, output_file):
    with open(input_file, 'rb') as file:
        data = file.read()

    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(data)

    with open(output_file, 'wb') as file:
        file.write(encrypted_data)

def decrypt_file(key, input_file, output_file):
    with open(input_file, 'rb') as file:
        encrypted_data = file.read()

    fernet = Fernet(key)
    decrypted_data = fernet.decrypt(encrypted_data)

    with open(output_file, 'wb') as file:
        file.write(decrypted_data)

if __name__ == "__main__":
    password = input("Enter the encryption password: ")
    key = generate_key(password)
    input_file = input("Enter the name of the file to encrypt: ")
    output_file = input("Enter the name of the encrypted file: ")

    save_key(key)
    encrypt_file(key, input_file, output_file)

    print(f"File '{input_file}' has been encrypted and saved as '{output_file}'.")

    decrypt_choice = input("Do you want to decrypt the file? (yes/no): ").lower()
    if decrypt_choice == "yes":
        decrypted_file = "decrypted_" + input_file
        decrypt_file(key, output_file, decrypted_file)
        print(f"File '{output_file}' has been decrypted and saved as '{decrypted_file}'.")

