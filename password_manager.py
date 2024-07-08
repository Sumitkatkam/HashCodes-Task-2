import os
import json
import base64
import hashlib
import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes

DATA_FILE = 'passwords.json'
SALT = b'some_salt_value'
ITERATIONS = 100000

def get_key(master_password: str) -> bytes:
    """Generate a key from the master password using PBKDF2HMAC."""
    backend = default_backend()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=ITERATIONS,
        backend=backend
    )
    return kdf.derive(master_password.encode())

def encrypt_password(key: bytes, plaintext_password: str) -> str:
    """Encrypt a password using AES."""
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext_password.encode()) + padder.finalize()

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_password = encryptor.update(padded_data) + encryptor.finalize()

    return base64.b64encode(iv + encrypted_password).decode()

def decrypt_password(key: bytes, encrypted_password: str) -> str:
    """Decrypt a password using AES."""
    encrypted_password_bytes = base64.b64decode(encrypted_password)
    iv = encrypted_password_bytes[:16]
    encrypted_data = encrypted_password_bytes[16:]

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_password = decryptor.update(encrypted_data) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext_password = unpadder.update(padded_password) + unpadder.finalize()

    return plaintext_password.decode()

class PasswordManager:
    def __init__(self, master_password: str):
        self.key = get_key(master_password)
        self.passwords = self.load_passwords()

    def load_passwords(self):
        """Load passwords from the data file."""
        if os.path.exists(DATA_FILE):
            with open(DATA_FILE, 'r') as file:
                try:
                    data = json.load(file)
                    if isinstance(data, dict):
                        return data
                    else:
                        print(f"Error: {DATA_FILE} does not contain a valid dictionary.")
                        return {}
                except json.JSONDecodeError:
                    print(f"Error: {DATA_FILE} contains invalid JSON.")
                    return {}
        return {}

    def save_passwords(self):
        """Save passwords to the data file."""
        with open(DATA_FILE, 'w') as file:
            json.dump(self.passwords, file)

    def add_password(self, service: str, password: str):
        """Add a new password."""
        encrypted_password = encrypt_password(self.key, password)
        print(f"Debug: Adding encrypted password for {service}: {encrypted_password}")  # Debug statement
        print(f"Debug: self.passwords type: {type(self.passwords)}")  # Debug statement
        self.passwords[service] = encrypted_password
        self.save_passwords()

    def get_password(self, service: str):
        """Retrieve a password."""
        encrypted_password = self.passwords.get(service)
        if encrypted_password:
            return decrypt_password(self.key, encrypted_password)
        return None

    def delete_password(self, service: str):
        """Delete a password."""
        if service in self.passwords:
            del self.passwords[service]
            self.save_passwords()

# Main Function
def main():
    master_password = getpass.getpass("Enter your master password: ")
    manager = PasswordManager(master_password)

    while True:
        print("\nPassword Manager")
        print("1. Add Password")
        print("2. Get Password")
        print("3. Delete Password")
        print("4. Exit")
        choice = input("Choose an option: ")

        if choice == '1':
            service = input("Enter the service name: ")
            password = getpass.getpass("Enter the password: ")
            manager.add_password(service, password)
            print(f"Password for {service} added.")

        elif choice == '2':
            service = input("Enter the service name: ")
            password = manager.get_password(service)
            if password:
                print(f"Password for {service}: {password}")
            else:
                print(f"No password found for {service}.")

        elif choice == '3':
            service = input("Enter the service name: ")
            manager.delete_password(service)
            print(f"Password for {service} deleted.")

        elif choice == '4':
            break

        else:
            print("Invalid choice, please try again.")

if __name__ == "__main__":
    main()
