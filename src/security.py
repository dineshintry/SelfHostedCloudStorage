import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from base64 import urlsafe_b64encode, urlsafe_b64decode

class SecurityManager:
    def __init__(self, password):
        self.password = password.encode('utf-8')
        self.salt = os.urandom(16) # Generate a random salt for key derivation
        self.key = self._derive_key()

    def _derive_key(self):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(self.password)

    def encrypt_data(self, data):
        """Encrypts data using AES-256 GCM."""
        iv = os.urandom(12)  # GCM recommended IV size
        cipher = Cipher(algorithms.AES(self.key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data.encode('utf-8')) + encryptor.finalize()
        return urlsafe_b64encode(self.salt + iv + encryptor.tag + ciphertext).decode('utf-8')

    def decrypt_data(self, encrypted_data):
        """Decrypts data using AES-256 GCM."""
        decoded_data = urlsafe_b64decode(encrypted_data.encode('utf-8'))
        
        salt = decoded_data[:16]
        iv = decoded_data[16:28]
        tag = decoded_data[28:44]
        ciphertext = decoded_data[44:]

        # Re-derive key with the received salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(self.password)

        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        return (decryptor.update(ciphertext) + decryptor.finalize()).decode('utf-8')
